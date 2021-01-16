/*
 * cuda_gstore.cu
 *
 * GPU device code to manage GPU Store (Gstore_Fdw)
 * ----
 * Copyright 2011-2020 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 * Copyright 2014-2020 (C) The PG-Strom Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "cuda_common.h"
#include "cuda_gstore.h"

#define KERN_CONTEXT_VARLENA_BUFSZ		0
#define KERN_CONTEXT_STACK_LIMIT		0


STATIC_FUNCTION(Datum)
kern_datum_get_column(kern_data_store *kds,
					  kern_data_extra *extra,
					  cl_uint colidx, cl_uint rowidx,
					  cl_bool *p_isnull)
{
	kern_colmeta   *cmeta = &kds->colmeta[colidx];
	char		   *addr;
	
	assert(colidx < kds->ncols);
	if (rowidx >= kds->nitems)
		goto null_return;

	if (cmeta->nullmap_offset != 0)
	{
		cl_uint	   *nullmap = (cl_uint *)
			((char *)kds + __kds_unpack(cmeta->nullmap_offset));
		if ((nullmap[rowidx>>5] & (1U<<(rowidx & 0x1f))) == 0)
			goto null_return;
	}
	*p_isnull = false;

	addr = (char *)kds + __kds_unpack(cmeta->values_offset);
	if (cmeta->attbyval)
	{
		assert(cmeta->attlen <= sizeof(Datum));
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * rowidx;
		if (cmeta->attlen == sizeof(cl_uchar))
			return READ_INT8_PTR(addr);
		if (cmeta->attlen == sizeof(cl_ushort))
			return READ_INT16_PTR(addr);
		if (cmeta->attlen == sizeof(cl_uint))
			return READ_INT32_PTR(addr);
		if (cmeta->attlen == sizeof(cl_ulong))
			return READ_INT64_PTR(addr);
	}
	else if (cmeta->attlen > 0)
	{
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * rowidx;
		return PointerGetDatum(addr);
	}
	else
	{
		cl_uint		offset;

		assert(cmeta->attlen == -1);
		assert(extra != NULL);
		offset = ((cl_uint *)addr)[rowidx];

		assert(__kds_unpack(offset) < extra->length);
		return PointerGetDatum((char *)extra + __kds_unpack(offset));
	}
null_return:
	*p_isnull = true;
	return 0;
}

/*
 * kds_get_column_sysattr
 */
STATIC_INLINE(GstoreFdwSysattr *)
kds_get_column_sysattr(kern_data_store *kds, cl_uint rowid)
{
	kern_colmeta   *cmeta = &kds->colmeta[kds->ncols-1];
	char		   *addr;

	assert(cmeta->attlen == sizeof(GstoreFdwSysattr) &&
		   cmeta->nullmap_offset == 0);
	addr = (char *)kds + __kds_unpack(cmeta->values_offset);
	if (rowid < kds->nrooms)
		return ((GstoreFdwSysattr *)addr) + rowid;
	return NULL;
}

/*
 * kern_gpustore_setup_owner
 *
 * This function setup sysattr->owner_id; that indicates which threads are
 * responsible to assign the target row.
 *
 * phase = 0 : zero clear the owner_id field of the sysattr
 * phase = 1 : assign max of get_global_id() who tries to update the row
 *             according to the INSERT/DELETE log
 * phase = 3 : assign max of get_global_id() who tries to apply commit log
 */
KERNEL_FUNCTION(void)
kern_gpustore_setup_owner(kern_gpustore_redolog *redo,
						  kern_data_store *kds,
						  kern_data_extra *extra,
						  int phase)
{
	cl_uint		owner_id;
	cl_uint		rowid;

	/* bailout if any errors */
	if (__syncthreads_count(redo->kerror.errcode) > 0)
		return;

	for (owner_id = get_global_id();
		 owner_id < redo->nitems;
		 owner_id += get_global_size())
	{
		GstoreFdwSysattr *sysattr;
		GstoreTxLogCommon *tx_log;
		cl_uint		offset = redo->log_index[owner_id];

		/* this log entry is successfully applied, and can be ignored */
		if (offset == UINT_MAX)
			continue;
		tx_log = (GstoreTxLogCommon *)((char *)redo + __kds_unpack(offset));
		if (tx_log->type == GSTORE_TX_LOG__INSERT)
		{
			rowid = ((GstoreTxLogInsert *)tx_log)->rowid;

			sysattr = kds_get_column_sysattr(kds, rowid);
			if (phase == 0)
				sysattr->owner_id = 0;
			else if (phase == 1)
				atomicMax(&sysattr->owner_id, owner_id);
		}
		else if (tx_log->type == GSTORE_TX_LOG__DELETE)
		{
			rowid = ((GstoreTxLogDelete *)tx_log)->rowid;

			sysattr = kds_get_column_sysattr(kds, rowid);
			if (phase == 0)
				sysattr->owner_id = 0;
			else if (phase == 1)
				atomicMax(&sysattr->owner_id, owner_id);
		}
		else if (tx_log->type == GSTORE_TX_LOG__COMMIT)
		{
			GstoreTxLogCommit *c_log = (GstoreTxLogCommit *)tx_log;
			char   *pos = c_log->data;
			int		i;

			for (i=0; i < c_log->nitems; i++)
			{
				if (*pos == 'I' || *pos == 'D')
				{
					memcpy(&rowid, pos+1, sizeof(cl_uint));

					sysattr = kds_get_column_sysattr(kds, rowid);
					if (phase == 0)
						sysattr->owner_id = 0;
					else if (phase == 3)
						atomicMax(&sysattr->owner_id, owner_id);
					pos += 5;
				}
				else
				{
					printf("unknown commit log entry '%c'\n", *pos);
					break;
				}
			}
		}
		else
		{
			printf("unknown redo-log type %08x, ignored\n", tx_log->type);
		}
	}
}

STATIC_FUNCTION(cl_bool)
__gpustore_apply_insert(kern_context *kcxt,
						kern_data_store *kds,
						kern_data_extra *extra,
						GstoreTxLogInsert *i_log,
						GstoreFdwSysattr *sysattr)
{
	HeapTupleHeaderData *htup = &i_log->htup;
	char	   *pos = (char *)htup + htup->t_hoff;
	cl_uint		rowid = i_log->rowid;
	cl_uint		oldid;
	cl_bool		tup_hasnull = ((htup->t_infomask & HEAP_HASNULL) != 0);
	cl_int		j, natts = (htup->t_infomask2 & HEAP_NATTS_MASK);

	oldid = (((cl_uint)i_log->htup.t_ctid.ip_blkid.bi_hi << 16) |
			 ((cl_uint)i_log->htup.t_ctid.ip_blkid.bi_lo));
	assert(pos == (char *)MAXALIGN(pos));
	sysattr->xmin = InvalidTransactionId;
	sysattr->xmax = InvalidTransactionId;

	for (j=0; j < kds->ncols-1; j++)
	{
		kern_colmeta   *cmeta = &kds->colmeta[j];
		char		   *dest = ((char *)kds + __kds_unpack(cmeta->values_offset));
		cl_uint		   *nullmap;

		if (j >= natts || (tup_hasnull && att_isnull(j, htup->t_bits)))
		{
			assert(cmeta->nullmap_offset != 0);
			nullmap = (cl_uint *)((char *)kds + __kds_unpack(cmeta->nullmap_offset));
			atomicAnd(&nullmap[rowid>>5], ~(1U << (rowid & 0x1f)));
			continue;
		}
		else if (cmeta->nullmap_offset != 0)
		{
			nullmap = (cl_uint *)((char *)kds + __kds_unpack(cmeta->nullmap_offset));
			atomicOr(&nullmap[rowid>>5], (1U << (rowid & 0x1f)));
		}

		if (cmeta->attlen > 0)
		{
			pos = (char *)TYPEALIGN(cmeta->attalign, pos);
			dest += TYPEALIGN(cmeta->attalign,
							  cmeta->attlen) * rowid;
			memcpy(dest, pos, cmeta->attlen);
			pos += cmeta->attlen;
		}
		else
		{
			cl_uint		sz;
			char	   *var;
			cl_ulong	offset;

			assert(cmeta->attlen == -1);
			if (!VARATT_NOT_PAD_BYTE(pos))
				pos = (char *)TYPEALIGN(cmeta->attalign, pos);
			sz = VARSIZE_ANY(pos);
			var = pos;
			pos += sz;

			/* try to check whether it is actually updated */
			if (oldid != UINT_MAX)
			{
				Datum	datum;
				cl_bool	isnull;

				datum = kern_datum_get_column(kds, extra, j, oldid, &isnull);
				if (!isnull)
				{
					cl_uint		sz1 = VARSIZE_ANY_EXHDR(var);
					cl_uint		sz2 = VARSIZE_ANY_EXHDR(datum);

					if ((char *)datum >= (char *)extra &&
						(char *)datum <= (char *)extra + extra->length)
					{
					
					if (sz1 == sz2 && __memcmp(VARDATA_ANY(var),
											   VARDATA_ANY(datum), sz1) == 0)
					{
						/* Ok, this attribute is not updated */
						offset = (char *)datum - (char *)extra;
						goto reuse_extra;
					}

					}
				}
			}
			/* allocation of extra buffer on demand */
			offset = atomicAdd(&extra->usage, MAXALIGN(sz));
			if (offset + MAXALIGN(sz) > extra->length)
			{
				STROM_EREPORT(kcxt, ERRCODE_OUT_OF_MEMORY, "out of extra buffer");
				return false;
			}
			memcpy((char *)extra + offset, var, sz);
		reuse_extra:
			((cl_uint *)dest)[rowid] = __kds_packed(offset);
		}
	}
	/* and, system attributes */
	sysattr->xmin = htup->t_choice.t_heap.t_xmin;
	sysattr->xmax = htup->t_choice.t_heap.t_xmax;
	atomicMax(&kds->nitems, rowid+1);

	return true;
}

STATIC_FUNCTION(void)
__gpustore_apply_delete(kern_context *kcxt,
						GstoreTxLogDelete *d_log,
						GstoreFdwSysattr *sysattr)
{
//	sysattr->xmin = d_log->xmin;
	sysattr->xmax = d_log->xid;
}

STATIC_FUNCTION(void)
__gpustore_apply_commit(kern_context *kcxt,
						kern_data_store *kds,
						cl_uint owner_id,
						GstoreTxLogCommit *c_log)
{
	GstoreFdwSysattr *sysattr;
	char	   *pos = c_log->data;

	for (int i=0; i < c_log->nitems; i++)
	{
		cl_uint		rowid;

		if (*pos == 'I')
		{
			memcpy(&rowid, pos+1, sizeof(cl_uint));
			sysattr = kds_get_column_sysattr(kds, rowid);
			if (sysattr && sysattr->owner_id == owner_id)
			{
				sysattr->xmin = FrozenTransactionId;
				sysattr->xmax = InvalidTransactionId;
			}
			pos += 5;
		}
		else if (*pos == 'D')
		{
			memcpy(&rowid, pos+1, sizeof(cl_uint));
			sysattr = kds_get_column_sysattr(kds, rowid);
			if (sysattr && sysattr->owner_id == owner_id)
			{
				sysattr->xmin = InvalidTransactionId;
				sysattr->xmax = InvalidTransactionId;
			}
			pos += 5;
		}
		else
		{
			printf("unknown commit log entry '%c'\n", *pos);
			break;
		}
	}
}

KERNEL_FUNCTION(void)
kern_gpustore_apply_redo(kern_gpustore_redolog *redo,
						 kern_data_store *kds,
						 kern_data_extra *extra,
						 int phase)
{
	kern_context kcxt;
	cl_uint		owner_id;

	/* bailout if any errors */
	if (__syncthreads_count(redo->kerror.errcode) > 0)
		goto skip;

	INIT_KERNEL_CONTEXT(&kcxt, NULL);	/* no kparams */
	for (owner_id = get_global_id();
		 owner_id < redo->nitems;
		 owner_id += get_global_size())
	{
		GstoreTxLogCommon *tx_log;
		GstoreFdwSysattr *sysattr;
		cl_uint		offset = redo->log_index[owner_id];

		/*
		 * In case of suspend & resume, a part of log entries are already
		 * applied to the kds/extra buffers. To avoid redundant consumption
		 * of the extra buffer, we skip these records.
		 */
		if (offset == UINT_MAX)
			continue;

		tx_log = (GstoreTxLogCommon *)((char *)redo + __kds_unpack(offset));
		if (tx_log->type == GSTORE_TX_LOG__INSERT)
		{
			GstoreTxLogInsert *i_log = (GstoreTxLogInsert *)tx_log;

			sysattr = kds_get_column_sysattr(kds, i_log->rowid);
			if (sysattr->owner_id == owner_id && phase == 2)
			{
				if (__gpustore_apply_insert(&kcxt, kds, extra, i_log, sysattr))
					redo->log_index[owner_id] = UINT_MAX;
			}
		}
		else if (tx_log->type == GSTORE_TX_LOG__DELETE)
		{
			GstoreTxLogDelete *d_log = (GstoreTxLogDelete *)tx_log;

			sysattr = kds_get_column_sysattr(kds, d_log->rowid);
			if (sysattr->owner_id == owner_id && phase == 2)
			{
				__gpustore_apply_delete(&kcxt, d_log, sysattr);
				redo->log_index[owner_id] = UINT_MAX;
			}
		}
		else if (tx_log->type == GSTORE_TX_LOG__COMMIT)
		{
			GstoreTxLogCommit *c_log = (GstoreTxLogCommit *)tx_log;

			if (phase == 4)
				__gpustore_apply_commit(&kcxt, kds, owner_id, c_log);
		}
		else
		{
			/* ignore other log type in this step */
		}
		if (kcxt.errcode != 0)
			break;
	}
skip:
	kern_writeback_error_status(&redo->kerror, &kcxt);
}

KERNEL_FUNCTION(void)
kern_gpustore_compaction(kern_data_store *kds,
						 kern_data_extra *old_extra,
						 kern_data_extra *new_extra)
{
	__shared__ cl_uint required;
	__shared__ cl_ulong extra_base;
	cl_uint		nloops;

	nloops = (kds->nitems + get_global_size() - 1) / get_global_size();
	for (int loop=0; loop < nloops; loop++)
	{
		cl_uint		rowid = get_global_id() + loop * get_global_size();
		GstoreFdwSysattr *sysattr = kds_get_column_sysattr(kds, rowid);

		for (int j=0; j < kds->ncols-1; j++)
		{
			kern_colmeta *cmeta = &kds->colmeta[j];
			cl_bool		isnull = false;
			cl_uint	   *values;
			char	   *orig = NULL;
			char	   *dest;
			cl_uint		sz, l_off = 0;

			if (cmeta->attbyval || cmeta->attlen != -1)
				continue;			/* not varlena */

			if (rowid >= kds->nitems)
				isnull = true;		/* out of range */
			else if (sysattr->xmin == InvalidTransactionId)
				isnull = true;		/* rows already removed */
			else if (cmeta->nullmap_offset != 0)
			{
				cl_uint	   *nullmap = (cl_uint *)
					((char *)kds + __kds_unpack(cmeta->nullmap_offset));
				if ((nullmap[rowid>>5] & (1U << (rowid & 0x1f))) == 0)
					isnull = true;
			}
			values = (cl_uint *)((char *)kds + __kds_unpack(cmeta->values_offset));
			
			/* copy the varlena to new extra buffer */
			if (get_local_id() == 0)
				required = 0;
			__syncthreads();
			if (!isnull)
			{
				orig = (char *)old_extra + __kds_unpack(values[rowid]);
				sz = VARSIZE_ANY(orig);
				assert(orig > (char *)old_extra &&
					   orig + sz <= (char *)old_extra + old_extra->length);
				l_off = atomicAdd(&required, MAXALIGN(sz));
			}
			__syncthreads();
			if (get_local_id() == 0)
				extra_base = atomicAdd(&new_extra->usage, required);
			__syncthreads();
			dest = (char *)new_extra + extra_base + l_off;
			if (isnull)
			{
				if (rowid < kds->nitems)
					values[rowid] = 0;
			}
			else if (dest + sz <= (char *)new_extra + new_extra->length)
			{
				memcpy(dest, orig, sz);
				values[rowid] = __kds_packed((char *)dest - (char *)new_extra);
			}
			else
			{
				assert(new_extra->length == 0);
			}
		}
	}
}
