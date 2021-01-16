/*
 * datastore.c
 *
 * Routines to manage data store; row-store, column-store, toast-buffer,
 * and param-buffer.
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
#include "pg_strom.h"
#include "cuda_numeric.h"
#include "cuda_gstore.h"
#include "nvme_strom.h"

/*
 * estimate_num_chunks
 *
 * it estimates number of chunks to be fetched from the supplied Path
 */
cl_uint
estimate_num_chunks(Path *pathnode)
{
	RelOptInfo *rel = pathnode->parent;
	int			ncols = list_length(rel->reltarget->exprs);
    Size        htup_size;
	cl_uint		num_chunks;

	htup_size = MAXALIGN(offsetof(HeapTupleHeaderData,
								  t_bits[BITMAPLEN(ncols)]));
	if (rel->reloptkind != RELOPT_BASEREL)
		htup_size += MAXALIGN(rel->reltarget->width);
	else
	{
		double      heap_size = (double)
			(BLCKSZ - SizeOfPageHeaderData) * rel->pages;

		htup_size += MAXALIGN(heap_size / Max(rel->tuples, 1.0) -
							  sizeof(ItemIdData) - SizeofHeapTupleHeader);
	}
	num_chunks = (cl_uint)
		((double)(htup_size + sizeof(cl_int)) * pathnode->rows /
		 (double)(pgstrom_chunk_size() - KDS_ESTIMATE_HEAD_LENGTH(ncols)));
	num_chunks = Max(num_chunks, 1);

	return num_chunks;
}

/*
 * PDS_fetch_tuple - fetch a tuple from the PDS
 */
bool
KDS_fetch_tuple_row(TupleTableSlot *slot,
					kern_data_store *kds,
					HeapTuple tuple_buf,
					size_t row_index)
{
	if (row_index < kds->nitems)
	{
		HeapTupleData	tupleData;
		kern_tupitem   *tup_item = KERN_DATA_STORE_TUPITEM(kds, row_index);

		ExecClearTuple(slot);
		tupleData.t_len  = tup_item->t_len;
		tupleData.t_self = tup_item->htup.t_ctid;
		tupleData.t_tableOid = kds->table_oid;
		tupleData.t_data = &tup_item->htup;

		ExecForceStoreHeapTuple(&tupleData, slot, false);

		return true;
	}
	return false;
}

bool
KDS_fetch_tuple_slot(TupleTableSlot *slot,
					 kern_data_store *kds,
					 size_t row_index)
{
	if (row_index < kds->nitems)
	{
		Datum  *tts_values = KERN_DATA_STORE_VALUES(kds, row_index);
		char   *tts_isnull = KERN_DATA_STORE_DCLASS(kds, row_index);
		int		natts = slot->tts_tupleDescriptor->natts;

		ExecClearTuple(slot);
		memcpy(slot->tts_values, tts_values, sizeof(Datum) * natts);
		memcpy(slot->tts_isnull, tts_isnull, sizeof(bool) * natts);
		ExecStoreVirtualTuple(slot);
		return true;
	}
	return false;
}

Datum
KDS_fetch_datum_column(kern_data_store *kds,
					   kern_colmeta *cmeta,
					   size_t row_index,
					   bool *p_isnull)
{
	char	   *addr;
	Datum		datum;

	Assert(cmeta >= &kds->colmeta[0] &&
		   cmeta <  &kds->colmeta[kds->nr_colmeta] &&
		   row_index < kds->nrooms);

	if (cmeta->nullmap_offset != 0)
	{
		bits8  *nullmap = (bits8 *)
			((char *)kds + __kds_unpack(cmeta->nullmap_offset));
		if (att_isnull(row_index, nullmap))
		{
			*p_isnull = true;
			return 0;
		}
	}
	*p_isnull = false;

	addr = (char *)kds + __kds_unpack(cmeta->values_offset);
	if (cmeta->attbyval)
	{
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * row_index;
		switch (cmeta->attlen)
		{
			case sizeof(cl_uchar):
				datum = UInt8GetDatum(*((cl_uchar *)addr));
				break;
			case sizeof(cl_ushort):
				datum = UInt16GetDatum(*((cl_ushort *)addr));
				break;
			case sizeof(cl_uint):
				datum = UInt32GetDatum(*((cl_uint *)addr));
				break;
			case sizeof(cl_ulong):
				datum = UInt64GetDatum(*((cl_ulong *)addr));
				break;
			default:
				elog(ERROR, "unexpected type definition");
		}
	}
	else if (cmeta->attlen > 0)
	{
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * row_index;
		datum = PointerGetDatum(addr);
	}
	else if (cmeta->attlen == -1)
	{
		kern_data_extra *extra = (kern_data_extra *)((char *)kds + kds->extra_hoffset);
		size_t		off = __kds_unpack(((cl_uint *)addr)[row_index]);

		Assert(off < extra->length);
		datum = PointerGetDatum((char *)extra + off);
	}
	else
	{
		elog(ERROR, "unsupported type definition attlen=%d attbyval=%d", cmeta->attlen, cmeta->attbyval);
	}
	return datum;
}

void
__KDS_store_datum_column(kern_data_store *kds,
						 kern_colmeta *cmeta,
						 size_t row_index,
						 Datum datum, bool isnull)
{


	char	   *addr;

	Assert(kds->format == KDS_FORMAT_COLUMN &&
		   cmeta >= &kds->colmeta[0] &&
		   cmeta <  &kds->colmeta[kds->ncols] &&
		   row_index < kds->nrooms);
	if (cmeta->nullmap_offset != 0)
	{
		uint32 *nullmap = (uint32 *)
			((char *)kds + __kds_unpack(cmeta->nullmap_offset));

		/*
		 * Row-level lock prevents concurrent access per row basis.
		 * So, null-bitmap must be set/cleared by atomic operations,
		 * because other bits are not locked at this moment.
		 */
		if (!isnull)
			__atomic_fetch_or(nullmap + (row_index >> 5),
							  (1U << (row_index & 0x1f)),
							  __ATOMIC_SEQ_CST);
		else
		{
			__atomic_fetch_and(nullmap + (row_index >> 5),
							   ~(1U << (row_index & 0x1f)),
							   __ATOMIC_SEQ_CST);
			return;
		}
	}
	else if (isnull)
	{
		elog(ERROR, "NULL value on '%s' column with NOT NULL constraint",
			 NameStr(cmeta->attname));
	}

	addr = (char *)kds + __kds_unpack(cmeta->values_offset);
	if (cmeta->attbyval)
	{
		switch (cmeta->attlen)
		{
			case sizeof(cl_uchar):
				((cl_uchar *)addr)[row_index] = DatumGetUInt8(datum);
				break;
			case sizeof(cl_ushort):
				((cl_ushort *)addr)[row_index] = DatumGetUInt16(datum);
				break;
			case sizeof(cl_uint):
				((cl_uint *)addr)[row_index] = DatumGetUInt32(datum);
				break;
			case sizeof(cl_ulong):
				((cl_ulong *)addr)[row_index] = DatumGetUInt64(datum);
				break;
			default:
				elog(ERROR, "unsupported type definition");
		}
	}
	else if (cmeta->attlen > 0)
	{
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * row_index;
		memcpy(addr, DatumGetPointer(datum), cmeta->attlen);
	}
	else if (cmeta->attlen == -1)
	{
		kern_data_extra *extra = (kern_data_extra *)((char *)kds + kds->extra_hoffset);

		Assert(kds->extra_hoffset > 0);
		Assert((char *)datum >= (char *)extra &&
			   (char *)datum + VARSIZE_ANY(datum) <= (char *)extra + extra->length);
		((cl_uint *)addr)[row_index] = __kds_packed((char *)datum - (char *)extra);
	}
	else
	{
		elog(ERROR, "unsupported type definition");
	}	
}

/*
 * NOTE: caller must ensure this KDS has no concurrent updates by lock or
 * other way.
 */
void
KDS_store_datum_column(kern_data_store *kds,
					   kern_colmeta *cmeta,
					   size_t row_index,
					   Datum datum, bool isnull)
{
	/* allocation of extra buffer, and copy the varlena datum */
	if (cmeta->attlen == -1)
	{
		kern_data_extra *extra = (kern_data_extra *)
			((char *)kds + kds->extra_hoffset);
		size_t		sz = VARSIZE_ANY(datum);
		char	   *pos;

		Assert(extra->usage + sz <= extra->length);
		pos = (char *)extra + extra->usage;
		memcpy(pos, DatumGetPointer(datum), sz);
		extra->usage += MAXALIGN(sz);

		datum = PointerGetDatum(pos);
	}
	__KDS_store_datum_column(kds, cmeta, row_index, datum, isnull);
}

bool
KDS_fetch_tuple_column(TupleTableSlot *slot,
					   kern_data_store *kds,
					   size_t row_index)
{
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	int			j;

	Assert(kds->format == KDS_FORMAT_COLUMN);
	Assert(kds->ncols >= tupdesc->natts);
	Assert(row_index < kds->nrooms);

	ExecClearTuple(slot);
	for (j=0; j < tupdesc->natts; j++)
	{
		kern_colmeta *cmeta = &kds->colmeta[j];
		Datum	datum;
		bool	isnull;

		datum = KDS_fetch_datum_column(kds, cmeta, row_index, &isnull);
		slot->tts_isnull[j] = isnull;
		slot->tts_values[j] = datum;
	}
	ExecStoreVirtualTuple(slot);

	return true;
}

static inline bool
KDS_fetch_tuple_block(TupleTableSlot *slot,
					  kern_data_store *kds,
					  GpuTaskState *gts)
{
	Relation	rel = gts->css.ss.ss_currentRelation;
	HeapTuple	tuple = &gts->curr_tuple;
	BlockNumber	block_nr;
	PageHeader	hpage;
	cl_uint		max_lp_index;
	ItemId		lpp;

	while (gts->curr_index < kds->nitems)
	{
		block_nr = KERN_DATA_STORE_BLOCK_BLCKNR(kds, gts->curr_index);
		hpage = KERN_DATA_STORE_BLOCK_PGPAGE(kds, gts->curr_index);
		Assert(PageIsAllVisible(hpage));
		max_lp_index = PageGetMaxOffsetNumber(hpage);
		while (gts->curr_lp_index < max_lp_index)
		{
			cl_uint		lp_index = gts->curr_lp_index++;

			lpp = &hpage->pd_linp[lp_index];
			if (!ItemIdIsNormal(lpp))
				continue;

			tuple->t_len = ItemIdGetLength(lpp);
			BlockIdSet(&tuple->t_self.ip_blkid, block_nr);
			tuple->t_self.ip_posid = lp_index;
			tuple->t_tableOid = (rel ? RelationGetRelid(rel) : InvalidOid);
			tuple->t_data = (HeapTupleHeader)((char *)hpage +
											  ItemIdGetOffset(lpp));
			ExecForceStoreHeapTuple(tuple, slot, false);
			return true;
		}
		/* move to the next block */
		gts->curr_index++;
		gts->curr_lp_index = 0;
	}
	return false;	/* end of the PDS */
}

bool
PDS_fetch_tuple(TupleTableSlot *slot,
				pgstrom_data_store *pds,
				GpuTaskState *gts)
{
	switch (pds->kds.format)
	{
		case KDS_FORMAT_ROW:
		case KDS_FORMAT_HASH:
			return KDS_fetch_tuple_row(slot, &pds->kds,
									   &gts->curr_tuple,
									   gts->curr_index++);
		case KDS_FORMAT_SLOT:
			return KDS_fetch_tuple_slot(slot, &pds->kds,
										gts->curr_index++);
		case KDS_FORMAT_BLOCK:
			return KDS_fetch_tuple_block(slot, &pds->kds, gts);
		case KDS_FORMAT_COLUMN:
			return KDS_fetch_tuple_column(slot, &pds->kds,
										  gts->curr_index++);
		case KDS_FORMAT_ARROW:
			return KDS_fetch_tuple_arrow(slot, &pds->kds,
										 gts->curr_index++);
		default:
			elog(ERROR, "Bug? unsupported data store format: %d",
				pds->kds.format);
	}
}

/*
 * KDS_clone - makes an empty data store with same definition
 */
kern_data_store *
__KDS_clone(GpuContext *gcontext, kern_data_store *kds_old,
			const char *filename, int lineno)
{
	kern_data_store *kds_new;
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	rc = __gpuMemAllocManaged(gcontext,
							  &m_deviceptr,
							  kds_old->length,
							  CU_MEM_ATTACH_GLOBAL,
							  filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("out of managed memory");
	kds_new = (kern_data_store *) m_deviceptr;
	/* setup */
	memcpy(kds_new, kds_old, KERN_DATA_STORE_HEAD_LENGTH(kds_old));
	kds_new->usage = 0;
	kds_new->nitems = 0;

	return kds_new;
}

/*
 * PDS_clone - makes an empty data store with same definition
 */
pgstrom_data_store *
__PDS_clone(pgstrom_data_store *pds_old,
			const char *filename, int lineno)
{
	pgstrom_data_store *pds_new;
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	rc = __gpuMemAllocManaged(pds_old->gcontext,
							  &m_deviceptr,
							  offsetof(pgstrom_data_store,
									   kds) + pds_old->kds.length,
							  CU_MEM_ATTACH_GLOBAL,
							  filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("out of managed memory");
	pds_new = (pgstrom_data_store *) m_deviceptr;

	/* setup */
	memset(pds_new, 0, offsetof(pgstrom_data_store, kds));
	pds_new->gcontext = pds_old->gcontext;
	pg_atomic_init_u32(&pds_new->refcnt, 1);
	pds_new->nblocks_uncached = 0;
	pds_new->filedesc.rawfd = -1;
	pds_new->iovec = NULL;
	memcpy(&pds_new->kds,
		   &pds_old->kds,
		   KERN_DATA_STORE_HEAD_LENGTH(&pds_old->kds));
	/* make the data store empty */
	pds_new->kds.usage = 0;
	pds_new->kds.nitems = 0;

	return pds_new;
}

/*
 * PDS_retain
 */
pgstrom_data_store *
PDS_retain(pgstrom_data_store *pds)
{
	int32		refcnt_old	__attribute__((unused));

	refcnt_old = (int32)pg_atomic_fetch_add_u32(&pds->refcnt, 1);

	Assert(refcnt_old > 0);

	return pds;
}

/*
 * PDS_release
 */
void
PDS_release(pgstrom_data_store *pds)
{
	GpuContext *gcontext = pds->gcontext;
	CUresult	rc;
	int32		refcnt;

	refcnt = (int32)pg_atomic_sub_fetch_u32(&pds->refcnt, 1);
	Assert(refcnt >= 0);
	if (refcnt == 0)
	{
		if (pds->gcontext)
		{
			rc = gpuMemFree(gcontext, (CUdeviceptr) pds);
			if (rc != CUDA_SUCCESS)
				werror("failed on gpuMemFree: %s", errorText(rc));
		}
		else
		{
			Assert(pds->kds.format == KDS_FORMAT_ARROW ||
				   pds->kds.format == KDS_FORMAT_COLUMN);
			pfree(pds);
		}
	}
}

static int
count_num_of_subfields(Oid type_oid)
{
	HeapTuple		tup;
	Form_pg_type	typeForm;
	int				result = 0;

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(type_oid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", type_oid);
	typeForm = (Form_pg_type) GETSTRUCT(tup);
	if (typeForm->typlen == -1 && OidIsValid(typeForm->typelem))
	{
		/* array type */
		result = 1 + count_num_of_subfields(typeForm->typelem);
	}
	else if (typeForm->typtype == TYPTYPE_COMPOSITE &&
			 OidIsValid(typeForm->typrelid))
	{
		TupleDesc	tupdesc = lookup_rowtype_tupdesc(type_oid, -1);
		int			i;

		result = tupdesc->natts;
		for (i=0; i < tupdesc->natts; i++)
		{
			Form_pg_attribute attr = tupleDescAttr(tupdesc, i);

			result += count_num_of_subfields(attr->atttypid);
		}
		ReleaseTupleDesc(tupdesc);
	}
	ReleaseSysCache(tup);
	return result;
}

static void
__init_kernel_column_metadata(kern_data_store *kds,
							  int column_index,
							  const char *attname,
							  int attnum,
							  Oid atttypid,
							  int atttypmod,
							  int *p_attcacheoff)
{
	kern_colmeta   *cmeta = &kds->colmeta[column_index];
	HeapTuple		tup;
	Form_pg_type	typ;

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(atttypid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", atttypid);
	typ = (Form_pg_type) GETSTRUCT(tup);

	cmeta->attbyval = typ->typbyval;
	cmeta->attalign = typealign_get_width(typ->typalign);
	cmeta->attlen   = typ->typlen;
	if (cmeta->attlen == 0 || cmeta->attlen < -1)
		elog(ERROR, "type %s has unexpected length (%d)",
			 NameStr(typ->typname), typ->typlen);
	else if (cmeta->attlen == -1)
		kds->has_varlena = true;
	cmeta->attnum   = attnum;
	if (p_attcacheoff && *p_attcacheoff > 0)
	{
		/*
		 * Special case handling - varlena can use attcacheoff only if offset
		 * is aligned, thus we can reference the value regardless of the format
		 * and padding.
		 */
		if (typ->typlen == -1)
		{
			int		__off = att_align_nominal(*p_attcacheoff, typ->typalign);

			if (*p_attcacheoff == __off)
				cmeta->attcacheoff = __off;
			else
				cmeta->attcacheoff = -1;
		}
		else
			cmeta->attcacheoff = att_align_nominal(*p_attcacheoff, typ->typalign);
	}
	else
		cmeta->attcacheoff = -1;
	cmeta->atttypid = atttypid;
	cmeta->atttypmod = atttypmod;
	strncpy(cmeta->attname.data, attname, NAMEDATALEN);

	if (OidIsValid(typ->typelem))
	{
		char		elem_name[NAMEDATALEN + 10];

		Assert(typ->typlen == -1);
		cmeta->atttypkind = TYPE_KIND__ARRAY;
		cmeta->idx_subattrs = kds->nr_colmeta++;
		cmeta->num_subattrs = 1;

		snprintf(elem_name, sizeof(elem_name), "__%s", attname);
		__init_kernel_column_metadata(kds,
									  cmeta->idx_subattrs,
									  elem_name,
									  1,		/* attnum */
									  typ->typelem,
									  -1,		/* typmod */
									  NULL);	/* attcacheoff */
	}
	else if (OidIsValid(typ->typrelid))
	{
		TupleDesc	rowdesc;
		int			j, attcacheoff = -1;

		Assert(typ->typtype == TYPTYPE_COMPOSITE);
		cmeta->atttypkind = TYPE_KIND__COMPOSITE;

		rowdesc = lookup_rowtype_tupdesc(atttypid, atttypmod);
		cmeta->idx_subattrs = kds->nr_colmeta;
		cmeta->num_subattrs = rowdesc->natts;
		kds->nr_colmeta += rowdesc->natts;

		if (kds->format == KDS_FORMAT_ROW ||
			kds->format == KDS_FORMAT_HASH ||
			kds->format == KDS_FORMAT_BLOCK)
		{
			attcacheoff = offsetof(HeapTupleHeaderData, t_bits);
			if (tupleDescHasOid(rowdesc))
				attcacheoff += sizeof(Oid);
			attcacheoff = MAXALIGN(attcacheoff);
		}
		
		for (j=0; j < rowdesc->natts; j++)
		{
			Form_pg_attribute	attr = tupleDescAttr(rowdesc, j);
			__init_kernel_column_metadata(kds,
										  cmeta->idx_subattrs + j,
										  NameStr(attr->attname),
										  attr->attnum,
										  attr->atttypid,
										  attr->atttypmod,
										  &attcacheoff);
		}
		ReleaseTupleDesc(rowdesc);
	}
	else
	{
		switch (typ->typtype)
		{
			case TYPTYPE_BASE:
				cmeta->atttypkind = TYPE_KIND__BASE;
				break;
			case TYPTYPE_DOMAIN:
				cmeta->atttypkind = TYPE_KIND__DOMAIN;
				break;
			case TYPTYPE_ENUM:
				cmeta->atttypkind = TYPE_KIND__ENUM;
				break;
			case TYPTYPE_PSEUDO:
				cmeta->atttypkind = TYPE_KIND__PSEUDO;
				break;
			case TYPTYPE_RANGE:
				cmeta->atttypkind = TYPE_KIND__RANGE;
				break;
			default:
				elog(ERROR, "Unexpected typtype ('%c')", typ->typtype);
				break;
		}
	}
	if (p_attcacheoff)
	{
		if (*p_attcacheoff > 0 && typ->typlen > 0)
			*p_attcacheoff += typ->typlen;
		else
			*p_attcacheoff = -1;
	}
	ReleaseSysCache(tup);
}

void
init_kernel_data_store(kern_data_store *kds,
					   TupleDesc tupdesc,
					   Size length,
					   int format,
					   uint nrooms)
{
	int			j, ncols = tupdesc->natts;
	int			nr_colmeta;
	int			attcacheoff = -1;

	if (format == KDS_FORMAT_COLUMN)
		ncols++;		/* internal system attribute */
	nr_colmeta = ncols;
	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute attr = tupleDescAttr(tupdesc, j);

		nr_colmeta += count_num_of_subfields(attr->atttypid);
	}
	memset(kds, 0, offsetof(kern_data_store, colmeta[nr_colmeta]));
	kds->length = length;
	kds->nitems = 0;
	kds->usage = 0;
	kds->nrooms = nrooms;
	kds->ncols = ncols;
	kds->format = format;
	kds->tdhasoid = tupleDescHasOid(tupdesc);
	kds->tdtypeid = tupdesc->tdtypeid;
	kds->tdtypmod = tupdesc->tdtypmod;
	kds->table_oid = InvalidOid;	/* caller shall set */
	kds->nslots = 0;				/* caller shall set, if any */
	kds->nrows_per_block = 0;
	kds->nr_colmeta = ncols;

	if (format == KDS_FORMAT_ROW ||
		format == KDS_FORMAT_HASH ||
		format == KDS_FORMAT_BLOCK)
	{
		attcacheoff = offsetof(HeapTupleHeaderData, t_bits);
		if (tupleDescHasOid(tupdesc))
			attcacheoff += sizeof(Oid);
		attcacheoff = MAXALIGN(attcacheoff);
	}
	else
		attcacheoff = -1;
	
	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute	attr = tupleDescAttr(tupdesc, j);
		__init_kernel_column_metadata(kds, j,
									  NameStr(attr->attname),
									  attr->attnum,
									  attr->atttypid,
									  attr->atttypmod,
									  &attcacheoff);
	}

	/* internal system attribute for column data */
	if (format == KDS_FORMAT_COLUMN)
	{
		kern_colmeta *cmeta = &kds->colmeta[tupdesc->natts];

		Assert(kds->ncols == tupdesc->natts + 1);
		cmeta->attbyval = true;
		cmeta->attalign = sizeof(cl_uint);
		cmeta->attlen = 3 * sizeof(cl_uint);
		cmeta->attnum = ncols;
		cmeta->attcacheoff = -1;
		cmeta->atttypid = InvalidOid;	/* internal type */
		cmeta->atttypmod = -1;
		cmeta->atttypkind = TYPE_KIND__BASE;
		strcpy(cmeta->attname.data, "__rowid__");
	}
	Assert(kds->nr_colmeta == nr_colmeta);
}

/*
 * KDS length calculators
 */
size_t
KDS_calculateHeadSize(TupleDesc tupdesc)
{
	int		j, nr_colmeta = tupdesc->natts;

	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute attr = tupleDescAttr(tupdesc, j);
		nr_colmeta += count_num_of_subfields(attr->atttypid);
	}
	return STROMALIGN(offsetof(kern_data_store, colmeta[nr_colmeta]));
}

/*
 * Check compatibility of KDS schema-definition
 */
static bool
__check_kern_colmeta_compatibility(Oid type_oid, int type_mod,
								   kern_data_store *kds, kern_colmeta *cmeta)
{
	HeapTuple		tup;
	Form_pg_type	typ;
	bool			retval = false;

	if (cmeta->atttypid != type_oid ||
		cmeta->atttypmod != type_mod)
		return false;

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(type_oid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", type_oid);
	typ = (Form_pg_type) GETSTRUCT(tup);

	if ((cmeta->attbyval && !typ->typbyval) ||
        (!cmeta->attbyval && typ->typbyval) ||
		(cmeta->attalign != typealign_get_width(typ->typalign)) ||
		(cmeta->attlen != typ->typlen))
		goto not_compatible;

	if (OidIsValid(typ->typelem))
	{
		kern_colmeta   *__cmeta = kds->colmeta + cmeta->idx_subattrs;

		if (cmeta->idx_subattrs >= kds->nr_colmeta ||
			cmeta->num_subattrs != 1 ||
			!__check_kern_colmeta_compatibility(typ->typelem, -1,
												kds, __cmeta))
			goto not_compatible;
	}
	else if (OidIsValid(typ->typrelid))
	{
		kern_colmeta   *__cmeta = kds->colmeta + cmeta->idx_subattrs;
		TupleDesc		rowdesc;
		int				j;

		rowdesc = lookup_rowtype_tupdesc(type_oid, type_mod);
		if (rowdesc->natts != cmeta->num_subattrs ||
			cmeta->idx_subattrs + cmeta->num_subattrs > kds->nr_colmeta)
			goto not_compatible;
		for (j=0; j < rowdesc->natts; j++)
		{
			Form_pg_attribute __attr = tupleDescAttr(rowdesc, j);

			if (!__check_kern_colmeta_compatibility(__attr->atttypid,
													__attr->atttypmod,
													kds, __cmeta+j))
				goto not_compatible;
		}
	}
	retval = true;
not_compatible:
	ReleaseSysCache(tup);
	return retval;
}

bool
KDS_schemaIsCompatible(TupleDesc tupdesc, kern_data_store *kds)
{
	int		j;
	
	if (kds->ncols != tupdesc->natts)
		return false;
	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute attr = tupleDescAttr(tupdesc, j);

		if (!__check_kern_colmeta_compatibility(attr->atttypid,
												attr->atttypmod,
												kds, &kds->colmeta[j]))
			return false;
	}
	return true;
}

pgstrom_data_store *
__PDS_create_row(GpuContext *gcontext,
				 TupleDesc tupdesc,
				 size_t bytesize,
				 const char *filename, int lineno)
{
	pgstrom_data_store *pds;
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	bytesize = STROMALIGN_DOWN(bytesize);
	rc = __gpuMemAllocManaged(gcontext,
							  &m_deviceptr,
							  offsetof(pgstrom_data_store,
									   kds) + bytesize,
							  CU_MEM_ATTACH_GLOBAL,
							  filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("out of managed memory");
	pds = (pgstrom_data_store *) m_deviceptr;

	/* setup */
	memset(pds, 0, offsetof(pgstrom_data_store, kds));
	pds->gcontext = gcontext;
	pg_atomic_init_u32(&pds->refcnt, 1);
	init_kernel_data_store(&pds->kds, tupdesc, bytesize,
						   KDS_FORMAT_ROW, INT_MAX);
	pds->nblocks_uncached = 0;
	pds->filedesc.rawfd = -1;
	pds->iovec = NULL;

	return pds;
}

pgstrom_data_store *
__PDS_create_hash(GpuContext *gcontext,
				  TupleDesc tupdesc,
				  size_t bytesize,
				  const char *filename, int lineno)
{
	pgstrom_data_store *pds;
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	bytesize = STROMALIGN_DOWN(bytesize);
	if (KDS_calculateHeadSize(tupdesc) > bytesize)
		elog(ERROR, "Required length for KDS-Hash is too short");

	rc = __gpuMemAllocManaged(gcontext,
							  &m_deviceptr,
							  offsetof(pgstrom_data_store,
									   kds) + bytesize,
							  CU_MEM_ATTACH_GLOBAL,
							  filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("out of managed memory");
	pds = (pgstrom_data_store *) m_deviceptr;

	/* setup */
	memset(pds, 0, offsetof(pgstrom_data_store, kds));
	pds->gcontext = gcontext;
	pg_atomic_init_u32(&pds->refcnt, 1);
	init_kernel_data_store(&pds->kds, tupdesc, bytesize,
						   KDS_FORMAT_HASH, INT_MAX);
	pds->nblocks_uncached = 0;
	pds->filedesc.rawfd = -1;
	pds->iovec = NULL;

	return pds;
}

pgstrom_data_store *
__PDS_create_slot(GpuContext *gcontext,
				  TupleDesc tupdesc,
				  size_t bytesize,
				  const char *filename, int lineno)
{
	pgstrom_data_store *pds;
	CUdeviceptr	m_deviceptr;
	CUresult	rc;
	size_t		kds_head_sz;
	size_t		unitsz;
	size_t		nrooms = UINT_MAX;

	bytesize = STROMALIGN_DOWN(bytesize);
	kds_head_sz = KDS_calculateHeadSize(tupdesc);
	if (kds_head_sz > bytesize)
		elog(ERROR, "Required length for KDS-Slot is too short");
	unitsz = MAXALIGN((sizeof(Datum) + sizeof(char)) * tupdesc->natts);
	if (unitsz > 0)
		nrooms = (bytesize - kds_head_sz) / unitsz;

	rc = __gpuMemAllocManaged(gcontext,
							  &m_deviceptr,
							  offsetof(pgstrom_data_store,
									   kds) + bytesize,
							  CU_MEM_ATTACH_GLOBAL,
							  filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("out of managed memory");
	pds = (pgstrom_data_store *) m_deviceptr;

	/* setup */
	memset(pds, 0, offsetof(pgstrom_data_store, kds));
	pds->gcontext = gcontext;
	pg_atomic_init_u32(&pds->refcnt, 1);
	init_kernel_data_store(&pds->kds, tupdesc,
						   bytesize - offsetof(pgstrom_data_store, kds),
						   KDS_FORMAT_SLOT, nrooms);
	pds->nblocks_uncached = 0;
	pds->filedesc.rawfd = -1;
	pds->iovec = NULL;

	return pds;
}

pgstrom_data_store *
__PDS_create_block(GpuContext *gcontext,
				   TupleDesc tupdesc,
				   NVMEScanState *nvme_sstate,
				   const char *filename, int lineno)
{
	pgstrom_data_store *pds = NULL;
	cl_uint		nrooms = nvme_sstate->nblocks_per_chunk;
	size_t		length;
	size_t		iovec_sz;
	CUresult	rc;

	length = KDS_calculateHeadSize(tupdesc)
		+ STROMALIGN(sizeof(BlockNumber) * nrooms)
		+ BLCKSZ * nrooms;
	iovec_sz = MAXALIGN(offsetof(strom_io_vector, ioc[nrooms]));

	if (offsetof(pgstrom_data_store,
				 kds) + length + iovec_sz > pgstrom_chunk_size())
		elog(ERROR,
			 "Bug? PDS length (%zu) is larger than pg_strom.chunk_size(%zu)",
			 offsetof(pgstrom_data_store, kds) + length + iovec_sz,
			 pgstrom_chunk_size());

	rc = __gpuMemAllocHost(gcontext,
						   (void **)&pds,
						   pgstrom_chunk_size(),
						   filename, lineno);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocHost: %s", errorText(rc));
	/* setup */
	memset(pds, 0, offsetof(pgstrom_data_store, kds));
	pds->gcontext = gcontext;
	pg_atomic_init_u32(&pds->refcnt, 1);
	init_kernel_data_store(&pds->kds, tupdesc, length,
						   KDS_FORMAT_BLOCK, nrooms);
	pds->kds.nrows_per_block = nvme_sstate->nrows_per_block;
	pds->nblocks_uncached = 0;
	pds->filedesc.rawfd = -1;
	pds->iovec = (strom_io_vector *)((char *)&pds->kds + length);
	pds->iovec->nr_chunks = 0;

	return pds;
}

/*
 * debug support
 */
void
KDS_dump_schema(kern_data_store *kds)
{
	int		j;

	elog(INFO, "KDS { length=%zu, nitems=%u, usage=%u, nrooms=%u, ncols=%d, format=%d, has_varlena=%s }",
		 kds->length,
		 kds->nitems,
		 kds->usage,
		 kds->nrooms,
		 kds->ncols,
		 kds->format,
		 kds->has_varlena ? "true" : "false");
	for (j=0; j < kds->nr_colmeta; j++)
	{
		kern_colmeta   *cmeta = &kds->colmeta[j];

		elog(INFO, "cmeta%c%d%c { attbyval=%d, attalign=%d, attlen=%d, attnum=%d, attcacheoff=%d, atttypid=%u, atttypmod=%d, atttypkind=%d }",
			 j < kds->ncols ? '[' : '(',
			 j,
			 j < kds->ncols ? ']' : ')',
			 cmeta->attbyval,
			 cmeta->attalign,
			 cmeta->attlen,
			 cmeta->attnum,
			 cmeta->attcacheoff,
			 cmeta->atttypid,
			 cmeta->atttypmod,
			 cmeta->atttypkind);
	}
}

/*
 * support for bulkload onto ROW/BLOCK format
 */

/*
 * nvme_sstate_open_smgr - fetch File descriptor of relation
 *
 * see storage/smgr/md.c
 */
typedef struct _MdfdVec
{
	File			mdfd_vfd;		/* fd number in fd.c's pool */
	BlockNumber		mdfd_segno;		/* segment number, from 0 */
} MdfdVec;

static void
nvme_sstate_open_files(GpuContext *gcontext,
					   NVMEScanState *nvme_sstate,
					   Relation relation)
{
	SMgrRelation rd_smgr = relation->rd_smgr;
	MdfdVec	   *vec;
	int			i, nr_open_segs;

	nr_open_segs = rd_smgr->md_num_open_segs[MAIN_FORKNUM];
	for (i=0; i < nvme_sstate->nr_segs; i++)
	{
		GPUDirectFileDesc *dfile = &nvme_sstate->files[i];

		if (i < nr_open_segs)
		{
			vec = &rd_smgr->md_seg_fds[MAIN_FORKNUM][i];
			if (vec->mdfd_segno != i)
				elog(ERROR, "Bug? mdfd_segno is not consistent");
			if (vec->mdfd_vfd < 0)
				elog(ERROR, "Bug? seg=%d of relation %s is not opened",
					 i, RelationGetRelationName(relation));
			gpuDirectFileDescOpen(dfile, vec->mdfd_vfd);
		}
		else
		{
			/* see _mdfd_openseg() and _mdfd_segpath() */
			const char *pathname;
			char	   *temp;

			temp = relpath(rd_smgr->smgr_rnode, MAIN_FORKNUM);
			if (i == 0)
				pathname = temp;
			else
			{
				pathname = psprintf("%s.%u", temp, i);
				pfree(temp);
			}
			gpuDirectFileDescOpenByPath(dfile, pathname);
		}

		if (!trackRawFileDesc(gcontext, dfile, __FILE__, __LINE__))
		{
			gpuDirectFileDescClose(dfile);
			elog(ERROR, "out of memory");
		}
	}
}

/*
 * PDS_init_heapscan_state - construct a per-query state for heap-scan
 * with KDS_FORMAT_BLOCK / NVMe-Strom.
 */
void
PDS_init_heapscan_state(GpuTaskState *gts)
{
	GpuContext	   *gcontext = gts->gcontext;
	Relation		relation = gts->css.ss.ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(relation);
	EState		   *estate = gts->css.ss.ps.state;
	cl_uint			nrows_per_block = gts->outer_nrows_per_block;
	BlockNumber		nr_blocks;
	BlockNumber		nr_segs;
	NVMEScanState  *nvme_sstate;
	size_t			kds_head_sz;
	cl_uint			nrooms_max;
	cl_uint			nchunks;
	cl_uint			nblocks_per_chunk;

	/*
	 * Check storage capability of NVMe-Strom
	 */
	if (nrows_per_block == 0 ||
		!RelationCanUseNvmeStrom(relation) ||
		(nr_blocks = RelationGetNumberOfBlocks(relation)) <= RELSEG_SIZE)
	{
		return;
	}

	/*
	 * Calculation of an optimal number of data-blocks for each PDS.
	 *
	 * We intend to load maximum available blocks onto the PDS which has
	 * configured chunk size, however, it will lead unbalanced smaller
	 * chunk around the bound of storage file segment.
	 * (Typically, 32 of 4091blocks + 1 of 160 blocks)
	 * So, we will adjust @nblocks_per_chunk to balance chunk size all
	 * around the relation scan.
	 */
	kds_head_sz = KDS_calculateHeadSize(tupdesc);
	nrooms_max = (pgstrom_chunk_size() -
				  offsetof(pgstrom_data_store, kds) -
				  kds_head_sz -
				  offsetof(strom_io_vector, ioc))
		/ (sizeof(BlockNumber) + BLCKSZ + sizeof(strom_io_chunk));
	while (offsetof(pgstrom_data_store,
					kds) + kds_head_sz +
		   STROMALIGN(sizeof(BlockNumber) * nrooms_max) +
		   BLCKSZ * nrooms_max +
		   MAXALIGN(offsetof(strom_io_vector,
							 ioc[nrooms_max])) > pgstrom_chunk_size())
		nrooms_max--;
	if (nrooms_max < 1)
		return;

	nchunks = (RELSEG_SIZE + nrooms_max - 1) / nrooms_max;
	nblocks_per_chunk = (RELSEG_SIZE + nchunks - 1) / nchunks;

	/* allocation of NVMEScanState structure */
	nr_segs = (nr_blocks + (BlockNumber) RELSEG_SIZE - 1) / RELSEG_SIZE;
	nvme_sstate = MemoryContextAllocZero(estate->es_query_cxt,
										 offsetof(NVMEScanState,
												  files[nr_segs]));
	nvme_sstate->nrows_per_block = nrows_per_block;
	nvme_sstate->nblocks_per_chunk = nblocks_per_chunk;
	nvme_sstate->curr_segno = InvalidBlockNumber;
	nvme_sstate->curr_vmbuffer = InvalidBuffer;
	nvme_sstate->nr_segs = nr_segs;
	nvme_sstate_open_files(gcontext, nvme_sstate, relation);

	gts->nvme_sstate = nvme_sstate;
}

/*
 * PDS_end_heapscan_state
 */
void
PDS_end_heapscan_state(GpuTaskState *gts)
{
	GpuContext	   *gcontext = gts->gcontext;
	NVMEScanState  *nvme_sstate = gts->nvme_sstate;
	int				i;

	if (nvme_sstate)
	{
		/* release visibility map, if any */
		if (nvme_sstate->curr_vmbuffer != InvalidBuffer)
		{
			ReleaseBuffer(nvme_sstate->curr_vmbuffer);
			nvme_sstate->curr_vmbuffer = InvalidBuffer;
		}
		/* close file descriptors, if any */
		for (i=0; i < nvme_sstate->nr_segs; i++)
		{
			untrackRawFileDesc(gcontext, &nvme_sstate->files[i]);
			gpuDirectFileDescClose(&nvme_sstate->files[i]);
		}
		pfree(nvme_sstate);
		gts->nvme_sstate = NULL;
	}
}

/*
 * PDS_insert_tuple
 *
 * It inserts a tuple onto the data store. Unlike block read mode, we cannot
 * use this API only for row-format.
 */
bool
KDS_insert_tuple(kern_data_store *kds, TupleTableSlot *slot)
{
	size_t			curr_usage;
	HeapTuple		tuple;
	cl_uint		   *tup_index;
	kern_tupitem   *tup_item;

	/* No room to store a new kern_rowitem? */
	if (kds->nitems >= kds->nrooms)
		return false;
	Assert(kds->ncols == slot->tts_tupleDescriptor->natts);

	if (kds->format != KDS_FORMAT_ROW)
		elog(ERROR, "Bug? unexpected data-store format: %d", kds->format);

	/* OK, put a record */
	tup_index = KERN_DATA_STORE_ROWINDEX(kds);

	/* reference a HeapTuple in TupleTableSlot */
	tuple = ExecFetchSlotHeapTuple(slot, false, NULL);

	/* check whether we have room for this tuple */
	curr_usage = (__kds_unpack(kds->usage) +
				  MAXALIGN(offsetof(kern_tupitem, htup) + tuple->t_len));
	if (KERN_DATA_STORE_HEAD_LENGTH(kds) +
		STROMALIGN(sizeof(cl_uint) * (kds->nitems + 1)) +
		STROMALIGN(curr_usage) > kds->length)
		return false;

	tup_item = (kern_tupitem *)((char *)kds + kds->length - curr_usage);
	tup_item->rowid = kds->nitems;
	tup_item->t_len = tuple->t_len;
	memcpy(&tup_item->htup, tuple->t_data, tuple->t_len);
	memcpy(&tup_item->htup.t_ctid, &tuple->t_self, sizeof(ItemPointerData));
	tup_index[kds->nitems++] = __kds_packed((uintptr_t)tup_item -
											(uintptr_t)kds);
	kds->usage = __kds_packed(curr_usage);

	return true;
}


/*
 * PDS_insert_hashitem
 *
 * It inserts a tuple to the data store of hash format.
 */
bool
KDS_insert_hashitem(kern_data_store *kds,
					TupleTableSlot *slot,
					cl_uint hash_value)
{
	cl_uint		   *row_index = KERN_DATA_STORE_ROWINDEX(kds);
	size_t			curr_usage;
	HeapTuple		tuple;
	kern_hashitem  *khitem;

	/* No room to store a new kern_hashitem? */
	if (kds->nitems >= kds->nrooms)
		return false;
	Assert(kds->ncols == slot->tts_tupleDescriptor->natts);

	/* KDS has to be KDS_FORMAT_HASH */
	if (kds->format != KDS_FORMAT_HASH)
		elog(ERROR, "Bug? unexpected data-store format: %d", kds->format);

	/* compute required length */
	tuple = ExecFetchSlotHeapTuple(slot, false, NULL);
	curr_usage = (__kds_unpack(kds->usage) +
				  MAXALIGN(offsetof(kern_hashitem, t.htup) + tuple->t_len));

	if (KERN_DATA_STORE_HEAD_LENGTH(kds) +
		STROMALIGN(sizeof(cl_uint) * (kds->nitems + 1)) +
		STROMALIGN(sizeof(cl_uint) * __KDS_NSLOTS(kds->nitems + 1)) +
		STROMALIGN(curr_usage) > kds->length)
		return false;	/* no more space to put */

	/* OK, put a tuple */
	khitem = (kern_hashitem *)((char *)kds + kds->length - curr_usage);
	khitem->hash = hash_value;
	khitem->next = 0x7f7f7f7f;	/* to be set later */
	khitem->t.rowid = kds->nitems;
	khitem->t.t_len = tuple->t_len;
	memcpy(&khitem->t.htup, tuple->t_data, tuple->t_len);
	memcpy(&khitem->t.htup.t_ctid, &tuple->t_self, sizeof(ItemPointerData));

	row_index[kds->nitems++] = __kds_packed((char *)&khitem->t.t_len -
											(char *)kds);
	kds->usage = __kds_packed(curr_usage);

	return true;
}

/*
 * PDS_fillup_blocks
 *
 * It fills up uncached blocks using synchronous read APIs.
 */
void
PDS_fillup_blocks(pgstrom_data_store *pds)
{
	cl_int			filedesc = pds->filedesc.rawfd;
	cl_int			i, nr_loaded;
	ssize_t			nbytes;
	char		   *dest_addr;
	loff_t			curr_fpos;
	size_t			curr_size;
	BlockNumber	   *block_nums;

	if (pds->kds.format != KDS_FORMAT_BLOCK)
		elog(ERROR, "Bug? only KDS_FORMAT_BLOCK can be filled up");

	if (pds->nblocks_uncached == 0)
		return;		/* already filled up */

	Assert(filedesc >= 0);
	Assert(pds->nblocks_uncached <= pds->kds.nitems);
	nr_loaded = pds->kds.nitems - pds->nblocks_uncached;
	block_nums = (BlockNumber *)KERN_DATA_STORE_BODY(&pds->kds);
	dest_addr = (char *)KERN_DATA_STORE_BLOCK_PGPAGE(&pds->kds, nr_loaded);
	curr_fpos = 0;
	curr_size = 0;
	for (i=pds->nblocks_uncached-1; i >=0; i--)
	{
		loff_t	file_pos = (block_nums[i] & (RELSEG_SIZE - 1)) * BLCKSZ;

		if (curr_size > 0 &&
			curr_fpos + curr_size == file_pos)
		{
			/* merge with the pending i/o */
			curr_size += BLCKSZ;
		}
		else
		{
			while (curr_size > 0)
			{
				nbytes = pread(filedesc, dest_addr, curr_size, curr_fpos);
				Assert(nbytes <= curr_size);
				if (nbytes < 0 || (nbytes == 0 && errno != EINTR))
					elog(ERROR, "failed on pread(2): %m");
				dest_addr += nbytes;
				curr_fpos += nbytes;
				curr_size -= nbytes;
			}
			curr_fpos = file_pos;
			curr_size = BLCKSZ;
		}
	}

	while (curr_size > 0)
	{
		nbytes = pread(filedesc, dest_addr, curr_size, curr_fpos);
		Assert(nbytes <= curr_size);
		if (nbytes < 0 || (nbytes == 0 && errno != EINTR))
			elog(ERROR, "failed on pread(2): %m");
		dest_addr += nbytes;
		curr_fpos += nbytes;
		curr_size -= nbytes;
	}
	Assert(dest_addr == (char *)KERN_DATA_STORE_BLOCK_PGPAGE(&pds->kds,
															 pds->kds.nitems));
	pds->nblocks_uncached = 0;
}

/*
 * PDS_fillup_arrow
 */
void
__PDS_fillup_arrow(pgstrom_data_store *pds_dst,
				   GpuContext *gcontext,
				   kern_data_store *kds_head,
				   int fdesc, strom_io_vector *iovec)
{
	size_t	head_sz = KERN_DATA_STORE_HEAD_LENGTH(kds_head);
	int		j;

	Assert(kds_head->format == KDS_FORMAT_ARROW);
	memset(pds_dst, 0, offsetof(pgstrom_data_store, kds));
	pds_dst->gcontext = gcontext;
	pg_atomic_init_u32(&pds_dst->refcnt, 1);
	pds_dst->nblocks_uncached = 0;
	pds_dst->filedesc.rawfd = -1;
	pds_dst->iovec = NULL;
	memcpy(&pds_dst->kds, kds_head, head_sz);

	for (j=0; j < iovec->nr_chunks; j++)
	{
		strom_io_chunk *ioc = &iovec->ioc[j];
		char   *dest = (char *)&pds_dst->kds + ioc->m_offset;
		off_t	f_pos = (size_t)ioc->fchunk_id * PAGE_SIZE;
		size_t	len = (size_t)ioc->nr_pages * PAGE_SIZE;
		ssize_t	sz;

		while (len > 0)
		{
			if (!GpuWorkerCurrentContext)
				CHECK_FOR_INTERRUPTS();
			else
				CHECK_WORKER_TERMINATION();

			sz = pread(fdesc, dest, len, f_pos);
			if (sz > 0)
			{
				Assert(sz <= len);
				dest += sz;
				f_pos += sz;
				len -= sz;
			}
			else if (sz == 0)
			{
				/*
				 * Due to the page_sz alignment, we may try to read the file
				 * over its tail. So, pread(2) may tell us unable to read
				 * any more. The expected scenario happend only when remained
				 * length is less than PAGE_SIZE.
				 */
				if (len >= PAGE_SIZE)
					werror("unable to read arrow file any more");
				memset(dest, 0, len);
				break;
			}
			else if (errno != EINTR)
			{
				werror("failed on pread(2) of arrow file: %m");
			}
		}
		/*
		 * NOTE: Due to the page_sz alignment, we may try to read the file
		 * over the its tail. So, above loop may terminate with non-zero
		 * remaining length.
		 */
		if (len > 0)
		{
			Assert(len < PAGE_SIZE);
			memset(dest, 0, len);
		}
	}
}

/*
 * PDS_fillup_arrow - fills up PDS buffer using filesystem i/o
 */
pgstrom_data_store *
PDS_fillup_arrow(pgstrom_data_store *pds_src)
{
	pgstrom_data_store *pds_dst;
	CUresult	rc;

	rc = gpuMemAllocManaged(pds_src->gcontext,
							(CUdeviceptr *)&pds_dst,
							offsetof(pgstrom_data_store,
									 kds) + pds_src->kds.length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));
	__PDS_fillup_arrow(pds_dst,
					   pds_dst->gcontext,
					   &pds_src->kds,
					   pds_src->filedesc.rawfd,
					   pds_src->iovec);
	return pds_dst;
}

/*
 * PDS_writeback_arrow - write back PDS buffer on device memory to host
 *                       if buffer content is not kept in host-side.
 */
pgstrom_data_store *
PDS_writeback_arrow(pgstrom_data_store *pds_src,
					CUdeviceptr m_kds_src)
{
	pgstrom_data_store *pds_dst;
	CUresult		rc;

	Assert(pds_src->kds.format == KDS_FORMAT_ARROW &&
		   pds_src->iovec != NULL);
	rc = gpuMemAllocHostRaw(pds_src->gcontext,
							(void **)&pds_dst,
							offsetof(pgstrom_data_store,
									 kds) + pds_src->kds.length);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocHostRaw: %s", errorText(rc));

	memset(pds_dst, 0, offsetof(pgstrom_data_store, kds));
	pds_dst->gcontext = pds_src->gcontext;
	pg_atomic_init_u32(&pds_dst->refcnt, 1);
	pds_dst->filedesc.rawfd = -1;
	rc = cuMemcpyDtoH(&pds_dst->kds,
					  m_kds_src,
					  pds_src->kds.length);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemcpyDtoH: %s", errorText(rc));
	/* detach old buffer */
	PDS_release(pds_src);

	return pds_dst;
}
