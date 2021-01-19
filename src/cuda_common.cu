/*
 * libgpucore.cu
 *
 * Core implementation of GPU device code.
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
#include "cuda_postgis.h"

/*
 * __compute_heaptuple_size
 */
DEVICE_FUNCTION(cl_uint)
__compute_heaptuple_size(kern_context *kcxt,
						 kern_colmeta *__cmeta,
						 cl_bool heap_hasoid,
						 cl_uint ncols,
						 cl_char *tup_dclass,
						 Datum   *tup_values)
{
	cl_uint		t_hoff;
	cl_uint		datalen = 0;
	cl_uint		j;
	cl_bool		heap_hasnull = false;

	/* compute data length */
	for (j=0; j < ncols; j++)
	{
		kern_colmeta   *cmeta = &__cmeta[j];
		cl_char			dclass = tup_dclass[j];

		if (dclass == DATUM_CLASS__NULL)
			heap_hasnull = true;
		else if (cmeta->attlen > 0)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			datalen = TYPEALIGN(cmeta->attalign, datalen);
			datalen += cmeta->attlen;
		}
		else
		{
			Datum		datum = tup_values[j];
			cl_uint		vl_len;

			switch (dclass)
			{
				case DATUM_CLASS__VARLENA:
					vl_len = pg_varlena_datum_length(kcxt,datum);
					datalen = TYPEALIGN(cmeta->attalign, datalen);
					break;
				case DATUM_CLASS__ARRAY:
					vl_len = pg_array_datum_length(kcxt,datum);
					datalen = TYPEALIGN(cmeta->attalign, datalen);
					break;
				case DATUM_CLASS__COMPOSITE:
					vl_len = pg_composite_datum_length(kcxt,datum);
					datalen = TYPEALIGN(cmeta->attalign, datalen);
					break;
				case DATUM_CLASS__GEOMETRY:
					vl_len = pg_geometry_datum_length(kcxt,datum);
					datalen = TYPEALIGN(cmeta->attalign, datalen);
					break;
				default:
					assert(dclass == DATUM_CLASS__NORMAL);
					vl_len = VARSIZE_ANY(datum);
					if (!VARATT_IS_1B(datum))
						datalen = TYPEALIGN(cmeta->attalign, datalen);
					break;
			}
			datalen += vl_len;
		}
	}
	/* compute header offset */
	t_hoff = offsetof(HeapTupleHeaderData, t_bits);
	if (heap_hasnull)
		t_hoff += BITMAPLEN(ncols);
	if (heap_hasoid)
		t_hoff += sizeof(cl_uint);
	t_hoff = MAXALIGN(t_hoff);

	return t_hoff + datalen;
}

/*
 * deform_kern_heaptuple
 *
 * Like deform_heap_tuple in host side, it extracts the supplied tuple-item
 * into tup_values / tup_isnull array.
 *
 * NOTE: composite datum which is built-in other composite datum might not
 * be aligned to 4-bytes boundary. So, we don't touch htup fields directly,
 * except for 1-byte datum.
 */
DEVICE_FUNCTION(void)
deform_kern_heaptuple(cl_int	nattrs,			/* in */
					  kern_colmeta *tup_attrs,	/* in */
					  HeapTupleHeaderData *htup,/* in */
					  cl_char  *tup_dclass,		/* out */
					  Datum	   *tup_values)		/* out */
{
	/* 'htup' must be aligned to 8bytes */
	assert(((cl_ulong)htup & (MAXIMUM_ALIGNOF-1)) == 0);
	if (!htup)
	{
		int		i;

		for (i=0; i < nattrs; i++)
			tup_dclass[i] = DATUM_CLASS__NULL;
	}
	else
	{
		cl_uint		offset = htup->t_hoff;
		cl_bool		tup_hasnull = ((htup->t_infomask & HEAP_HASNULL) != 0);
		cl_uint		i, ncols = (htup->t_infomask2 & HEAP_NATTS_MASK);

		ncols = Min(ncols, nattrs);
		for (i=0; i < ncols; i++)
		{
			if (tup_hasnull && att_isnull(i, htup->t_bits))
			{
				tup_dclass[i] = DATUM_CLASS__NULL;
				tup_values[i] = 0;
			}
			else
			{
				kern_colmeta   *cmeta = &tup_attrs[i];
				char		   *addr;

				if (cmeta->attlen > 0)
					offset = TYPEALIGN(cmeta->attalign, offset);
				else if (!VARATT_NOT_PAD_BYTE((char *)htup + offset))
					offset = TYPEALIGN(cmeta->attalign, offset);

				/* Store the value */
				addr = ((char *) htup + offset);
				if (cmeta->attbyval)
				{
					if (cmeta->attlen == sizeof(cl_char))
						tup_values[i] = *((cl_char *)addr);
					else if (cmeta->attlen == sizeof(cl_short))
						tup_values[i] = *((cl_short *)addr);
					else if (cmeta->attlen == sizeof(cl_int))
						tup_values[i] = *((cl_int *)addr);
					else if (cmeta->attlen == sizeof(cl_long))
						tup_values[i] = *((cl_long *)addr);
					else
					{
						assert(cmeta->attlen <= sizeof(Datum));
						memcpy(&tup_values[i], addr, cmeta->attlen);
					}
					offset += cmeta->attlen;
				}
				else
				{
					cl_uint		attlen = (cmeta->attlen > 0
										  ? cmeta->attlen
										  : VARSIZE_ANY(addr));
					tup_values[i] = PointerGetDatum(addr);
					offset += attlen;
				}
				tup_dclass[i] = DATUM_CLASS__NORMAL;
			}
		}
		/*
		 * Fill up remaining columns if source tuple has less columns than
		 * length of the array; that is definition of the destination
		 */
		while (i < nattrs)
			tup_dclass[i++] = DATUM_CLASS__NORMAL;
	}
}

/*
 * __form_kern_heaptuple
 */
DEVICE_FUNCTION(cl_uint)
__form_kern_heaptuple(kern_context *kcxt,
					  void	   *buffer,			/* out */
					  cl_int	ncols,			/* in */
					  kern_colmeta *colmeta,	/* in */
					  cl_uint	comp_typeid,	/* in */
					  cl_int	comp_typmod,	/* in */
					  ItemPointerData *tup_self,/* in: optional */
					  cl_char  *tup_dclass,		/* in */
					  Datum	   *tup_values)		/* in */
{
	HeapTupleHeaderData *htup = (HeapTupleHeaderData *)buffer;
	cl_bool		tup_hasnull = false;
	cl_ushort	t_infomask;
	cl_uint		t_hoff;
	cl_uint		i, curr;

	/* alignment checks */
	assert((cl_ulong)htup == MAXALIGN(htup));

	/* has any NULL attributes? */
	if (tup_dclass != NULL)
	{
		for (i=0; i < ncols; i++)
		{
			if (tup_dclass[i] == DATUM_CLASS__NULL)
			{
				tup_hasnull = true;
				break;
			}
		}
	}
	t_infomask = (tup_hasnull ? HEAP_HASNULL : 0);

	/* set up header */
	htup->t_choice.t_datum.datum_typmod = comp_typmod;
	htup->t_choice.t_datum.datum_typeid = comp_typeid;
	if (tup_self)
		memcpy(&htup->t_ctid, tup_self, sizeof(ItemPointerData));
	else
	{
		htup->t_ctid.ip_blkid.bi_hi = 0xffff;	/* InvalidBlockNumber */
		htup->t_ctid.ip_blkid.bi_lo = 0xffff;
		htup->t_ctid.ip_posid = 0;				/* InvalidOffsetNumber */
	}
	htup->t_infomask2 = (ncols & HEAP_NATTS_MASK);

	/* computer header size */
	t_hoff = offsetof(HeapTupleHeaderData, t_bits);
	if (tup_hasnull)
		t_hoff += BITMAPLEN(ncols);
	t_hoff = MAXALIGN(t_hoff);

	/* walk on the regular columns */
	htup->t_hoff = t_hoff;
	curr = t_hoff;
	for (i=0; i < ncols; i++)
	{
		kern_colmeta *cmeta = &colmeta[i];
		Datum		datum = tup_values[i];
		cl_char		dclass;
		cl_int		padding;

		dclass = (!tup_dclass ? DATUM_CLASS__NORMAL : tup_dclass[i]);
		if (dclass == DATUM_CLASS__NULL)
		{
			assert(tup_hasnull);
			htup->t_bits[i >> 3] &= ~(1 << (i & 0x07));
			continue;
		}

		if (tup_hasnull)
			htup->t_bits[i >> 3] |= (1 << (i & 0x07));

		padding = TYPEALIGN(cmeta->attalign, curr) - curr;
		if (cmeta->attbyval)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			while (padding-- > 0)
				((char *)htup)[curr++] = '\0';
			assert(cmeta->attlen <= sizeof(datum));
			memcpy((char *)htup + curr, &datum, cmeta->attlen);
			curr += cmeta->attlen;
		}
		else if (cmeta->attlen > 0)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			while (padding-- > 0)
				((char *)htup)[curr++] = '\0';
			memcpy((char *)htup + curr,
				   DatumGetPointer(datum), cmeta->attlen);
			curr += cmeta->attlen;
		}
		else
		{
			cl_int		vl_len;

			switch (dclass)
			{
				case DATUM_CLASS__VARLENA:
					while (padding-- > 0)
						((char *)htup)[curr++] = '\0';
					vl_len = pg_varlena_datum_write(kcxt,
													(char *)htup+curr,
													datum);
					break;
				case DATUM_CLASS__ARRAY:
					while (padding-- > 0)
						((char *)htup)[curr++] = '\0';
					vl_len = pg_array_datum_write(kcxt,
												  (char *)htup+curr,
												  datum);
					break;
				case DATUM_CLASS__COMPOSITE:
					while (padding-- > 0)
						((char *)htup)[curr++] = '\0';
					vl_len = pg_composite_datum_write(kcxt,
													  (char *)htup+curr,
													  datum);
					break;
				case DATUM_CLASS__GEOMETRY:
					while (padding-- > 0)
						((char *)htup)[curr++] = '\0';
					vl_len = pg_geometry_datum_write(kcxt,
													 (char *)htup+curr,
													 datum);
					break;
				default:
					assert(dclass == DATUM_CLASS__NORMAL);
					vl_len = VARSIZE_ANY(datum);
					if (!VARATT_IS_1B(datum))
					{
						while (padding-- > 0)
							((char *)htup)[curr++] = '\0';
					}
					memcpy((char *)htup + curr,
						   DatumGetPointer(datum), vl_len);
					break;
			}
			t_infomask |= HEAP_HASVARWIDTH;
			curr += vl_len;
		}
	}
	htup->t_infomask = t_infomask;
	SET_VARSIZE(&htup->t_choice.t_datum, curr);
	return curr;
}

/*
 * kds_slot_compute_extra
 */
DEVICE_FUNCTION(cl_uint)
kds_slot_compute_extra(kern_context *kcxt,
					   kern_data_store *kds,
					   cl_char *tup_dclass,
					   Datum   *tup_values)
{
	cl_uint		extra_sz = 0;

	for (int j=0; j < kds->ncols; j++)
	{
		kern_colmeta *cmeta = &kds->colmeta[j];
		cl_char		dclass = tup_dclass[j];

		if (dclass == DATUM_CLASS__NULL)
			continue;

		if (cmeta->attbyval)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
		}
		else if (cmeta->attlen > 0)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			extra_sz = TYPEALIGN(cmeta->attalign, extra_sz);
			extra_sz += cmeta->attlen;
		}
		else
		{
			Datum	datum = tup_values[j];

			extra_sz = TYPEALIGN(cmeta->attalign, extra_sz);
			switch (dclass)
			{
				case DATUM_CLASS__NORMAL:
					extra_sz += VARSIZE_ANY(datum);
					break;
				case DATUM_CLASS__VARLENA:
					extra_sz += pg_varlena_datum_length(kcxt,datum);
					break;
				case DATUM_CLASS__ARRAY:
					extra_sz += pg_array_datum_length(kcxt,datum);
					break;
				case DATUM_CLASS__COMPOSITE:
					extra_sz += pg_composite_datum_length(kcxt,datum);
					break;
				case DATUM_CLASS__GEOMETRY:
					extra_sz += pg_geometry_datum_length(kcxt,datum);
					break;
				default:
					STROM_ELOG(kcxt, "unexpected DATUM_CLASS");
					return 0;
			}
		}
	}
	return MAXALIGN(extra_sz);
}

DEVICE_FUNCTION(void)
kds_slot_store_values(kern_context *kcxt,
					  kern_data_store *kds_dst,
					  cl_uint  dst_index,
					  char    *dst_extra,
					  cl_char *tup_dclass,
					  Datum   *tup_values)
{
	Datum	   *dst_values = KERN_DATA_STORE_VALUES(kds_dst, dst_index);
	cl_char	   *dst_dclass = KERN_DATA_STORE_DCLASS(kds_dst, dst_index);

	assert(dst_extra == (char *)MAXALIGN(dst_extra));
	assert(dst_extra >= (char *)(dst_dclass + kds_dst->ncols) &&
		   dst_extra <= (char *)kds_dst + kds_dst->length);
	for (int j=0; j < kds_dst->ncols; j++)
	{
		kern_colmeta *cmeta = &kds_dst->colmeta[j];
		cl_char		dclass = tup_dclass[j];
		cl_int		sz, padding;

		if (dclass == DATUM_CLASS__NULL)
		{
			dst_dclass[j] = DATUM_CLASS__NULL;
			dst_values[j] = 0;
		}
		else if (cmeta->attbyval)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			dst_dclass[j] = DATUM_CLASS__NORMAL;
			dst_values[j] = tup_values[j];
		}
		else if (cmeta->attlen > 0)
		{
			assert(dclass == DATUM_CLASS__NORMAL);
			padding = (char *)TYPEALIGN(cmeta->attalign,
										dst_extra) - dst_extra;
			while (padding-- > 0)
				*dst_extra++ = '\0';
			memcpy(dst_extra, (char *)tup_values[j], cmeta->attlen);
			dst_dclass[j] = DATUM_CLASS__NORMAL;
			dst_values[j] = PointerGetDatum(dst_extra);
			dst_extra += cmeta->attlen;
		}
		else
		{
			Datum	datum = tup_values[j];

			padding = (char *)TYPEALIGN(cmeta->attalign,
										dst_extra) - dst_extra;
			while (padding-- > 0)
				*dst_extra++ = '\0';
			switch (dclass)
			{
				case DATUM_CLASS__NORMAL:
					sz = VARSIZE_ANY(datum);
					memcpy(dst_extra, DatumGetPointer(datum), sz);
					break;
				case DATUM_CLASS__VARLENA:
					sz = pg_varlena_datum_write(kcxt, dst_extra, datum);
					break;
				case DATUM_CLASS__ARRAY:
					sz = pg_array_datum_write(kcxt, dst_extra, datum);
					break;
				case DATUM_CLASS__COMPOSITE:
					sz = pg_composite_datum_write(kcxt, dst_extra, datum);
					break;
				case DATUM_CLASS__GEOMETRY:
					sz = pg_geometry_datum_write(kcxt, dst_extra, datum);
					break;
				default:
					STROM_ELOG(kcxt, "unexpected DATUM_CLASS");
					return;
			}
			dst_dclass[j] = DATUM_CLASS__NORMAL;
            dst_values[j] = PointerGetDatum(dst_extra);
			dst_extra += sz;
		}
	}
}

/*
 * pgstromStairlikeSum
 *
 * A utility routine to calculate sum of values when we have N items and 
 * want to know sum of items[i=0...k] (k < N) for each k, using reduction
 * algorithm on local memory (so, it takes log2(N) + 1 steps)
 *
 * The 'my_value' argument is a value to be set on the items[get_local_id(0)].
 * Then, these are calculate as follows:
 *
 *           init   1st      2nd         3rd         4th
 *           state  step     step        step        step
 * items[0] = X0 -> X0    -> X0       -> X0       -> X0
 * items[1] = X1 -> X0+X1 -> X0+X1    -> X0+X1    -> X0+X1
 * items[2] = X2 -> X2    -> X0+...X2 -> X0+...X2 -> X0+...X2
 * items[3] = X3 -> X2+X3 -> X0+...X3 -> X0+...X3 -> X0+...X3
 * items[4] = X4 -> X4    -> X4       -> X0+...X4 -> X0+...X4
 * items[5] = X5 -> X4+X5 -> X4+X5    -> X0+...X5 -> X0+...X5
 * items[6] = X6 -> X6    -> X4+...X6 -> X0+...X6 -> X0+...X6
 * items[7] = X7 -> X6+X7 -> X4+...X7 -> X0+...X7 -> X0+...X7
 * items[8] = X8 -> X8    -> X8       -> X8       -> X0+...X8
 * items[9] = X9 -> X8+X9 -> X8+9     -> X8+9     -> X0+...X9
 *
 * In Nth step, we split the array into 2^N blocks. In 1st step, a unit
 * containt odd and even indexed items, and this logic adds the last value
 * of the earlier half onto each item of later half. In 2nd step, you can
 * also see the last item of the earlier half (item[1] or item[5]) shall
 * be added to each item of later half (item[2] and item[3], or item[6]
 * and item[7]). Then, iterate this step until 2^(# of steps) less than N.
 *
 * Note that supplied items[] must have at least sizeof(cl_uint) *
 * get_local_size(0), and its contents shall be destroyed.
 * Also note that this function internally use barrier(), so unable to
 * use within if-blocks.
 */
DEVICE_FUNCTION(cl_uint)
pgstromStairlikeSum(cl_uint my_value, cl_uint *total_sum)
{
	cl_uint	   *items = SHARED_WORKMEM(cl_uint);
	cl_uint		local_sz;
	cl_uint		local_id;
	cl_uint		unit_sz;
	cl_uint		stair_sum;
	cl_int		i, j;

	/* setup local size (pay attention, if 2D invocation) */
	local_sz = get_local_size();
	local_id = get_local_id();
	assert(local_id < local_sz);

	/* set initial value */
	items[local_id] = my_value;
	__syncthreads();

	for (i=1, unit_sz = local_sz; unit_sz > 0; i++, unit_sz >>= 1)
	{
		/* index of last item in the earlier half of each 2^i unit */
		j = (local_id & ~((1 << i) - 1)) | ((1 << (i-1)) - 1);

		/* add item[j] if it is later half in the 2^i unit */
		if ((local_id & (1 << (i - 1))) != 0)
			items[local_id] += items[j];
		__syncthreads();
	}
	if (total_sum)
		*total_sum = items[local_sz - 1];
	stair_sum = local_id == 0 ? 0 : items[local_id - 1];
	__syncthreads();
	return stair_sum;
}

/*
 * pgstromStairlikeBinaryCount
 *
 * A special optimized version of pgstromStairlikeSum, for binary count.
 * It has smaller number of __syncthreads().
 */
DEVICE_FUNCTION(cl_uint)
pgstromStairlikeBinaryCount(int predicate, cl_uint *total_count)
{
	cl_uint	   *items = SHARED_WORKMEM(cl_uint);
	cl_uint		nwarps = get_local_size() / warpSize;
	cl_uint		warp_id = get_local_id() / warpSize;
	cl_uint		w_bitmap;
	cl_uint		stair_count;
	cl_int		unit_sz;
	cl_int		i, j;

	w_bitmap = __ballot_sync(__activemask(), predicate);
	if ((get_local_id() & (warpSize-1)) == 0)
		items[warp_id] = __popc(w_bitmap);
	__syncthreads();

	for (i=1, unit_sz = nwarps; unit_sz > 0; i++, unit_sz >>= 1)
	{
		/* index of last item in the earlier half of each 2^i unit */
		j = (get_local_id() & ~((1<<i)-1)) | ((1<<(i-1))-1);

		/* add item[j] if it is later half in the 2^i unit */
		if (get_local_id() < nwarps &&
			(get_local_id() & (1 << (i-1))) != 0)
			items[get_local_id()] += items[j];
		__syncthreads();
	}
	if (total_count)
		*total_count = items[nwarps - 1];
	w_bitmap &= (1U << (get_local_id() & (warpSize-1))) - 1;
	stair_count = (warp_id == 0 ? 0 : items[warp_id - 1]) + __popc(w_bitmap);
	__syncthreads();

	return stair_count;
}

/*
 * Device version of hash_any() in PG host code
 */
#define rot(x,k)		(((x)<<(k)) | ((x)>>(32-(k))))
#define mix(a,b,c)								\
	{											\
		a -= c;  a ^= rot(c, 4);  c += b;		\
		b -= a;  b ^= rot(a, 6);  a += c;		\
		c -= b;  c ^= rot(b, 8);  b += a;		\
		a -= c;  a ^= rot(c,16);  c += b;		\
		b -= a;  b ^= rot(a,19);  a += c;		\
		c -= b;  c ^= rot(b, 4);  b += a;		\
	}

#define final(a,b,c)							\
	{											\
		c ^= b; c -= rot(b,14);					\
		a ^= c; a -= rot(c,11);					\
		b ^= a; b -= rot(a,25);					\
		c ^= b; c -= rot(b,16);					\
		a ^= c; a -= rot(c, 4);					\
		b ^= a; b -= rot(a,14);					\
		c ^= b; c -= rot(b,24);					\
	}

DEVICE_FUNCTION(cl_uint)
pg_hash_any(const cl_uchar *k, cl_int keylen)
{
	cl_uint		a, b, c;
	cl_uint		len;

	/* Set up the internal state */
	len = keylen;
	a = b = c = 0x9e3779b9 + len + 3923095;

	/* If the source pointer is word-aligned, we use word-wide fetches */
	if (((cl_ulong) k & (sizeof(cl_uint) - 1)) == 0)
	{
		/* Code path for aligned source data */
		const cl_uint	*ka = (const cl_uint *) k;

		/* handle most of the key */
		while (len >= 12)
		{
			a += ka[0];
			b += ka[1];
			c += ka[2];
			mix(a, b, c);
			ka += 3;
			len -= 12;
		}

		/* handle the last 11 bytes */
		k = (const unsigned char *) ka;
		switch (len)
		{
			case 11:
				c += ((cl_uint) k[10] << 24);
				/* fall through */
			case 10:
				c += ((cl_uint) k[9] << 16);
				/* fall through */
			case 9:
				c += ((cl_uint) k[8] << 8);
				/* the lowest byte of c is reserved for the length */
				/* fall through */
			case 8:
				b += ka[1];
				a += ka[0];
				break;
			case 7:
				b += ((cl_uint) k[6] << 16);
				/* fall through */
			case 6:
				b += ((cl_uint) k[5] << 8);
				/* fall through */
			case 5:
				b += k[4];
				/* fall through */
			case 4:
				a += ka[0];
				break;
			case 3:
				a += ((cl_uint) k[2] << 16);
				/* fall through */
			case 2:
				a += ((cl_uint) k[1] << 8);
				/* fall through */
			case 1:
				a += k[0];
				/* case 0: nothing left to add */
		}
	}
	else
	{
		/* Code path for non-aligned source data */

		/* handle most of the key */
		while (len >= 12)
		{
			a += k[0] + (((cl_uint) k[1] << 8) +
						 ((cl_uint) k[2] << 16) +
						 ((cl_uint) k[3] << 24));
			b += k[4] + (((cl_uint) k[5] << 8) +
						 ((cl_uint) k[6] << 16) +
						 ((cl_uint) k[7] << 24));
			c += k[8] + (((cl_uint) k[9] << 8) +
						 ((cl_uint) k[10] << 16) +
						 ((cl_uint) k[11] << 24));
			mix(a, b, c);
			k += 12;
			len -= 12;
		}

		/* handle the last 11 bytes */
		switch (len)            /* all the case statements fall through */
		{
			case 11:
				c += ((cl_uint) k[10] << 24);
			case 10:
				c += ((cl_uint) k[9] << 16);
			case 9:
				c += ((cl_uint) k[8] << 8);
				/* the lowest byte of c is reserved for the length */
			case 8:
				b += ((cl_uint) k[7] << 24);
			case 7:
				b += ((cl_uint) k[6] << 16);
			case 6:
				b += ((cl_uint) k[5] << 8);
			case 5:
				b += k[4];
			case 4:
				a += ((cl_uint) k[3] << 24);
			case 3:
				a += ((cl_uint) k[2] << 16);
			case 2:
				a += ((cl_uint) k[1] << 8);
			case 1:
				a += k[0];
				/* case 0: nothing left to add */
		}
	}
	final(a, b, c);

	return c;
}
#undef rot
#undef mix
#undef final

/*
 * varlena compress/decompress functions
 */

/*
 * toast_raw_datum_size - return the raw (detoasted) size of a varlena
 * datum (including the VARHDRSZ header)
 */
DEVICE_FUNCTION(size_t)
toast_raw_datum_size(kern_context *kcxt, varlena *attr)
{
	size_t		result;

	if (VARATT_IS_EXTERNAL(attr))
	{
		if (VARATT_IS_EXTERNAL_ONDISK(attr))
		{
			varatt_external	va_ext;

			memcpy(&va_ext, ((varattrib_1b_e *)attr)->va_data,
				   sizeof(varatt_external));
			result = va_ext.va_rawsize;
		}
		else
		{
			/* should not appear in the kernel space */
			STROM_CPU_FALLBACK(kcxt, ERRCODE_STROM_VARLENA_UNSUPPORTED,
							   "unsupported varlena datum on device");
			result = 0;
		}
	}
	else if (VARATT_IS_COMPRESSED(attr))
	{
		/* here, va_rawsize is just the payload size */
		result = VARRAWSIZE_4B_C(attr) + VARHDRSZ;
	}
	else if (VARATT_IS_SHORT(attr))
	{
		/*
		 * we have to normalize the header length to VARHDRSZ or else the
		 * callers of this function will be confused.
		 */
		result = VARSIZE_SHORT(attr) - VARHDRSZ_SHORT + VARHDRSZ;
	}
	else
	{
		/* plain untoasted datum */
		result = VARSIZE(attr);
	}
	return result;
}

/*
 * toast_decompress_datum - decompress a compressed version of a varlena datum
 */
DEVICE_FUNCTION(cl_int)
pglz_decompress(const char *source, cl_int slen,
				char *dest, cl_int rawsize)
{
	const cl_uchar *sp;
	const cl_uchar *srcend;
	cl_uchar	   *dp;
	cl_uchar	   *destend;

	sp = (const cl_uchar *) source;
	srcend = ((const cl_uchar *) source) + slen;
	dp = (cl_uchar *) dest;
	destend = dp + rawsize;

	while (sp < srcend && dp < destend)
	{
		/*
		 * Read one control byte and process the next 8 items (or as many as
		 * remain in the compressed input).
		 */
		cl_uchar	ctrl = *sp++;
		int			ctrlc;

		for (ctrlc = 0; ctrlc < 8 && sp < srcend; ctrlc++)
		{
			if (ctrl & 1)
			{
				/*
				 * Otherwise it contains the match length minus 3 and the
				 * upper 4 bits of the offset. The next following byte
				 * contains the lower 8 bits of the offset. If the length is
				 * coded as 18, another extension tag byte tells how much
				 * longer the match really was (0-255).
				 */
				cl_int		len;
				cl_int		off;

				len = (sp[0] & 0x0f) + 3;
				off = ((sp[0] & 0xf0) << 4) | sp[1];
				sp += 2;
				if (len == 18)
					len += *sp++;

				/*
				 * Check for output buffer overrun, to ensure we don't clobber
				 * memory in case of corrupt input.  Note: we must advance dp
				 * here to ensure the error is detected below the loop.  We
				 * don't simply put the elog inside the loop since that will
				 * probably interfere with optimization.
				 */
				if (dp + len > destend)
				{
					dp += len;
					break;
				}
				/*
				 * Now we copy the bytes specified by the tag from OUTPUT to
				 * OUTPUT. It is dangerous and platform dependent to use
				 * memcpy() here, because the copied areas could overlap
				 * extremely!
				 */
				while (len--)
				{
					*dp = dp[-off];
					dp++;
				}
			}
			else
			{
				/*
				 * An unset control bit means LITERAL BYTE. So we just copy
				 * one from INPUT to OUTPUT.
				 */
				if (dp >= destend)		/* check for buffer overrun */
					break;				/* do not clobber memory */

				*dp++ = *sp++;
			}

			/*
			 * Advance the control bit
			 */
			ctrl >>= 1;
		}
	}

	/*
	 * Check we decompressed the right amount.
	 */
	if (dp != destend || sp != srcend)
		return -1;

	/*
	 * That's it.
	 */
	return rawsize;
}

DEVICE_FUNCTION(cl_bool)
toast_decompress_datum(char *buffer, cl_uint buflen,
					   const varlena *datum)
{
	cl_int		rawsize;

	assert(VARATT_IS_COMPRESSED(datum));
	rawsize = TOAST_COMPRESS_RAWSIZE(datum);
	if (rawsize + VARHDRSZ > buflen)
		return false;
	SET_VARSIZE(buffer, rawsize + VARHDRSZ);
	if (pglz_decompress(TOAST_COMPRESS_RAWDATA(datum),
						VARSIZE(datum) - TOAST_COMPRESS_HDRSZ,
						buffer + VARHDRSZ,
						rawsize) < 0)
	{
		printf("GPU kernel: compressed varlena datum is corrupted\n");
		return false;
	}
	return true;
}

/*
 * kern_get_datum_xxx
 *
 * Reference to a particular datum on the supplied kernel data store.
 * It returns NULL, if it is a really null-value in context of SQL,
 * or in case when out of range with error code
 *
 * NOTE: We are paranoia for validation of the data being fetched from
 * the kern_data_store in row-format because we may see a phantom page
 * if the source transaction that required this kernel execution was
 * aborted during execution.
 * Once a transaction gets aborted, shared buffers being pinned are
 * released, even if DMA send request on the buffers are already
 * enqueued. In this case, the calculation result shall be discarded,
 * so no need to worry about correctness of the calculation, however,
 * needs to be care about address of the variables being referenced.
 */
DEVICE_FUNCTION(void *)
kern_get_datum_tuple(kern_colmeta *colmeta,
					 HeapTupleHeaderData *htup,
					 cl_uint colidx)
{
	cl_bool		heap_hasnull = ((htup->t_infomask & HEAP_HASNULL) != 0);
	cl_uint		offset = htup->t_hoff;
	cl_uint		i, ncols = (htup->t_infomask2 & HEAP_NATTS_MASK);

	/* shortcut if colidx is obviously out of range */
	if (colidx >= ncols)
		return NULL;
	/* shortcut if tuple contains no NULL values */
	if (!heap_hasnull)
	{
		kern_colmeta   *cmeta = &colmeta[colidx];

		if (cmeta->attcacheoff >= 0)
			return (char *)htup + cmeta->attcacheoff;
	}
	/* regular path that walks on heap-tuple from the head */
	for (i=0; i < ncols; i++)
	{
		if (heap_hasnull && att_isnull(i, htup->t_bits))
		{
			if (i == colidx)
				return NULL;
		}
		else
		{
			kern_colmeta   *cmeta = &colmeta[i];
			char		   *addr;

			if (cmeta->attlen > 0)
				offset = TYPEALIGN(cmeta->attalign, offset);
			else if (!VARATT_NOT_PAD_BYTE((char *)htup + offset))
				offset = TYPEALIGN(cmeta->attalign, offset);

			/* TODO: overrun checks here */
			addr = ((char *) htup + offset);
			if (i == colidx)
				return addr;
			if (cmeta->attlen > 0)
				offset += cmeta->attlen;
			else
				offset += VARSIZE_ANY(addr);
		}
	}
	return NULL;
}

/*
 * kern_get_datum_column - datum referer to KDS_FORMAT_COLUMN
 */
DEVICE_FUNCTION(void *)
kern_get_datum_column(kern_data_store *kds,
					  kern_data_extra *extra,
					  cl_uint colidx, cl_uint rowidx)
{
	kern_colmeta   *cmeta = &kds->colmeta[colidx];
	char		   *addr;

	if (rowidx >= kds->nitems)
		return NULL;	/* out of range */
	if (cmeta->nullmap_offset != 0)
	{
		cl_uint	   *nullmap = (cl_uint *)
			((char *)kds + __kds_unpack(cmeta->nullmap_offset));
		if ((nullmap[rowidx>>5] & (1U << (rowidx & 0x1f))) == 0)
			return NULL;
	}

	addr = (char *)kds + __kds_unpack(cmeta->values_offset);
	if (cmeta->attlen > 0)
	{
		addr += TYPEALIGN(cmeta->attalign,
						  cmeta->attlen) * rowidx;
		return addr;
	}
	else if (cmeta->attlen == -1)
	{
		assert(extra != NULL);
		return (char *)extra + __kds_unpack(((cl_uint *)addr)[rowidx]);
	}
	return NULL;
}

DEVICE_FUNCTION(cl_bool)
kern_check_visibility_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowidx,
							 GstoreFdwSysattr *p_sysattr)
{
	kern_parambuf  *kparams = kcxt->kparams;
	xidvector	   *xvec = (xidvector *)
		kparam_get_value(kparams, kparams->xactIdVector);
	GstoreFdwSysattr *sysattr = (GstoreFdwSysattr *)
		kern_get_datum_column(kds, NULL, kds->ncols-1, rowidx);

	assert(xvec != NULL);
	assert(sysattr != NULL);
	if (p_sysattr != NULL)
		memcpy(p_sysattr, sysattr, sizeof(GstoreFdwSysattr));
	if (sysattr->xmin == InvalidTransactionId)
		return false;
	if (sysattr->xmin != FrozenTransactionId)
	{
		for (int i=0; i < xvec->dim1; i++)
		{
			if (sysattr->xmin == xvec->values[i])
				goto xmin_is_visible;
		}
		return false;
	}
xmin_is_visible:
	if (sysattr->xmax == InvalidTransactionId)
		return true;
	if (sysattr->xmax == FrozenTransactionId)
		return false;
	for (int i=0; i < xvec->dim1; i++)
	{
		if (sysattr->xmax == xvec->values[i])
			return false;
	}
	return true;
}

/*
 * Routines to reference values on KDS_FORMAT_ARROW for base types.
 * Usually, these routines are referenced via pg_datum_ref_arrow().
 */
DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_bool_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_uchar	   *bitmap;
	cl_uchar		mask = (1 << (rowidx & 7));

	bitmap = (cl_uchar *)
		kern_fetch_simple_datum_arrow(cmeta,
									  base,
									  rowidx>>3,
									  sizeof(cl_uchar));
	if (!bitmap)
		result.isnull = true;
	else
	{
		result.isnull = false;
		result.value  = ((*bitmap & mask) ? true : false);
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_date_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	void	   *addr;

	switch (cmeta->attopts.date.unit)
	{
		case ArrowDateUnit__Day:
			addr = kern_fetch_simple_datum_arrow(cmeta,
												 base,
												 rowidx,
												 sizeof(cl_uint));
			if (!addr)
				result.isnull = true;
			else
			{
				result.isnull = false;
				result.value = *((cl_uint *)addr)
					- (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
			}
			break;
		case ArrowDateUnit__MilliSecond:
			addr = kern_fetch_simple_datum_arrow(cmeta,
												 base,
												 rowidx,
												 sizeof(cl_ulong));
			if (!addr)
				result.isnull = true;
			else
			{
				result.isnull = false;
				result.value = *((cl_ulong *)addr) / 1000
					- (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
			}
			break;
		default:
			result.isnull = true;
			STROM_EREPORT(kcxt, ERRCODE_DATA_CORRUPTED,
						  "corrupted unit-size of Arrow::Date");
			return;
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_time_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_ulong	   *aval = (cl_ulong *)
		kern_fetch_simple_datum_arrow(cmeta,
									  base,
									  rowidx,
									  sizeof(cl_ulong));
	if (!aval)
		result.isnull = true;
	else
	{
		switch (cmeta->attopts.time.unit)
		{
			case ArrowTimeUnit__Second:
				result.isnull = false;
				result.value = *aval * 1000000L;
				break;
			case ArrowTimeUnit__MilliSecond:
				result.isnull = false;
				result.value = *aval * 1000L;
				break;
			case ArrowTimeUnit__MicroSecond:
				result.isnull = false;
				result.value = *aval;
				break;
			case ArrowTimeUnit__NanoSecond:
				result.isnull = false;
				result.value = *aval / 1000L;
				break;
			default:
				result.isnull = true;
				STROM_EREPORT(kcxt, ERRCODE_DATA_CORRUPTED,
							  "corrupted unit-size of Arrow::Time");
				return;
		}
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_timestamp_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_ulong	   *aval = (cl_ulong *)
		kern_fetch_simple_datum_arrow(cmeta,
									  base,
									  rowidx,
									  sizeof(cl_ulong));
	if (!aval)
		result.isnull = true;
	else
	{
		switch (cmeta->attopts.time.unit)
		{
			case ArrowTimeUnit__Second:
				result.isnull = false;
				result.value = *aval * 1000000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__MilliSecond:
				result.isnull = false;
				result.value = *aval * 1000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__MicroSecond:
				result.isnull = false;
				result.value = *aval -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__NanoSecond:
				result.isnull = false;
				result.value = *aval / 1000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			default:
				result.isnull = true;
				STROM_EREPORT(kcxt, ERRCODE_DATA_CORRUPTED,
							  "corrupted unit-size of Arrow::Timestamp");
				return;
		}
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_timestamptz_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_ulong	   *aval = (cl_ulong *)
		kern_fetch_simple_datum_arrow(cmeta,
									  base,
									  rowidx,
									  sizeof(cl_ulong));
	if (!aval)
		result.isnull = true;
	else
	{
		switch (cmeta->attopts.time.unit)
		{
			case ArrowTimeUnit__Second:
				result.isnull = false;
				result.value = *aval * 1000000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__MilliSecond:
				result.isnull = false;
				result.value = *aval * 1000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__MicroSecond:
				result.isnull = false;
				result.value = *aval -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			case ArrowTimeUnit__NanoSecond:
				result.isnull = false;
				result.value = *aval / 1000L -
					(POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * USECS_PER_DAY;
				break;
			default:
				result.isnull = true;
				STROM_EREPORT(kcxt, ERRCODE_DATA_CORRUPTED,
							  "corrupted unit-size of Arrow::Timestamp");
				return;
		}
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_interval_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_uint		   *ival;

	switch (cmeta->attopts.interval.unit)
	{
		case ArrowIntervalUnit__Year_Month:
			ival = (cl_uint *)
				kern_fetch_simple_datum_arrow(cmeta,
											  base,
											  rowidx,
											  sizeof(cl_uint));
			result.value.month = *ival;
			result.value.day = 0;
			result.value.month = 0;
			result.isnull = false;
			break;

		case ArrowIntervalUnit__Day_Time:
			ival = (cl_uint *)
				kern_fetch_simple_datum_arrow(cmeta,
											  base,
											  rowidx,
											  2 * sizeof(cl_uint));
			result.value.month = 0;
			result.value.day  = ival[0];
			result.value.time = ival[1];
			result.isnull = false;
			break;

		default:
			result.isnull = true;
			STROM_EREPORT(kcxt, ERRCODE_DATA_CORRUPTED,
						  "corrupted unit-size of Arrow::Interval");
			break;
	}
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_bpchar_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	cl_int			unitsz = cmeta->atttypmod - VARHDRSZ;
	char		   *addr, *pos;

	if (unitsz <= 0)
		addr = NULL;
	else
		addr = (char *)kern_fetch_simple_datum_arrow(cmeta,
													 base,
													 rowidx,
													 unitsz);
	if (!addr)
		result.isnull = true;
	else
	{
		pos = addr + unitsz;
		while (pos > addr && pos[-1] == ' ')
			pos--;
		result.isnull = false;
		result.value  = addr;
		result.length = pos - addr;
	}
}

/*
 * Hash-functions for base types
 */
DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_int2_t datum)
{
	cl_int		ival;

	if (datum.isnull)
		return 0;
	ival = (cl_int)datum.value;
	return pg_hash_any((cl_uchar *)&ival, sizeof(cl_int));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_int4_t datum)
{
	if (datum.isnull)
		return 0;
	return pg_hash_any((cl_uchar *)&datum.value, sizeof(cl_int));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_int8_t datum)
{
	cl_uint		hi, lo;

	if (datum.isnull)
		return 0;
	/* see hashint8, for cross-type hash joins */
	lo = (cl_uint)(datum.value & 0xffffffffL);
	hi = (cl_uint)(datum.value >> 32);
	lo ^= (datum.value >= 0 ? hi : ~hi);
	return pg_hash_any((cl_uchar *)&lo, sizeof(cl_int));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_float2_t datum)
{
	cl_double	fval;

	/* see comments at hashfloat4() */
	if (datum.isnull)
		return 0;
	fval = datum.value;
	if (fval == 0.0)
		return 0;
	return pg_hash_any((cl_uchar *)&fval, sizeof(cl_double));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_float4_t datum)
{
	cl_double	fval;

	/* see comments at hashfloat4() */
	if (datum.isnull || datum.value == 0.0)
		return 0;
	fval = datum.value;
	return pg_hash_any((cl_uchar *)&fval, sizeof(cl_double));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_float8_t datum)
{
	/* see comments at hashfloat8() */
	if (datum.isnull || datum.value == 0.0)
		return 0;
	return pg_hash_any((cl_uchar *)&datum.value, sizeof(cl_double));
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_bpchar_t datum)
{
	cl_int		len;

	if (datum.isnull)
		return 0;
	if (datum.length >= 0)
		return pg_hash_any((cl_uchar *)datum.value, datum.length);
	if (VARATT_IS_COMPRESSED(datum.value) ||
		VARATT_IS_EXTERNAL(datum.value))
	{
		STROM_CPU_FALLBACK(kcxt, ERRCODE_STROM_VARLENA_UNSUPPORTED,
						   "varlena datum is compressed or external");
		return 0;
	}
	len = bpchar_truelen(VARDATA_ANY(datum.value),
						 VARSIZE_ANY_EXHDR(datum.value));
	return pg_hash_any((cl_uchar *)VARDATA_ANY(datum.value), len);
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_interval_t datum)
{
	cl_long		days, frac;

	if (datum.isnull)
		return 0;
	interval_cmp_value(datum.value, &days, &frac);
	days ^= frac;
	return pg_hash_any((cl_uchar *)&days, sizeof(cl_long));
}

/*
 * for DATUM_CLASS__VARLENA handler
 *
 * If dclass == DATUM_CLASS__VARLENA, value is a pointer to pg_varlena_t; that
 * is binary compatible to other base variable-length types (pg_text_t,
 * pg_bytea_t, pg_bpchar_t). Unlike varlena of PostgreSQL
 */
DEVICE_FUNCTION(cl_uint)
pg_varlena_datum_length(kern_context *kcxt, Datum datum)
{
	pg_varlena_t   *vl = (pg_varlena_t *) datum;

	if (vl->length < 0)
		return VARSIZE_ANY(vl->value);
	return VARHDRSZ + vl->length;
}

DEVICE_FUNCTION(cl_uint)
pg_varlena_datum_write(kern_context *kcxt, char *dest, Datum datum)
{
	pg_varlena_t   *vl = (pg_varlena_t *) datum;
	cl_uint			vl_len;

	if (vl->length < 0)
	{
		vl_len = VARSIZE_ANY(vl->value);
		memcpy(dest, vl->value, vl_len);
	}
	else
	{
		vl_len = VARHDRSZ + vl->length;
		memcpy(dest + VARHDRSZ, vl->value, vl->length);
		SET_VARSIZE(dest, vl_len);
	}
	return vl_len;
}

/*
 * DATUM_CLASS_ARRAY handler
 *
 * If dclass == DATUM_CLASS_ARRAY, value is a pointer to pg_array_t that
 * is likely a reference to Arrow::List values, assumed to 1-dimensional
 * array in PostgreSQL.
 */

/*
 * pg_array_t handlers (not suitable for template)
 */
DEVICE_FUNCTION(pg_array_t)
pg_array_datum_ref(kern_context *kcxt, void *addr)
{
	pg_array_t	result;

	if (!addr)
		result.isnull = true;
	else
	{
		result.value  = (char *)addr;
		result.isnull = false;
		result.length = -1;
		result.start  = -1;
		result.smeta  = NULL;
	}
	return result;
}

DEVICE_FUNCTION(void)
pg_datum_ref(kern_context *kcxt,
			 pg_array_t &result, void *addr)
{
	result = pg_array_datum_ref(kcxt, addr);
}

DEVICE_FUNCTION(void)
pg_datum_ref_slot(kern_context *kcxt,
				  pg_array_t &result,
				  cl_char dclass, Datum datum)
{
	if (dclass == DATUM_CLASS__NULL)
		result = pg_array_datum_ref(kcxt, NULL);
	else if (dclass == DATUM_CLASS__ARRAY)
		memcpy(&result, DatumGetPointer(datum), sizeof(pg_array_t));
	else
	{
		assert(dclass == DATUM_CLASS__NORMAL);
		result = pg_array_datum_ref(kcxt, (char *)datum);
	}
}

DEVICE_FUNCTION(cl_int)
pg_datum_store(kern_context *kcxt,
			   pg_array_t datum,
			   cl_char &dclass,
			   Datum &value)
{
	if (datum.isnull)
		dclass = DATUM_CLASS__NULL;
	else if (datum.length < 0)
	{
		cl_uint		len = VARSIZE_ANY(datum.value);

		dclass = DATUM_CLASS__NORMAL;
		value  = PointerGetDatum(datum.value);
		if (PTR_ON_VLBUF(kcxt, datum.value, len))
			return len;
	}
	else
	{
		pg_array_t *temp;

		temp = (pg_array_t *)
			kern_context_alloc(kcxt, sizeof(pg_array_t));
		if (temp)
		{
			memcpy(temp, &datum, sizeof(pg_array_t));
			dclass = DATUM_CLASS__ARRAY;
			value  = PointerGetDatum(temp);
			return sizeof(pg_array_t);
		}
		STROM_EREPORT(kcxt, ERRCODE_OUT_OF_MEMORY,
					  "out of memory");
		dclass = DATUM_CLASS__NULL;
	}
	return 0;
}

DEVICE_FUNCTION(pg_array_t)
pg_array_param(kern_context *kcxt, cl_uint param_id)
{
	kern_parambuf  *kparams = kcxt->kparams;
	pg_array_t		result;

	if (param_id < kparams->nparams &&
		kparams->poffset[param_id] > 0)
	{
		char   *addr = (char *)kparams + kparams->poffset[param_id];

		if (VARATT_IS_4B_U(addr) || VARATT_IS_1B(addr))
			result = pg_array_datum_ref(kcxt, addr);
		else
		{
			result.isnull = true;
			STROM_CPU_FALLBACK(kcxt, ERRCODE_STROM_VARLENA_UNSUPPORTED,
							   "varlena datum is compressed or external");
		}
	}
	else
	{
		result.isnull = true;
	}
	return result;
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_array_t datum)
{
	/* we don't support to use pg_array_t for JOIN/GROUP BY key */
	STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,
				  "wrong code generation");
	return 0;
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_array_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	kern_data_store *kds = (kern_data_store *)base;
	kern_colmeta   *smeta;
	cl_uint		   *offset;

	assert(kds->format == KDS_FORMAT_ARROW);
	assert(cmeta->num_subattrs == 1 &&
		   cmeta->idx_subattrs < kds->nr_colmeta);
	assert(rowidx < kds->nitems);
	if (cmeta->nullmap_offset != 0)
	{
		cl_char	   *nullmap =
			(char *)kds + __kds_unpack(cmeta->nullmap_offset);
		if (att_isnull(rowidx, nullmap))
		{
			result.isnull = true;
			return;
		}
	}
	smeta = &kds->colmeta[cmeta->idx_subattrs];
	offset = (cl_uint *)((char *)kds + __kds_unpack(cmeta->values_offset));
	assert(offset[rowidx] <= offset[rowidx+1]);

	result.value  = base;
	result.isnull = false;
	result.length = (offset[rowidx+1] - offset[rowidx]);
	result.start  = offset[rowidx];
	result.smeta  = smeta;
}

/*
 * Template to generate pg_array_t from Apache Arrow store
 */
#define STROMCL_SIMPLE_PGARRAY_TEMPLATE(NAME)				\
	STATIC_INLINE(cl_uint)									\
	pg_##NAME##_array_from_arrow(kern_context *kcxt,		\
								 char *dest,				\
								 kern_colmeta *cmeta,		\
								 char *base,				\
								 cl_uint start,				\
								 cl_uint end)				\
	{														\
		return pg_simple_array_from_arrow<pg_##NAME##_t>	\
					(kcxt, dest, cmeta, base, start, end);	\
	}

#define STROMCL_VARLENA_PGARRAY_TEMPLATE(NAME)				\
	STATIC_INLINE(cl_uint)									\
	pg_##NAME##_array_from_arrow(kern_context *kcxt,		\
								 char *dest,				\
								 kern_colmeta *cmeta,		\
								 char *base,				\
								 cl_uint start,				\
								 cl_uint end)				\
	{														\
		return pg_varlena_array_from_arrow<pg_##NAME##_t>	\
					(kcxt, dest, cmeta, base, start, end);	\
	}

#define STROMCL_EXTERNAL_PGARRAY_TEMPLATE(NAME)				\
	DEVICE_FUNCTION(cl_uint)								\
	pg_##NAME##_array_from_arrow(kern_context *kcxt,		\
								 char *dest,				\
								 kern_colmeta *cmeta,		\
								 char *base,				\
								 cl_uint start,				\
                                 cl_uint end);

template <typename T>
STATIC_FUNCTION(cl_uint)
pg_simple_array_from_arrow(kern_context *kcxt,
						   char *dest,
						   kern_colmeta *cmeta,
						   char *base,
						   cl_uint start, cl_uint end)
{
	ArrayType  *res = (ArrayType *)dest;
	cl_uint		nitems = end - start;
	cl_uint		i, sz;
	char	   *nullmap = NULL;
	T			temp;

	Assert((cl_ulong)res == MAXALIGN(res));
	Assert(start <= end);
	if (cmeta->nullmap_offset == 0)
		sz = ARR_OVERHEAD_NONULLS(1);
	else
		sz = ARR_OVERHEAD_WITHNULLS(1, nitems);

	if (res)
	{
		res->ndim = 1;
		res->dataoffset = (cmeta->nullmap_offset == 0 ? 0 : sz);
		res->elemtype = cmeta->atttypid;
		ARR_DIMS(res)[0] = nitems;
		ARR_LBOUND(res)[0] = 1;

		nullmap = ARR_NULLBITMAP(res);
	}

	for (i=0; i < nitems; i++)
	{
		pg_datum_fetch_arrow(kcxt, temp, cmeta, base, start+i);
		if (temp.isnull)
		{
			if (nullmap)
				nullmap[i>>3] &= ~(1<<(i&7));
			else
				Assert(!dest);
		}
		else
		{
			if (nullmap)
				nullmap[i>>3] |= (1<<(i&7));
			sz = TYPEALIGN(cmeta->attalign, sz);
			if (dest)
				memcpy(dest+sz, &temp.value, sizeof(temp.value));
			sz += sizeof(temp.value);
		}
	}
	return sz;
}

template <typename T>
STATIC_INLINE(cl_uint)
pg_varlena_array_from_arrow(kern_context *kcxt,
							char *dest,
							kern_colmeta *cmeta,
							char *base,
							cl_uint start, cl_uint end)
{
	ArrayType  *res = (ArrayType *)dest;
	cl_uint		nitems = end - start;
	cl_uint		i, sz;
	char	   *nullmap = NULL;
	T			temp;

	Assert((cl_ulong)res == MAXALIGN(res));
	Assert(start <= end);
	if (cmeta->nullmap_offset == 0)
		sz = ARR_OVERHEAD_NONULLS(1);
	else
		sz = ARR_OVERHEAD_WITHNULLS(1, nitems);

	if (res)
	{
		res->ndim = 1;
		res->dataoffset = (cmeta->nullmap_offset == 0 ? 0 : sz);
		res->elemtype = cmeta->atttypid;
		ARR_DIMS(res)[0] = nitems;
		ARR_LBOUND(res)[0] = 1;

		nullmap = ARR_NULLBITMAP(res);
	}

	for (i=0; i < nitems; i++)
	{
		pg_datum_fetch_arrow(kcxt, temp, cmeta, base, start+i);
		if (temp.isnull)
		{
			if (nullmap)
				nullmap[i>>3] &= ~(1<<(i&7));
			else
				Assert(!dest);
		}
		else
		{
			if (nullmap)
				nullmap[i>>3] |= (1<<(i&7));

			sz = TYPEALIGN(cmeta->attalign, sz);
			if (temp.length < 0)
			{
				cl_uint		vl_len = VARSIZE_ANY(temp.value);

				if (dest)
					memcpy(dest + sz, DatumGetPointer(temp.value), vl_len);
				sz += vl_len;
			}
			else
			{
				if (dest)
				{
					memcpy(dest + sz + VARHDRSZ, temp.value, temp.length);
					SET_VARSIZE(dest + sz, VARHDRSZ + temp.length);
				}
				sz += VARHDRSZ + temp.length;
			}
		}
	}
	return sz;
}

STROMCL_SIMPLE_PGARRAY_TEMPLATE(bool)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(int2)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(int4)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(int8)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(float2)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(float4)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(float8)
STROMCL_EXTERNAL_PGARRAY_TEMPLATE(numeric)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(date)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(time)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(timestamp)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(timestamptz)
STROMCL_SIMPLE_PGARRAY_TEMPLATE(interval)
STROMCL_VARLENA_PGARRAY_TEMPLATE(bytea)
STROMCL_VARLENA_PGARRAY_TEMPLATE(text)
STROMCL_VARLENA_PGARRAY_TEMPLATE(bpchar)

/*
 * functions to write out Arrow::List<T> as an array of PostgreSQL
 *
 * only called if dclass == DATUM_CLASS__ARRAY
 */
STATIC_FUNCTION(cl_uint)
__pg_array_from_arrow(kern_context *kcxt, char *dest, Datum datum)
{
	pg_array_t	   *array = (pg_array_t *)DatumGetPointer(datum);
	kern_colmeta   *smeta = array->smeta;
	char		   *base  = array->value;
	cl_uint			start = array->start;
	cl_uint			end   = array->start + array->length;
	cl_uint			sz;

	assert(!array->isnull && array->length >= 0);
	assert(start <= end);
	switch (smeta->atttypid)
	{
		case PG_BOOLOID:
			sz = pg_bool_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_INT2OID:
			sz = pg_int2_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_INT4OID:
			sz = pg_int4_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_INT8OID:
			sz = pg_int8_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_FLOAT2OID:
			sz = pg_float2_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_FLOAT4OID:
			sz = pg_float4_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_FLOAT8OID:
			sz = pg_float8_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_NUMERICOID:
			sz = pg_numeric_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_DATEOID:
			sz = pg_date_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_TIMEOID:
			sz = pg_time_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_TIMESTAMPOID:
			sz = pg_timestamp_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_TIMESTAMPTZOID:
			sz = pg_timestamptz_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_INTERVALOID:
			sz = pg_interval_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_BPCHAROID:
			sz = pg_bpchar_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_TEXTOID:
		case PG_VARCHAROID:
			sz = pg_text_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		case PG_BYTEAOID:
			sz = pg_bytea_array_from_arrow(kcxt,dest,smeta,base,start,end);
			break;
		default:
			STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,
						  "wrong code generation");
			return 0;
	}
	return sz;
}

DEVICE_FUNCTION(cl_uint)
pg_array_datum_length(kern_context *kcxt, Datum datum)
{
    return __pg_array_from_arrow(kcxt, NULL, datum);
}

DEVICE_FUNCTION(cl_uint)
pg_array_datum_write(kern_context *kcxt, char *dest, Datum datum)
{
    return __pg_array_from_arrow(kcxt, dest, datum);
}

/*
 * pg_composite_t handlers (not suitable for template)
 */
DEVICE_FUNCTION(pg_composite_t)
pg_composite_datum_ref(kern_context *kcxt, void *addr)
{
	pg_composite_t	result;

	if (!addr)
		result.isnull = true;
	else
	{
		HeapTupleHeaderData *htup = (HeapTupleHeaderData *)addr;
		result.value  = (char *)htup;
		result.isnull = false;
		result.length = -1;
		result.rowidx = -1;
		result.comp_typid = __Fetch(&htup->t_choice.t_datum.datum_typeid);
		result.comp_typmod = __Fetch(&htup->t_choice.t_datum.datum_typmod);
		result.smeta  = NULL;
	}
	return result;
}

DEVICE_FUNCTION(void)
pg_datum_ref(kern_context *kcxt,
			 pg_composite_t &result, void *addr)
{
	result = pg_composite_datum_ref(kcxt, addr);
}

DEVICE_FUNCTION(void)
pg_datum_ref_slot(kern_context *kcxt,
				  pg_composite_t &result,
				  cl_char dclass, Datum datum)
{
	if (dclass == DATUM_CLASS__NULL)
		result = pg_composite_datum_ref(kcxt, NULL);
	else if (dclass == DATUM_CLASS__COMPOSITE)
		memcpy(&result, DatumGetPointer(datum), sizeof(pg_composite_t));
	else
	{
		assert(dclass == DATUM_CLASS__NORMAL);
		result = pg_composite_datum_ref(kcxt, DatumGetPointer(datum));
	}
}

DEVICE_FUNCTION(cl_int)
pg_datum_store(kern_context *kcxt,
               pg_composite_t datum,
               cl_char &dclass,
               Datum &value)
{
	if (datum.isnull)
		dclass = DATUM_CLASS__NULL;
	else if (datum.length < 0)
	{
		cl_uint		len = VARSIZE_ANY(datum.value);

		dclass = DATUM_CLASS__NORMAL;
		value  = PointerGetDatum(datum.value);
		if (PTR_ON_VLBUF(kcxt, datum.value, len))
			return len;
	}
	else
	{
		pg_composite_t *temp;

		temp = (pg_composite_t *)
			kern_context_alloc(kcxt, sizeof(pg_composite_t));
		if (temp)
		{
			memcpy(temp, &datum, sizeof(pg_composite_t));
			dclass = DATUM_CLASS__COMPOSITE;
			value  = PointerGetDatum(temp);
			return sizeof(pg_composite_t);
		}
		dclass = DATUM_CLASS__NULL;
		STROM_CPU_FALLBACK(kcxt, ERRCODE_OUT_OF_MEMORY,
						   "out of memory");
	}
	return 0;
}

DEVICE_FUNCTION(pg_composite_t)
pg_composite_param(kern_context *kcxt, cl_uint param_id)
{
	kern_parambuf  *kparams = kcxt->kparams;
	pg_composite_t	result;

	if (param_id < kparams->nparams &&
		kparams->poffset[param_id] > 0)
	{
		char   *addr = (char *)kparams + kparams->poffset[param_id];

		if (VARATT_IS_4B_U(addr) || VARATT_IS_1B(addr))
			result = pg_composite_datum_ref(kcxt, addr);
		else
		{
			result.isnull = true;
			STROM_CPU_FALLBACK(kcxt, ERRCODE_STROM_VARLENA_UNSUPPORTED,
							   "varlena datum is compressed or external");
		}
	}
	else
	{
		result.isnull = true;
	}
	return result;
}

DEVICE_FUNCTION(cl_uint)
pg_comp_hash(kern_context *kcxt, pg_composite_t datum)
{
	/* we don't support to use pg_composite_t for JOIN/GROUP BY key */
	STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,
				  "wrong code generation");
	return 0;
}

DEVICE_FUNCTION(void)
pg_datum_fetch_arrow(kern_context *kcxt,
					 pg_composite_t &result,
					 kern_colmeta *cmeta,
					 char *base, cl_uint rowidx)
{
	kern_data_store *kds = (kern_data_store *)base;

	assert(kds->format == KDS_FORMAT_ARROW);
	assert(rowidx < kds->nitems);
	assert(cmeta->idx_subattrs + cmeta->num_subattrs <= kds->nr_colmeta);
	if (cmeta->nullmap_offset != 0)
	{
		cl_char	   *nullmap =
			(char *)kds + __kds_unpack(cmeta->nullmap_offset);
		if (att_isnull(rowidx, nullmap))
		{
			result.isnull = true;
			return;
		}
	}
	result.value  = base;
	result.isnull = false;
	result.length = cmeta->num_subattrs;
	result.rowidx = rowidx;
	result.comp_typid = cmeta->atttypid;
	result.comp_typmod = cmeta->atttypmod;
	result.smeta  = &kds->colmeta[cmeta->idx_subattrs];
}

/*
 * for DATUM_CLASS_COMPOSITE handler
 *
 * A functions to write out Arrow::Struct as a composite datum of PostgreSQL
 * only called if dclass == DATUM_CLASS__COMPOSITE
 */
STATIC_FUNCTION(void)
__pg_composite_from_arrow(kern_context *kcxt,
						  pg_composite_t *comp,
						  cl_char *tup_dclass,
						  Datum *tup_values)
{
	char	   *base = comp->value;
	cl_uint		j, nfields = comp->length;
	cl_uint		rowidx = comp->rowidx;

	for (j=0; j < nfields; j++)
	{
		kern_colmeta   *smeta = comp->smeta + j;

		if (smeta->atttypkind == TYPE_KIND__COMPOSITE)
		{
			pg_composite_t	temp;

			pg_datum_fetch_arrow(kcxt, temp,
								 smeta, base, rowidx);
			pg_datum_store(kcxt, temp,
						   tup_dclass[j],
						   tup_values[j]);
		}
		else if (smeta->atttypkind == TYPE_KIND__ARRAY)
		{
			pg_array_t		temp;

			pg_datum_fetch_arrow(kcxt, temp,
								 smeta, base, rowidx);
			pg_datum_store(kcxt, temp,
						   tup_dclass[j],
						   tup_values[j]);
		}
		else if (smeta->atttypkind == TYPE_KIND__BASE)
		{
#define ELEMENT_ENTRY(NAME,PG_TYPEOID)							\
			case PG_TYPEOID:									\
			{													\
				pg_##NAME##_t	temp;							\
					pg_datum_fetch_arrow(kcxt, temp,			\
										 smeta, base, rowidx);	\
					pg_datum_store(kcxt, temp,					\
								   tup_dclass[j],				\
								   tup_values[j]);				\
			}													\
			break

			switch (smeta->atttypid)
			{
				ELEMENT_ENTRY(bool,PG_BOOLOID);
				ELEMENT_ENTRY(int2,PG_INT2OID);
				ELEMENT_ENTRY(int4,PG_INT4OID);
				ELEMENT_ENTRY(int8,PG_INT8OID);
				ELEMENT_ENTRY(float2,PG_FLOAT2OID);
				ELEMENT_ENTRY(float4,PG_FLOAT4OID);
				ELEMENT_ENTRY(float8,PG_FLOAT8OID);
				ELEMENT_ENTRY(numeric,PG_NUMERICOID);
				ELEMENT_ENTRY(date, PG_DATEOID);
				ELEMENT_ENTRY(time, PG_TIMEOID);
				ELEMENT_ENTRY(timestamp, PG_TIMESTAMPOID);
				ELEMENT_ENTRY(timestamptz, PG_TIMESTAMPTZOID);
				ELEMENT_ENTRY(interval, PG_INTERVALOID);
				ELEMENT_ENTRY(bpchar, PG_BPCHAROID);
				ELEMENT_ENTRY(text, PG_TEXTOID);
				ELEMENT_ENTRY(varchar, PG_VARCHAROID);
				ELEMENT_ENTRY(bytea, PG_BYTEAOID);
				default:
					STROM_EREPORT(kcxt, ERRCODE_INVALID_COLUMN_DEFINITION,
								  "unsupported type of sub-field");
					tup_dclass[j] = DATUM_CLASS__NULL;
			}
		}
	}
}
#undef ELEMENT_ENTRY

DEVICE_FUNCTION(cl_uint)
pg_composite_datum_length(kern_context *kcxt, Datum datum)
{
	pg_composite_t *comp = (pg_composite_t *)DatumGetPointer(datum);
	cl_uint		nfields = comp->length;
	cl_char	   *tup_dclass;
	Datum	   *tup_values;
	cl_char	   *vlpos_saved = kcxt->vlpos;
	cl_uint		sz;

	tup_dclass = (cl_char *)
		kern_context_alloc(kcxt, sizeof(cl_char) * nfields);
	tup_values = (Datum *)
		kern_context_alloc(kcxt, sizeof(Datum) * nfields);
	if (!tup_dclass || !tup_values)
	{
		STROM_CPU_FALLBACK(kcxt, ERRCODE_OUT_OF_MEMORY,
						   "out of memory");
		kcxt->vlpos = vlpos_saved;
		return 0;
	}
	__pg_composite_from_arrow(kcxt, comp, tup_dclass, tup_values);
	sz = __compute_heaptuple_size(kcxt,
								  comp->smeta,
								  false,
								  comp->length,
								  tup_dclass,
								  tup_values);
	kcxt->vlpos = vlpos_saved;
	return sz;
}

DEVICE_FUNCTION(cl_uint)
pg_composite_datum_write(kern_context *kcxt, char *dest, Datum datum)
{
	pg_composite_t *comp = (pg_composite_t *)DatumGetPointer(datum);
	cl_uint		nfields = comp->length;
	cl_char	   *tup_dclass;
	Datum	   *tup_values;
	cl_uint		sz;
	cl_char	   *vlpos_saved = kcxt->vlpos;

	tup_dclass = (cl_char *)
		kern_context_alloc(kcxt, sizeof(cl_char) * nfields);
	tup_values = (Datum *)
		kern_context_alloc(kcxt, sizeof(Datum) * nfields);
	if (!tup_dclass || !tup_values)
	{
		STROM_CPU_FALLBACK(kcxt, ERRCODE_OUT_OF_MEMORY,
						   "out of memory");
		kcxt->vlpos = vlpos_saved;
		return 0;
	}
	__pg_composite_from_arrow(kcxt, comp, tup_dclass, tup_values);
	sz = form_kern_composite_type(kcxt,
								  dest,
								  comp->comp_typid,
								  comp->comp_typmod,
								  comp->length,
								  comp->smeta,
								  tup_dclass,
								  tup_values);
	kcxt->vlpos = vlpos_saved;
	return sz;
}

/* ================================================================
 *
 * PotsGIS Support Routines
 *
 * ================================================================
 */
DEVICE_FUNCTION(cl_uint)
pg_geometry_datum_length(kern_context *kcxt, Datum datum)
{
	pg_geometry_t *geom = (pg_geometry_t *)DatumGetPointer(datum);
	size_t		sz = offsetof(GSERIALIZED, body.data);

	/*
	 * NOTE: We always use v1 format of GSERIALIZED, because v2 has
	 * no functional differences right now, and v1 is shorter than
	 * the v2 format, by 8 bytes for extra flags.
	 */
	if ((geom->flags & GEOM_FLAG__BBOX) != 0 && geom->bbox)
		sz += geometry_bbox_size(geom->flags);
	return sz + (sizeof(cl_uint) +	/* geometry type */
				 sizeof(cl_uint) + 	/* nitems of top-level items */
				 geom->rawsize);	/* payload of points/vertexes */
}

DEVICE_FUNCTION(cl_uint)
pg_geometry_datum_write(kern_context *kcxt, char *dest, Datum datum)
{
	pg_geometry_t *geom = (pg_geometry_t *)DatumGetPointer(datum);
	GSERIALIZED	   *gs = (GSERIALIZED *)dest;
	char		   *rawdata = gs->body.data;
	cl_uchar		gflags = G1FLAG_READONLY;
	cl_uint			sz;

	/* extract SRID */
	gs->body.srid[0] = (geom->srid & 0x001f0000) >> 16;
	gs->body.srid[1] = (geom->srid & 0x0000ff00) >>  8;
	gs->body.srid[2] = (geom->srid & 0x000000ff);

	/* extract flags */
	if ((geom->flags & GEOM_FLAG__Z) != 0)
		gflags |= G1FLAG_Z;
	if ((geom->flags & GEOM_FLAG__M) != 0)
		gflags |= G1FLAG_M;
	if ((geom->flags & GEOM_FLAG__BBOX) != 0 && geom->bbox)
		gflags |= G1FLAG_BBOX;
	if ((geom->flags & GEOM_FLAG__GEODETIC) != 0)
		gflags |= G1FLAG_GEODETIC;
	if ((geom->flags & GEOM_FLAG__SOLID) != 0)
		gflags |= G1FLAG_SOLID;
	gs->body.gflags = gflags;
	
	if ((gflags & G1FLAG_BBOX) != 0)
	{
		cl_uint		sz = geometry_bbox_size(geom->flags);

		memcpy(rawdata, geom->bbox, sz);
		rawdata += sz;
	}
	/* type and nitems */
	((cl_uint *)rawdata)[0] = geom->type;
	((cl_uint *)rawdata)[1] = geom->nitems;
	rawdata += 2 * sizeof(cl_uint);

	/* other payload */
	memcpy(rawdata, geom->rawdata, geom->rawsize);
	rawdata += geom->rawsize;

	sz = (rawdata - dest);
	SET_VARSIZE(gs, sz);

	return sz;
}
