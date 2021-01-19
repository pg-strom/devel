/*
 * cuda_utils.h
 *
 * Collection of CUDA inline functions for device code
 * --
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
#ifndef CUDA_UTILS_H
#define CUDA_UTILS_H
#ifdef __CUDACC__
/*
 * NumSmx - reference to the %nsmid register
 */
DEVICE_INLINE(cl_uint) NumSmx(void)
{
	cl_uint		ret;
	asm volatile("mov.u32 %0, %nsmid;" : "=r"(ret) );
	return ret;
}

/*
 * SmxId - reference to the %smid register
 */
DEVICE_INLINE(cl_uint) SmxId(void)
{
	cl_uint		ret;
	asm volatile("mov.u32 %0, %smid;" : "=r"(ret) );
	return ret;
}

/*
 * LaneId() - reference to the %laneid register
 */
DEVICE_INLINE(cl_uint) LaneId(void)
{
	cl_uint		ret;
	asm volatile("mov.u32 %0, %laneid;" : "=r"(ret) );
	return ret;
}

/*
 * TotalShmemSize() - reference to the %total_smem_size
 */
DEVICE_INLINE(cl_uint) TotalShmemSize(void)
{
	cl_uint		ret;
	asm volatile("mov.u32 %0, %total_smem_size;" : "=r"(ret) );
	return ret;
}

/*
 * DynamicShmemSize() - reference to the %dynamic_smem_size
 */
DEVICE_INLINE(cl_uint) DynamicShmemSize(void)
{
	cl_uint		ret;
	asm volatile("mov.u32 %0, %dynamic_smem_size;" : "=r"(ret) );
	return ret;
}

/*
 * GlobalTimer - A pre-defined, 64bit global nanosecond timer.
 *
 * NOTE: clock64() is not consistent across different SMX, thus, should not
 *       use this API in case when device time-run may reschedule the kernel.
 */
DEVICE_INLINE(cl_ulong) GlobalTimer(void)
{
	cl_ulong	ret;
	asm volatile("mov.u64 %0, %globaltimer;" : "=l"(ret) );
	return ret;
}

/* memory comparison */
DEVICE_INLINE(cl_int)
__memcmp(const void *s1, const void *s2, size_t n)
{
	const cl_uchar *p1 = (const cl_uchar *)s1;
	const cl_uchar *p2 = (const cl_uchar *)s2;

	while (n--)
	{
		if (*p1 != *p2)
			return ((int)*p1) - ((int)*p2);
		p1++;
		p2++;
	}
	return 0;
}

/* cstring comparison */
STATIC_INLINE(cl_int)
__strcmp(const char *__s1, const char *__s2)
{
	const cl_uchar *s1 = (const cl_uchar *) __s1;
	const cl_uchar *s2 = (const cl_uchar *) __s2;
	cl_int		c1, c2;

	do {
		c1 = (cl_uchar) *s1++;
		c2 = (cl_uchar) *s2++;

		if (c1 == '\0')
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}

STATIC_INLINE(cl_int)
__strncmp(const char *__s1, const char *__s2, cl_uint n)
{
	const cl_uchar *s1 = (const cl_uchar *) __s1;
	const cl_uchar *s2 = (const cl_uchar *) __s2;
	cl_int		c1 = '\0';
	cl_int		c2 = '\0';

	while (n > 0)
	{
		c1 = (cl_uchar) *s1++;
		c2 = (cl_uchar) *s2++;
		if (c1 == '\0' || c1 != c2)
			return c1 - c2;
		n--;
	}
	return c1 - c2;
}

/* swap values */
template <typename T>
STATIC_INLINE(void)
__swap(T &value_x, T &value_y)
{
	T	temp;

	temp = value_x;
	value_x = value_y;
	value_y = temp;
}

/*
 * pgstromTotalSum
 *
 * A utility routine to calculate total sum of the supplied array which are
 * consists of primitive types.
 * Unlike pgstromStairLikeSum, it accepts larger length of the array than
 * size of thread block, and unused threads shall be relaxed earlier.
 *
 * Restrictions:
 * - array must be a primitive types, like int, double.
 * - array must be on the shared memory.
 * - all the threads must call the function simultaneously.
 *   (Unacceptable to call the function in if-block)
 */
template <typename T>
DEVICE_INLINE(T)
pgstromTotalSum(T *values, cl_uint nitems)
{
	cl_uint		nsteps = get_next_log2(nitems);
	cl_uint		nthreads;
	cl_uint		step;
	cl_uint		loop;
	T			retval;

	if (nitems == 0)
		return (T)(0);
	__syncthreads();
	for (step=1; step <= nsteps; step++)
	{
		nthreads = ((nitems - 1) >> step) + 1;

		for (loop=get_local_id(); loop < nthreads; loop += get_local_size())
		{
			cl_uint		dst = (loop << step);
			cl_uint		src = dst + (1U << (step - 1));

			if (src < nitems)
				values[dst] += values[src];
		}
		__syncthreads();
	}
	retval = values[0];
	__syncthreads();

	return retval;
}

/*
 * Utility functions to reference system columns
 */
DEVICE_INLINE(cl_int)
pg_sysattr_ctid_store(kern_context *kcxt,
					  kern_data_store *kds,
					  HeapTupleHeaderData *htup,
					  ItemPointerData *t_self,
					  cl_char &dclass,
					  Datum   &value)
{
	void	   *temp;

	if (!t_self)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		if (kds && ((char *)t_self >= (char *)kds &&
					(char *)t_self <  (char *)kds + kds->length))
		{
			value = PointerGetDatum(t_self);
		}
		else
		{
			temp = kern_context_alloc(kcxt, sizeof(ItemPointerData));
			if (temp)
			{
				memcpy(temp, t_self, sizeof(ItemPointerData));
				value = PointerGetDatum(temp);
				return sizeof(ItemPointerData);
			}
			dclass = DATUM_CLASS__NULL;
			STROM_EREPORT(kcxt, ERRCODE_OUT_OF_MEMORY, "out of memory");
		}
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_oid_store(kern_context *kcxt,
					 kern_data_store *kds,
					 HeapTupleHeaderData *htup,
					 ItemPointerData *t_self,
					 cl_char &dclass,
					 Datum   &value)
{
	if (!htup)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		if ((htup->t_infomask & HEAP_HASOID) == 0)
			value = 0;
		else
			value = *((cl_uint *)((char *) htup
								  + htup->t_hoff
								  - sizeof(cl_uint)));
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmin_store(kern_context *kcxt,
					  kern_data_store *kds,
					  HeapTupleHeaderData *htup,
					  ItemPointerData *t_self,
					  cl_char &dclass,
					  Datum   &value)
{
	if (!htup)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = htup->t_choice.t_heap.t_xmin;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmin_store(kern_context *kcxt,
					  kern_data_store *kds,
					  HeapTupleHeaderData *htup,
					  ItemPointerData *t_self,
					  cl_char &dclass,
					  Datum   &value)
{
	if (!htup)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = htup->t_choice.t_heap.t_field3.t_cid;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmax_store(kern_context *kcxt,
					  kern_data_store *kds,
					  HeapTupleHeaderData *htup,
					  ItemPointerData *t_self,
					  cl_char &dclass,
					  Datum   &value)
{
	if (!htup)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = htup->t_choice.t_heap.t_xmax;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmax_store(kern_context *kcxt,
					  kern_data_store *kds,
					  HeapTupleHeaderData *htup,
					  ItemPointerData *t_self,
					  cl_char &dclass,
					  Datum   &value)
{
	if (!htup)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = htup->t_choice.t_heap.t_field3.t_cid;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_tableoid_store(kern_context *kcxt,
						  kern_data_store *kds,
						  HeapTupleHeaderData *htup,
						  ItemPointerData *t_self,
						  cl_char &dclass,
						  Datum   &value)
{
	if (!kds)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = kds->table_oid;
	}
	return 0;
}
/*
 * System attribute reference for Apache Arrow
 */
DEVICE_INLINE(cl_int)
pg_sysattr_ctid_fetch_arrow(kern_context *kcxt,
							kern_data_store *kds,
							cl_uint row_index,
							cl_char &dclass,
							Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_oid_fetch_arrow(kern_context *kcxt,
						   kern_data_store *kds,
                           cl_uint row_index,
                           cl_char &dclass,
                           Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmin_fetch_arrow(kern_context *kcxt,
							kern_data_store *kds,
							cl_uint row_index,
							cl_char &dclass,
							Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmax_fetch_arrow(kern_context *kcxt,
                            kern_data_store *kds,
                            cl_uint row_index,
                            cl_char &dclass,
                            Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmin_fetch_arrow(kern_context *kcxt,
							kern_data_store *kds,
							cl_uint row_index,
							cl_char &dclass,
							Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmax_fetch_arrow(kern_context *kcxt,
							kern_data_store *kds,
							cl_uint row_index,
							cl_char &dclass,
							Datum   &value)
{
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_tableoid_fetch_arrow(kern_context *kcxt,
								kern_data_store *kds,
								cl_uint row_index,
								cl_char &dclass,
								Datum   &value)
{
	if (!kds)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = (Datum)kds->table_oid;
	}
	return 0;
}

/*
 * System attribute reference for GPU memory Store
 */
#include "cuda_gstore.h"

/*
 * inline functions to form/deform HeapTuple
 */
DEVICE_INLINE(cl_uint)
compute_heaptuple_size(kern_context *kcxt,
					   kern_data_store *kds,
					   cl_char *tup_dclass,
					   Datum   *tup_values)
{
	return __compute_heaptuple_size(kcxt,
									kds->colmeta,
									kds->tdhasoid,
									kds->ncols,
									tup_dclass,
									tup_values);
}

/*
 * form_kern_heaptuple
 *
 * A utility routine to build a kern_tupitem on the destination buffer
 * already allocated.
 *
 * tupitem      ... kern_tupitem allocated on the kds
 * kds_dst      ... destination data store
 * tup_self     ... item pointer of the tuple, if any
 * htup         ... tuple-header of the original tuple, if any
 * tup_dclass   ... any of DATUM_CLASS__*
 * tup_values   ... array of values to be written
 */
DEVICE_INLINE(cl_uint)
form_kern_heaptuple(kern_context    *kcxt,
					kern_tupitem    *tupitem,		/* out */
					kern_data_store	*kds_dst,		/* in */
					ItemPointerData *tup_self,		/* in, optional */
					cl_char         *tup_dclass,	/* in */
					Datum           *tup_values)	/* in */
{
	assert((cl_ulong)tupitem == MAXALIGN(tupitem));
	assert((char *)tupitem >= (char *)kds_dst &&
		   (char *)tupitem <  (char *)kds_dst + kds_dst->length);
	tupitem->rowid = UINT_MAX;		/* caller should set */
	tupitem->t_len = __form_kern_heaptuple(kcxt,
										   &tupitem->htup,
										   kds_dst->ncols,
										   kds_dst->colmeta,
										   kds_dst->tdtypeid,
										   kds_dst->tdtypmod,
										   tup_self,
										   tup_dclass,
										   tup_values);
	return tupitem->t_len;
}

/*
 * form_kern_composite_type
 *
 * A utility routine to set up a composite type data structure
 * on the supplied pre-allocated region. It in
 *
 * @buffer     ... pointer to global memory where caller wants to construct
 *                 a composite datum. It must have enough length and also
 *                 must be aligned to DWORD.
 * @typeoid    ... type OID of the composite type 
 * @typemod    ... type modifier of the composite type
 * @nfields    ... number of sub-fields of the composite type
 * @colmeta    ... array of kern_colmeta for sub-field types
 * @tup_dclass ... any of DATUM_CLASS__*
 * @tup_values ... values of the sub-fields
 */
DEVICE_INLINE(cl_uint)
form_kern_composite_type(kern_context *kcxt,
						 void      *buffer,      /* out */
						 cl_uint    comp_typeid, /* in: type OID */
						 cl_int		comp_typmod, /* in: type modifier */
						 cl_int		nfields,     /* in: # of attributes */
						 kern_colmeta *colmeta,  /* in: sub-type attributes */
						 cl_char   *tup_dclass,  /* in: */
						 Datum	   *tup_values)	 /* in: */
{
	return __form_kern_heaptuple(kcxt,
								 buffer,
								 nfields,
								 colmeta,
								 comp_typeid,
								 comp_typmod,
								 NULL,
								 tup_dclass,
								 tup_values);
}

/*
 * A utility function to evaluate pg_bool_t value as if built-in
 * bool variable.
 */
DEVICE_INLINE(cl_bool)
EVAL(pg_bool_t arg)
{
	if (!arg.isnull && arg.value != 0)
		return true;
	return false;
}

DEVICE_INLINE(pg_bool_t)
NOT(pg_bool_t arg)
{
	arg.value = !arg.value;
	return arg;
}

DEVICE_INLINE(pg_bool_t)
PG_BOOL(cl_bool isnull, cl_bool value)
{
	pg_bool_t	res;
	res.isnull = isnull;
	res.value  = value;
	return res;
}

#define AND(temp,anynull,x,y)						\
	((temp) = (x), (anynull) |= (temp).isnull,		\
	 ((!(temp).isnull && !(temp).value) ? (temp) : (y)))
#define OR(temp,anynull,x,y)						\
	((temp) = (x), (anynull) |= (temp).isnull,		\
	 ((!(temp).isnull &&  (temp).value) ? (temp) : (y)))

/*
 * A simple wrapper for pgfn_type_compare
 */
template <typename T>
DEVICE_INLINE(cl_bool)
pgfn_type_equal(kern_context *kcxt, T arg1, T arg2)
{
	pg_int4_t	cmp = pgfn_type_compare(kcxt, arg1, arg2);

	if (!cmp.isnull && cmp.value == 0)
		return true;
	return false;
}

/*
 * Support routine for COALESCE / GREATEST / LEAST
 */
template <typename T>
DEVICE_INLINE(T)
PG_COALESCE(kern_context *kcxt, const T& arg)
{
	return arg;
}

template <typename T, typename ...R>
DEVICE_INLINE(T)
PG_COALESCE(kern_context *kcxt, const T& arg1, const R&... args_rest)
{
	if (!arg1.isnull)
		return arg1;
	return PG_COALESCE(kcxt, args_rest...);
}

template <typename T>
DEVICE_INLINE(T)
PG_GREATEST(kern_context *kcxt, const T& arg)
{
	return arg;
}

template <typename T, typename ...R>
DEVICE_INLINE(T)
PG_GREATEST(kern_context *kcxt, const T& arg1, const R&... args_rest)
{
	if (arg1.isnull)
		return PG_GREATEST(kcxt, args_rest...);
	else
	{
		T			arg2 = PG_GREATEST(kcxt, args_rest...);
		pg_int4_t	cmp;

		cmp = pgfn_type_compare(kcxt, arg1, arg2);
		if (cmp.isnull)
			return arg1;
		else if (cmp.value > 0)
			return arg1;
		else
			return arg2;
	}
}

template <typename T>
DEVICE_INLINE(T)
PG_LEAST(kern_context *kcxt, const T& arg)
{
	return arg;
}

template <typename T, typename... R>
DEVICE_INLINE(T)
PG_LEAST(kern_context *kcxt, const T& arg1, const R&... args_rest)
{
	if (arg1.isnull)
		return PG_LEAST(kcxt, args_rest...);
	else
	{
		T			arg2 = PG_LEAST(kcxt, args_rest...);
		pg_int4_t	cmp;

		cmp = pgfn_type_compare(kcxt, arg1, arg2);
		if (cmp.isnull)
			return arg1;
		else if (cmp.value > 0)
			return arg2;
		else
			return arg1;
	}
}

/*
 * Support routine for NullTest
 */
template <typename T>
DEVICE_INLINE(pg_bool_t)
PG_ISNULL(kern_context *kcxt, T arg)
{
	pg_bool_t	result;

	result.isnull = false;
	result.value = arg.isnull;

	return result;
}

template <typename T>
DEVICE_INLINE(pg_bool_t)
PG_ISNOTNULL(kern_context *kcxt, T arg)
{
	pg_bool_t	result;

	result.isnull = false;
	result.value = !arg.isnull;

	return result;
}

/*
 * Functions for BooleanTest
 */
DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_true(kern_context *kcxt, pg_bool_t result)
{
	result.value = (!result.isnull && result.value);
	result.isnull = false;
	return result;
}

DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_not_true(kern_context *kcxt, pg_bool_t result)
{
	result.value = (result.isnull || !result.value);
	result.isnull = false;
	return result;
}

DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_false(kern_context *kcxt, pg_bool_t result)
{
	result.value = (!result.isnull && !result.value);
	result.isnull = false;
	return result;
}

DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_not_false(kern_context *kcxt, pg_bool_t result)
{
	result.value = (result.isnull || result.value);
	result.isnull = false;
	return result;
}

DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_unknown(kern_context *kcxt, pg_bool_t result)
{
	result.value = result.isnull;
	result.isnull = false;
	return result;
}

DEVICE_INLINE(pg_bool_t)
pgfn_bool_is_not_unknown(kern_context *kcxt, pg_bool_t result)
{
	result.value = !result.isnull;
	result.isnull = false;
	return result;
}

/*
 * Support routine of ScalarArrayOpExpr
 */
DEVICE_INLINE(cl_int)
ArrayGetNItems(kern_context *kcxt, cl_int ndim, const cl_int *dims)
{
	cl_int		i, ret;
	cl_long		prod;

	if (ndim <= 0)
		return 0;

	ret = 1;
	for (i=0; i < ndim; i++)
	{
		cl_int		d = __Fetch(dims + i);

		if (d < 0)
		{
			/* negative dimension implies an error... */
			STROM_EREPORT(kcxt, ERRCODE_PROGRAM_LIMIT_EXCEEDED,
						  "array size exceeds the limit");
			return 0;
		}
		prod = (cl_long) ret * (cl_long) d;
		ret = (cl_int) prod;
		if ((cl_long) ret != prod)
		{
			/* array size exceeds the maximum allowed... */
			STROM_EREPORT(kcxt, ERRCODE_PROGRAM_LIMIT_EXCEEDED,
						  "array size exceeds the limit");
			return 0;
		}
	}
	assert(ret >= 0);

	return ret;
}

template <typename ScalarType, typename ElementType>
DEVICE_INLINE(pg_bool_t)
PG_SCALAR_ARRAY_OP(kern_context *kcxt,
				   pg_bool_t (*compare_fn)(kern_context *kcxt,
										   ScalarType scalar,
										   ElementType element),
				   ScalarType scalar,
				   pg_array_t array,
				   cl_bool useOr,	/* true = ANY, false = ALL */
				   cl_int typelen,
				   cl_int typealign)
{
	kern_colmeta *smeta = array.smeta;
	ElementType	element;
	pg_bool_t	result;
	pg_bool_t	rv;
	char	   *base;
	cl_uint		offset = 0;
	char	   *nullmap = NULL;
	int			nullmask = 1;
	cl_uint		i, nitems;

	/*
	 * MEMO: In case when we support a device type with non-strict comparison
	 * function, we need to extract the array loop towards NULL-input.
	 */
	if (array.isnull || scalar.isnull)
	{
		result.isnull = true;
		result.value = false;
		return result;
	}
	result.isnull = false;
    result.value = (useOr ? false : true);

	if (array.length < 0)
	{
		nitems = ArrayGetNItems(kcxt,
								ARR_NDIM(array.value),
								ARR_DIMS(array.value));
		base = ARR_DATA_PTR(array.value);
		nullmap = ARR_NULLBITMAP(array.value);
	}
	else
	{
		nitems = array.length;
		base = (char *)array.value;
		if (smeta->nullmap_offset != 0)
			nullmap = base + __kds_unpack(smeta->nullmap_offset);
	}
	if (nitems == 0)
		return result;

	for (i=0; i < nitems; i++)
	{
		if (nullmap && (*nullmap & nullmask) == 0)
			pg_datum_ref(kcxt, element, NULL);
		else if (array.length < 0)
		{
			/* PG Array */
			char   *pos = base + offset;

			pg_datum_ref(kcxt, element, pos);
			if (typelen > 0)
				offset = TYPEALIGN(typealign, offset + typelen);
			else if (typelen == -1)
				offset = TYPEALIGN(typealign, offset + VARSIZE_ANY(pos));
			else
			{
				STROM_EREPORT(kcxt, ERRCODE_WRONG_OBJECT_TYPE,
							  "unexpected type length");
				result.isnull = true;
				return result;
			}
		}
		else
		{
			/* Arrow::List */
			assert(i < array.length);
			pg_datum_fetch_arrow(kcxt, element, smeta, base, i);
		}
		/* call for the comparison function */
		rv = compare_fn(kcxt, scalar, element);
		if (rv.isnull)
			result.isnull = true;
		else if (useOr)
		{
			if (rv.value)
			{
				result.isnull = false;
				result.value = true;
				break;
			}
		}
		else
		{
			if (!rv.value)
			{
				result.isnull = false;
				result.value = false;
				break;
			}
		}
		/* advance nullmap pointer if any */
		if (nullmap)
		{
			nullmask <<= 1;
			if (nullmask == 0x0100)
			{
				nullmap++;
				nullmask = 1;
			}
		}
	}
	return result;
}
#endif  /* __CUDACC__ */
#endif  /* CUDA_UTILS_H */
