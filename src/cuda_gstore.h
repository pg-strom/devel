/*
 * cuda_gstore.h
 *
 * CUDA device code specific to GstoreFdw in-memory data store
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
#ifndef CUDA_GSTORE_H
#define CUDA_GSTORE_H

#define GSTORE_TX_LOG__MAGIC		0xEBAD7C00
#define GSTORE_TX_LOG__INSERT		(GSTORE_TX_LOG__MAGIC | 'I')
#define GSTORE_TX_LOG__DELETE		(GSTORE_TX_LOG__MAGIC | 'D')
#define GSTORE_TX_LOG__COMMIT		(GSTORE_TX_LOG__MAGIC | 'C')
#define GSTORE_TX_LOG__TERMINATOR	0xFBADBEEF

typedef struct {
	cl_uint		type;
	cl_uint		length;
	cl_ulong	timestamp;
	char		data[1];		/* variable length */
} GstoreTxLogCommon;

typedef struct {
	cl_uint		type;
	cl_uint		length;
	cl_ulong	timestamp;
	cl_uint		rowid;
	HeapTupleHeaderData htup __attribute__((aligned(8)));
	/* + GSTORE_TX_LOG__TERMINATOR */
} GstoreTxLogInsert;

typedef struct {
	cl_uint		type;
	cl_uint		length;
	cl_ulong	timestamp;
	cl_uint		rowid;
	cl_uint		xid;
} GstoreTxLogDelete;

/*
 * COMMIT/ABORT
 */
#define GSTORE_TX_LOG_COMMIT_ALLOCSZ	96
typedef struct {
	cl_uint		type;
	cl_uint		length;
	cl_ulong	timestamp;
	cl_uint		xid;
	cl_ushort	nitems;
	char		data[1];		/* variable length */
} GstoreTxLogCommit;

/*
 * GstoreFdwSysattr
 *
 * A fixed-length system attribute for each row.
 */
struct GstoreFdwSysattr
{
	cl_uint		xmin;
	cl_uint		xmax;
	/* get_global_id() of the thread who tries to update the row */
	cl_uint		owner_id;
};
typedef struct GstoreFdwSysattr	GstoreFdwSysattr;

#ifdef __CUDACC_RTC__
DEVICE_INLINE(cl_int)
pg_sysattr_ctid_fetch_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowid,
							 cl_char &dclass,
							 Datum   &value)
{
	if (kds)
	{
		ItemPointerData *t_self = (ItemPointerData *)
			kern_context_alloc(kcxt, sizeof(ItemPointerData));
		if (t_self)
		{
			t_self->ip_blkid.bi_hi = (rowid >> 16);
			t_self->ip_blkid.bi_lo = (rowid & 0xffffU);
			t_self->ip_posid       = 0;
			dclass = DATUM_CLASS__NORMAL;
			value  = PointerGetDatum(t_self);
			return sizeof(ItemPointerData);
		}
		STROM_EREPORT(kcxt, ERRCODE_OUT_OF_MEMORY, "out of memory");
	}
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_oid_fetch_column(kern_context *kcxt,
							kern_data_store *kds,
							cl_uint rowid,
							cl_char &dclass,
							Datum   &value)
{
	if (!kds)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = 0;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmin_fetch_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowid,
							 cl_char &dclass,
							 Datum   &value)
{
	if (kds)
	{
		GstoreFdwSysattr   *sysattr = (GstoreFdwSysattr *)
			kern_get_datum_column(kds, NULL, kds->ncols-1, rowid);
		if (sysattr)
		{
			dclass = DATUM_CLASS__NORMAL;
			value  = sysattr->xmin;
			return 0;
		}
	}
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_xmax_fetch_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowid,
							 cl_char &dclass,
							 Datum   &value)
{
	if (kds)
	{
		GstoreFdwSysattr   *sysattr = (GstoreFdwSysattr *)
			kern_get_datum_column(kds, NULL, kds->ncols-1, rowid);
		if (sysattr)
		{
			dclass = DATUM_CLASS__NORMAL;
			value  = sysattr->xmax;
			return 0;
		}
	}
	dclass = DATUM_CLASS__NULL;
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmin_fetch_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowid,
							 cl_char &dclass,
							 Datum   &value)
{
	if (!kds)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = (Datum)InvalidCommandId;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_cmax_fetch_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowid,
							 cl_char &dclass,
							 Datum   &value)
{
	if (!kds)
		dclass = DATUM_CLASS__NULL;
	else
	{
		dclass = DATUM_CLASS__NORMAL;
		value  = (Datum)InvalidCommandId;
	}
	return 0;
}

DEVICE_INLINE(cl_int)
pg_sysattr_tableoid_fetch_column(kern_context *kcxt,
								 kern_data_store *kds,
								 cl_uint rowid,
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
#endif

/*
 * kern_gpustore_init_load
 */
typedef struct
{
	kern_errorbuf	kerror;
	kern_data_store	kds_row;
} kern_gpustore_initial_load;

/*
 * kern_gpustore_redolog
 */
typedef struct
{
	kern_errorbuf	kerror;
	size_t			length;
	cl_uint			nrooms;
	cl_uint			nitems;
	cl_uint			log_index[FLEXIBLE_ARRAY_MEMBER];
} kern_gpustore_redolog;

#endif /* CUDA_GSTORE_H */
