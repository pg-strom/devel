/*
 * gpu_store.c
 *
 * GPU data store that syncronizes PostgreSQL tables
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
#include "cuda_gstore.h"

/*
 * GpuStoreBackgroundCommand
 */
#define GSTORE_BACKGROUND_CMD__INITIAL_LOAD     'I'
#define GSTORE_BACKGROUND_CMD__APPLY_REDO       'A'
#define GSTORE_BACKGROUND_CMD__COMPACTION       'C'
#define GSTORE_BACKGROUND_CMD__DROP_UNLOAD      'D'
typedef struct
{
	dlist_node  chain;
	Oid         database_oid;
	Oid         table_oid;
	Latch      *backend;        /* MyLatch of the backend, if any */
	int         command;        /* one of GSTORE_MAINTAIN_CMD__* */
	CUresult    retval;
	uint64      end_pos;        /* for APPLY_REDO */
} GpuStoreBackgroundCommand;

/*
 * GpuStoreSharedHead (shared structure; static)
 */
#define GPUSTORE_SHARED_DESC_NSLOTS		107
typedef struct
{
	/* hash slot for GpuStoreSharedState */
	slock_t		gstore_sstate_lock[GPUSTORE_SHARED_DESC_NSLOTS];
	dlist_head	gstore_sstate_slot[GPUSTORE_SHARED_DESC_NSLOTS];
	/* database name for preloading */
	int			preload_database_status;
	char		preload_database_name[NAMEDATALEN];
	/* IPC to GpuStore background workers */
	slock_t		bgworker_cmd_lock;
	dlist_head	bgworker_free_cmds;
	GpuStoreBackgroundCommand __bgworker_cmds[300];
	struct {
		Latch	   *latch;
		dlist_head	cmd_queue;
	} bgworkers[FLEXIBLE_ARRAY_MEMBER];
} GpuStoreSharedHead;

/*
 * GpuStoreRowIdHash / GpuStoreRowId / GpuStoreRedoBuffer (shared structure; DSM)
 */
typedef struct
{
	slock_t		lock;
	cl_uint		nslots;
	cl_uint		nrooms;
	cl_uint		free_list;
	cl_uint		hash_slot[FLEXIBLE_ARRAY_MEMBER];
	/* rowid_map->hash_slot[nslots] is head of GpuStoreRowId array */
} GpuStoreRowIdHash;

typedef struct
{
	cl_uint		next;
	ItemPointerData	ctid;
} GpuStoreRowId;

#define REDO_BUFFER_SIZE		(128UL << 20)		/* 128MB */
typedef struct
{
	size_t		length;
	slock_t		lock;
	uint64		timestamp;
	uint64		write_nitems;
	uint64		write_pos;
	uint64		read_nitems;
	uint64		read_pos;
	uint64		sync_pos;
	char		buffer[FLEXIBLE_ARRAY_MEMBER];
} GpuStoreRedoBuffer;

static inline GpuStoreRowIdHash *
__gpuStoreRowIdHash(dsm_segment *shbuf_seg)
{
	return (GpuStoreRowIdHash *)dsm_segment_address(shbuf_seg);
}

static inline GpuStoreRowId *
__gpuStoreRowIdMap(dsm_segment *shbuf_seg)
{
	GpuStoreRowIdHash  *rowhash = __gpuStoreRowIdHash(shbuf_seg);

	return (GpuStoreRowId *)
		((char *)rowhash + STROMALIGN(offsetof(GpuStoreRowIdHash,
											   hash_slot[rowhash->nslots])));
}

static inline GpuStoreRedoBuffer *
__gpuStoreRedoBuffer(dsm_segment *shbuf_seg)
{
	GpuStoreRowIdHash  *rowhash = __gpuStoreRowIdHash(shbuf_seg);
	GpuStoreRowId	   *rowmap = __gpuStoreRowIdMap(shbuf_seg);

	return (GpuStoreRedoBuffer *)
		((char *)rowmap + STROMALIGN(sizeof(GpuStoreRowId) * rowhash->nrooms));
}

/*
 * GpuStoreSharedState (shared structure; dynamic portable)
 */
typedef struct
{
	dlist_node	chain;
	Oid			database_oid;
	Oid			table_oid;
	/* GPU memory store resources */
	bool		initial_load_in_progress;
	dsm_handle	shbuf_handle;
	/* GPU memory store parameter */
	int64		max_num_rows;
	int32		cuda_dindex;
	/* device data store */
	pthread_rwlock_t gpu_buffer_lock;
	CUipcMemHandle	gpu_main_mhandle;
	CUipcMemHandle	gpu_extra_mhandle;
	size_t			gpu_main_size;
	size_t			gpu_extra_size;
} GpuStoreSharedState;

/*
 * PendingRowIdArray / PendingRowIdItem
 */
typedef struct
{
	char		tag;
	ItemPointerData ctid;
	cl_uint		rowid;
} PendingRowIdItem;

typedef struct
{
	dlist_node	chain;
	TransactionId xid;
	cl_uint		nitems;
	StringInfoData buf;
} PendingRowIdArray;

/*
 * GpuStoreDesc (per-backend local structure)
 */
typedef struct
{
	Oid					database_oid;
	Oid					table_oid;
	GpuStoreSharedState *gs_sstate; /* NULL, if no GPU Store */
	dsm_segment		   *shbuf_seg;
	GpuStoreRowIdHash  *rowhash;	/* DSM */
	GpuStoreRowId	   *rowmap;		/* DSM */
	GpuStoreRedoBuffer *redo_buf;	/* DSM */
	PendingRowIdArray  *pending_rowid_last;
	dlist_head			pending_rowid_list;
} GpuStoreDesc;

/* --- static variables --- */
static GpuStoreSharedHead *gstore_shared_head = NULL;
static HTAB	   *gstore_desc_htab = NULL;
static shmem_startup_hook_type shmem_startup_next = NULL;
static object_access_hook_type object_access_next = NULL;
static void	  (*gstore_xact_redo_next)(XLogReaderState *record) = NULL;
static void	  (*gstore_heap_redo_next)(XLogReaderState *record) = NULL;

/* --- function declarations --- */
static CUresult gpuStoreInvokeApplyRedo(GpuStoreSharedState *gs_sstate,
										uint64 end_pos,
										bool is_async);
static CUresult gpuStoreInvokeCompaction(GpuStoreSharedState *gs_sstate,
										 bool is_async);
Datum	pgstrom_gpustore_synchronizer(PG_FUNCTION_ARGS);
void	GpuStoreStartupPreloader(Datum arg);

/*
 * relationHasSynchronizer
 */
static bool
relationHasSynchronizer(Relation rel, int64 *p_max_num_rows, int32 *p_cuda_dindex)
{
	TriggerDesc *trigdesc = rel->trigdesc;
	Oid		namespace_oid;
	Oid		synchronizer_oid;
	oidvector *argtypes;
	int		i;

	if (!trigdesc)
		return false;	/* no trigger */
	if (!trigdesc->trig_insert_after_row ||
		!trigdesc->trig_update_after_row ||
		!trigdesc->trig_delete_after_row)
		return false;	/* quick bailout */

	/* lookup OID of pgstrom.gpustore_synchronizer */
	namespace_oid = get_namespace_oid("pgstrom", true);
	if (!OidIsValid(namespace_oid))
		return false;
	argtypes = palloc0(offsetof(oidvector, values[1]));
	SET_VARSIZE(argtypes, offsetof(oidvector, values[1]));
	argtypes->ndim = 1;
	argtypes->dataoffset = 0;
	argtypes->elemtype = OIDOID;
	argtypes->dim1 = 1;
	argtypes->lbound1 = 0;
	argtypes->values[0] = OIDOID;

	synchronizer_oid = GetSysCacheOid3(PROCNAMEARGSNSP,
									   Anum_pg_proc_oid,
									   CStringGetDatum("gpustore_synchronizer"),
									   PointerGetDatum(argtypes),
									   ObjectIdGetDatum(namespace_oid));
	if (!OidIsValid(synchronizer_oid))
		return false;

	for (i=0; i < trigdesc->numtriggers; i++)
	{
		Trigger	   *trig = &trigdesc->triggers[i];

		if (trig->tgfoid == synchronizer_oid &&
			trig->tgenabled &&
			trig->tgtype == (TRIGGER_TYPE_ROW |
							 TRIGGER_TYPE_INSERT |
							 TRIGGER_TYPE_DELETE |
							 TRIGGER_TYPE_UPDATE) &&
			trig->tgnargs == 2 &&
			trig->tgargs[0] != NULL &&
			trig->tgargs[1] != NULL)
		{
			/* Ok, check argument (must be int8) */
			Const	   *con0 = (Const *)stringToNode(trig->tgargs[0]);
			Const	   *con1 = (Const *)stringToNode(trig->tgargs[1]);
			int64		max_num_rows;
			int32		gpu_device_id;
			int			i, cuda_dindex = -1;

			if (!IsA(con0, Const) ||
				con0->consttype != INT8OID ||
				con0->consttypmod != -1 ||
				con0->constcollid != InvalidOid)
				continue;
			if(!IsA(con1, Const) ||
			   con1->consttype != INT4OID ||
			   con1->consttypmod != -1 ||
			   con1->constcollid != InvalidOid)
				continue;

			max_num_rows = DatumGetInt64(con0->constvalue);
			if (max_num_rows < 10000 ||
                max_num_rows > INT_MAX)
			{
				elog(WARNING, "%s: max_num_rows (%ld) is out of range",
					 __FUNCTION__, max_num_rows);
				continue;
			}

			gpu_device_id = DatumGetInt32(con1->constvalue);
			if (numDevAttrs == 0)
			{
				elog(WARNING, "%s: No GPU devices are installed",
					 __FUNCTION__);
				continue;
			}
			else if (gpu_device_id < 0)
			{
				cuda_dindex = 0;	/* assign first GPU */
			}
			else
			{
				for (i=0; i < numDevAttrs; i++)
				{
					if (devAttrs[i].DEV_ID == gpu_device_id)
					{
						cuda_dindex = i;
						break;
					}
				}
				if (cuda_dindex < 0)
				{
					elog(WARNING, "%s: GPU device id (%d) not found",
						 __FUNCTION__, gpu_device_id);
					continue;
				}
			}

			if (p_max_num_rows)
				*p_max_num_rows = max_num_rows;
			if (p_cuda_dindex)
				*p_cuda_dindex = cuda_dindex;
			return true;
		}
	}
	return false;
}

/*
 * baseRelHasGpuStore
 */
bool
baseRelHasGpuStore(PlannerInfo *root, RelOptInfo *baserel)
{
	RangeTblEntry *rte = root->simple_rte_array[baserel->relid];
	bool		retval = false;

	if (rte->rtekind == RTE_RELATION &&
		(baserel->reloptkind == RELOPT_BASEREL ||
		 baserel->reloptkind == RELOPT_OTHER_MEMBER_REL))
	{
		GpuStoreDesc *gs_desc;
		Relation	rel;
		Oid			hkey[2];
		bool		found;

		hkey[0] = MyDatabaseId;
		hkey[1] = rte->relid;
		gs_desc = (GpuStoreDesc *)
			hash_search(gstore_desc_htab,
						hkey,
						HASH_FIND,
						NULL);
		if (gs_desc)
			retval = (gs_desc->gs_sstate != NULL ? true : false);
		else
		{
			rel = relation_open(rte->relid, NoLock);

			retval = relationHasSynchronizer(rel, NULL, NULL);
			if (!retval)
			{
				/* Add negative entry for relations w/o GPU Store */
				gs_desc = (GpuStoreDesc *)
					hash_search(gstore_desc_htab,
								hkey,
								HASH_ENTER,
								&found);
				Assert(!found);
				memset(&gs_desc->gs_sstate, 0,
					   sizeof(GpuStoreDesc) - offsetof(GpuStoreDesc, gs_sstate));
				dlist_init(&gs_desc->pending_rowid_list);
			}
			relation_close(rel, NoLock);
		}
	}
	return retval;
}

/*
 * RelationHasGpuStore
 */
bool
RelationHasGpuStore(Relation rel)
{
	return relationHasSynchronizer(rel, NULL, NULL);
}

/*
 * __gpuStoreLoadCudaModule
 */
static CUresult
__gpuStoreLoadCudaModule(CUmodule *p_cuda_module)
{
	const char *path = PGSHAREDIR "/pg_strom/cuda_gstore.fatbin";
	int			rawfd;
	struct stat	stat_buf;
	ssize_t		nbytes;
	void	   *fatbin_image;
	CUmodule	cuda_module;
	CUresult	rc = CUDA_ERROR_FILE_NOT_FOUND;

	rawfd = open(path, O_RDONLY);
	if (rawfd < 0)
		goto error_0;

	if (fstat(rawfd, &stat_buf) != 0)
		goto error_1;

	fatbin_image = malloc(stat_buf.st_size + 1);
	if (!fatbin_image)
		goto error_1;

	nbytes = __readFileSignal(rawfd, fatbin_image,
							  stat_buf.st_size, false);
	if (nbytes != stat_buf.st_size)
		goto error_2;

	rc = cuModuleLoadFatBinary(&cuda_module, fatbin_image);
	if (rc == CUDA_SUCCESS)
		*p_cuda_module = cuda_module;
error_2:
	free(fatbin_image);
error_1:
	close(rawfd);
error_0:
	return rc;
}

/*
 * __gpuStoreAllocateDSM
 */
static void
__gpuStoreAllocateDSM(GpuStoreDesc *gs_desc, int64 nrooms, int64 nslots)
{
	GpuStoreRowIdHash  *rowhash;
	GpuStoreRowId	   *rowmap;
	GpuStoreRedoBuffer *redo_buf;
	dsm_segment		   *shbuf_seg;
	size_t				sz;
	int64				i;

	sz = (STROMALIGN(offsetof(GpuStoreRowIdHash, hash_slot[nslots])) +
		  STROMALIGN(sizeof(GpuStoreRowId) * nrooms) +
		  STROMALIGN(offsetof(GpuStoreRedoBuffer, buffer) + REDO_BUFFER_SIZE));
	shbuf_seg = dsm_create(sz, 0);
	if (!shbuf_seg)
		elog(ERROR, "failed on dsm_create(%zu, 0)", sz);

	rowhash = __gpuStoreRowIdHash(shbuf_seg);
	SpinLockInit(&rowhash->lock);
	rowhash->nslots = nslots;
	rowhash->nrooms = nrooms;
	rowhash->free_list = 0;
	memset(rowhash->hash_slot, -1, sizeof(cl_uint) * nslots);

	rowmap = __gpuStoreRowIdMap(shbuf_seg);
	memset(rowmap, 0, sizeof(GpuStoreRowId) * nrooms);
	for (i=1; i <= nrooms; i++)
	{
		rowmap[i-1].next = (i < nrooms ? i : UINT_MAX);
	}

	redo_buf = __gpuStoreRedoBuffer(shbuf_seg);
	memset(redo_buf, 0, offsetof(GpuStoreRedoBuffer, buffer));
	redo_buf->length = REDO_BUFFER_SIZE;
	SpinLockInit(&redo_buf->lock);

	gs_desc->shbuf_seg = shbuf_seg;
	gs_desc->rowhash   = rowhash;
	gs_desc->rowmap    = rowmap;
	gs_desc->redo_buf  = redo_buf;
}

/*
 * __gpuStoreSetupHeader
 */
static kern_data_store *
__gpuStoreCreateKernelBuffer(Relation rel, int64 nrooms,
							 kern_data_extra *kds_extra)
{
	TupleDesc	tupdesc = RelationGetDescr(rel);
	kern_data_store *kds_head;
	size_t		main_sz;
	size_t		unitsz, sz;
	int			j;

	main_sz = (KDS_calculateHeadSize(tupdesc) +
			   STROMALIGN(sizeof(kern_colmeta)));
	kds_head = palloc0(main_sz);
	init_kernel_data_store(kds_head,
						   tupdesc,
						   0,	/* to be set later */
						   KDS_FORMAT_COLUMN,
						   nrooms);
	kds_head->table_oid = RelationGetRelid(rel);
	Assert(main_sz >= offsetof(kern_data_store,
							   colmeta[kds_head->nr_colmeta]));
	memset(kds_extra, 0, offsetof(kern_data_extra, data));
	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute attr = tupleDescAttr(tupdesc, j);
		kern_colmeta   *cmeta = &kds_head->colmeta[j];

		if (!attr->attnotnull)
		{
			sz = MAXALIGN(BITMAPLEN(nrooms));
			cmeta->nullmap_offset = __kds_packed(main_sz);
			cmeta->nullmap_length = __kds_packed(sz);
			main_sz += sz;
		}

		if (attr->attlen > 0)
		{
			unitsz = att_align_nominal(attr->attlen,
									   attr->attalign);
			sz = MAXALIGN(unitsz * nrooms);
			cmeta->values_offset = __kds_packed(main_sz);
			cmeta->values_length = __kds_packed(sz);
			main_sz += sz;
		}
		else if (attr->attlen == -1)
		{
			/* offset == 0 means NULL-value for varlena */
			sz = MAXALIGN(sizeof(cl_uint) * nrooms);
			cmeta->values_offset = __kds_packed(main_sz);
			cmeta->values_length = __kds_packed(sz);
			main_sz += sz;
			unitsz = get_typavgwidth(attr->atttypid,
									 attr->atttypmod);
			kds_extra->length += MAXALIGN(unitsz) * nrooms;
		}
		else
		{
			elog(ERROR, "unexpected type length (%d) at %s.%s",
				 attr->attlen,
				 RelationGetRelationName(rel),
				 NameStr(attr->attname));
		}
	}
	kds_head->length = main_sz;

	return kds_head;
}

/*
 * __gpuStoreLoadRelation
 */
static void
__gpuStoreLoadRelation(Relation rel,
					   kern_data_store *kds,
					   GpuStoreRowIdHash *rowhash,
					   GpuStoreRowId  *rowmap)
{
	TableScanDesc	scandesc;
	Snapshot		snapshot;
	HeapTuple		tuple;
	cl_uint			hash, hindex;
	cl_uint			rowid;
	cl_uint		   *tup_index = KERN_DATA_STORE_ROWINDEX(kds);
	cl_int			j, ncols = RelationGetNumberOfAttributes(rel);
	TupleDesc		tupdesc = RelationGetDescr(rel);
	Datum		   *values = alloca(sizeof(Datum) * ncols);
	bool		   *isnull = alloca(sizeof(bool) * ncols);

	Assert(kds->ncols == RelationGetNumberOfAttributes(rel));
	Assert(kds->nrooms == rowhash->nrooms);
	Assert(rowhash->nslots > rowhash->nrooms);
	
	snapshot = RegisterSnapshot(GetLatestSnapshot());
	scandesc = table_beginscan(rel, snapshot, 0, NULL);
	while ((tuple = heap_getnext(scandesc, ForwardScanDirection)) != NULL)
	{
		kern_tupitem *tup_item;
		size_t		usage;
		bool		tuple_pfree = false;

		CHECK_FOR_INTERRUPTS();

		rowid = kds->nitems++;
		if (rowid >= kds->nrooms)
			elog(ERROR, "gpu_store: no more row-id available");
		/* expand external values, if any */
		if (HeapTupleHeaderHasExternal(tuple->t_data))
		{
			heap_deform_tuple(tuple, tupdesc, values, isnull);
			for (j=0; j < ncols; j++)
			{
				Form_pg_attribute attr = tupleDescAttr(tupdesc, j);

				if (attr->attisdropped)
					isnull[j] = true;
				else if (attr->attlen == -1 && !isnull[j])
					values[j] = (Datum)PG_DETOAST_DATUM_PACKED(values[j]);
			}
			tuple = heap_form_tuple(tupdesc, values, isnull);
			tuple_pfree = true;
		}
		/* add tuple to KDS */
		usage = (__kds_unpack(kds->usage) +
				 MAXALIGN(offsetof(kern_tupitem, htup) + tuple->t_len));
		if (KERN_DATA_STORE_HEAD_LENGTH(kds) +
			STROMALIGN(sizeof(cl_uint) * kds->nitems) +
			STROMALIGN(usage) > kds->length)
			elog(ERROR, "gpu_store: buffer full! at initial loading");

		tup_item = (kern_tupitem *)((char *)kds + kds->length - usage);
		tup_item->rowid = rowid;
		tup_item->t_len = tuple->t_len;
		memcpy(&tup_item->htup, tuple->t_data, tuple->t_len);
		memcpy(&tup_item->htup.t_ctid, &tuple->t_self, sizeof(ItemPointerData));
		tup_index[rowid] = __kds_packed((uintptr_t)tup_item -
										(uintptr_t)kds);
		kds->usage = __kds_packed(usage);
		if (tuple_pfree)
			pfree(tuple);

		/* add ctid and rowid to hash */
		hash = hash_any((unsigned char *)&tuple->t_self,
						sizeof(ItemPointerData));
		hindex = hash % rowhash->nslots;

		rowmap[rowid].ctid = tuple->t_self;
		rowmap[rowid].next = rowhash->hash_slot[hindex];
		rowhash->hash_slot[hindex] = rowid;
	}
	table_endscan(scandesc);
	UnregisterSnapshot(snapshot);

	/* add unused rowid to free-list */
	if (kds->nitems < kds->nrooms)
	{
		for (rowid=kds->nitems; rowid < kds->nrooms; rowid++)
		{
			Assert(!ItemPointerIsValid(&rowmap[rowid].ctid));
			rowmap[rowid].next = (rowid+1 < kds->nrooms ? rowid+1 : UINT_MAX);
		}
		rowhash->free_list = kds->nitems;
	}
	else
	{
		rowhash->free_list = UINT_MAX;
	}
}

/*
 * GpuStoreExecInitialLoad
 */
static void
__GpuStoreExecInitialLoad(Relation rel,
						  GpuStoreDesc *gs_desc,
						  CUmodule cuda_module)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	TupleDesc		tupdesc = RelationGetDescr(rel);
	CUfunction		kfunc_init_load;
	CUdeviceptr		m_main = 0UL;
	CUdeviceptr		m_extra = 0UL;
	CUresult		rc;
	kern_gpustore_baserel *kgs_base;
	kern_data_store *kds_main;
	kern_data_extra kds_extra;
	int64			nrooms = gs_sstate->max_num_rows;
	int64			nslots = Min((double)nrooms * 1.25, UINT_MAX);
	size_t			sz;

	/* allocation of managed memory for KDS_FORMAT_ROW */
	sz = (KDS_calculateHeadSize(tupdesc) +
		  STROMALIGN(sizeof(cl_uint) * nrooms) +
		  table_relation_size(rel, MAIN_FORKNUM));
	rc = cuMemAllocManaged((CUdeviceptr *)&kgs_base,
						   offsetof(kern_gpustore_baserel, kds_row) + sz,
						   CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on cuMemAllocManaged: %s", errorText(rc));
	memset(kgs_base, 0, offsetof(kern_gpustore_baserel, kds_row));
	init_kernel_data_store(&kgs_base->kds_row,
						   tupdesc, sz, KDS_FORMAT_ROW, nrooms);
	/* allocation of DSM for rowid hash/map and redo-buffer */
	__gpuStoreAllocateDSM(gs_desc, nrooms, nslots);
	/* load the entire relation */
	kds_main = __gpuStoreCreateKernelBuffer(rel, nrooms, &kds_extra);
	__gpuStoreLoadRelation(rel, kds_main, gs_desc->rowhash, gs_desc->rowmap);

	/* GPU kernel invocation for initial loading */
	PG_TRY();
	{
		int			grid_sz;
		int			block_sz;
		void	   *kfunc_args[5];

		rc = cuModuleGetFunction(&kfunc_init_load, cuda_module,
								 "kern_gpustore_initial_load");
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuModuleGetFunction: %s", errorText(rc));

		rc = __gpuOptimalBlockSize(&grid_sz,
								   &block_sz,
								   kfunc_init_load,
								   gs_sstate->cuda_dindex, 0, 0);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on __gpuOptimalBlockSize: %s", errorText(rc));
		grid_sz = Min(grid_sz, (kds_main->nitems +
								block_sz - 1) / block_sz);

		/* preserve the main store */
		rc = gpuMemAllocPreserved(gs_sstate->cuda_dindex,
								  &gs_sstate->gpu_main_mhandle,
								  kds_main->length);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on gpuMemAllocPreserved: %s", errorText(rc));
		gs_sstate->gpu_main_size = kds_main->length;

		rc = cuIpcOpenMemHandle(&m_main, gs_sstate->gpu_main_mhandle,
								CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuIpcOpenMemHandle: %s", errorText(rc));

		rc = cuMemcpyHtoD(m_main, kds_main,
						  KERN_DATA_STORE_HEAD_LENGTH(kds_main));
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuMemcpyHtoD: %s", errorText(rc));

	retry:
		/* preserve the extra store, if any */
		if (kds_extra.length > 0)
		{
			rc = gpuMemAllocPreserved(gs_sstate->cuda_dindex,
									  &gs_sstate->gpu_extra_mhandle,
									  kds_extra.length);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on gpuMemAllocPreserved: %s", errorText(rc));
			gs_sstate->gpu_extra_size = kds_extra.length;

			rc = cuIpcOpenMemHandle(&m_extra, gs_sstate->gpu_extra_mhandle,
									CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuIpcOpenMemHandle: %s", errorText(rc));

			rc = cuMemcpyHtoD(m_extra, &kds_extra,
							  offsetof(kern_data_extra, data));
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuMemcpyHtoD: %s", errorText(rc));
		}

		/* kick GPU kernel */
		kfunc_args[0] = &m_main;
		kfunc_args[1] = &m_extra;
		kfunc_args[2] = &kgs_base;
		rc = cuLaunchKernel(kfunc_init_load,
							grid_sz, 1, 1,
							block_sz, 1, 1,
							0,
							CU_STREAM_PER_THREAD,
							kfunc_args,
							NULL);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuLaunchKernel: %s", errorText(rc));

		/* check status of the kernel execution */
		rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuStreamSynchronize: %s", errorText(rc));

		if (kgs_base->kerror.errcode == ERRCODE_OUT_OF_MEMORY)
		{
			Assert(m_extra != 0UL);
			/* how much extra buffer is actually required? */
			rc = cuMemcpyDtoH(&kds_extra, m_extra,
							  offsetof(kern_data_extra, data));
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuMemcpyDtoH: %s", errorText(rc));
			kds_extra.length = kds_extra.usage + (64UL << 20);	/* 64MB margin */
			kds_extra.usage = 0;
			
			/* once release the extra buffer */
			rc = cuIpcCloseMemHandle(m_extra);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuIpcCloseMemHandle: %s", errorText(rc));
			m_extra = 0UL;

			rc = gpuMemFreePreserved(gs_sstate->cuda_dindex,
									 gs_sstate->gpu_extra_mhandle);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on gpuMemFreePreserved: %s", errorText(rc));
			gs_sstate->gpu_extra_size = 0;
			goto retry;
		}
		else if (kgs_base->kerror.errcode != 0)
		{
			ereport(ERROR,
					(errcode(kgs_base->kerror.errcode),
					 errmsg("failed on GpuStore Initial Loading: %s",
							kgs_base->kerror.message),
					 errdetail("GPU kernel location: %s:%d [%s]",
							   kgs_base->kerror.filename,
							   kgs_base->kerror.lineno,
							   kgs_base->kerror.funcname)));
		}
	}
	PG_CATCH();
	{
		if (m_main != 0UL)
		{
			rc = cuIpcCloseMemHandle(m_main);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on cuIpcCloseMemHandle: %s", errorText(rc));
		}

		if (gs_sstate->gpu_main_size > 0)
		{
			rc = gpuMemFreePreserved(gs_sstate->cuda_dindex,
									 gs_sstate->gpu_main_mhandle);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on gpuMemFreePreserved: %s", errorText(rc));
		}

		if (m_extra != 0UL)
		{
			rc = cuIpcCloseMemHandle(m_extra);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on cuIpcCloseMemHandle: %s", errorText(rc));
		}

		if (gs_sstate->gpu_extra_size > 0)
		{
			rc = gpuMemFreePreserved(gs_sstate->cuda_dindex,
									 gs_sstate->gpu_extra_mhandle);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on gpuMemFreePreserved: %s", errorText(rc));
		}
	}
	PG_END_TRY();
	/* unmap device memory */
	if (m_main != 0UL)
	{
		rc = cuIpcCloseMemHandle(m_main);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuIpcCloseMemHandle: %s", errorText(rc));
	}
	if (m_extra != 0UL)
	{
		rc = cuIpcCloseMemHandle(m_extra);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuIpcCloseMemHandle: %s", errorText(rc));
	}
	/* all Ok, so pin DSM mapping */
	gs_sstate->shbuf_handle = dsm_segment_handle(gs_desc->shbuf_seg);
	dsm_pin_mapping(gs_desc->shbuf_seg);
	dsm_pin_segment(gs_desc->shbuf_seg);
}

static void
GpuStoreExecInitialLoad(Relation rel, GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	int			cuda_dindex = gs_sstate->cuda_dindex;
	CUdevice	cuda_device;
	CUcontext	cuda_context = NULL;
	CUmodule	cuda_module = NULL;
	CUresult	rc;
	
	/* setup one-time cuda context, then load full-relation */
	PG_TRY();
	{
		rc = gpuInit(0);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuInit: %s", errorText(rc));

		rc = cuDeviceGet(&cuda_device, devAttrs[cuda_dindex].DEV_ID);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuDeviceGet: %s", errorText(rc));

		rc = cuCtxCreate(&cuda_context,
						 CU_CTX_SCHED_AUTO,
						 cuda_device);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuCtxCreate: %s", errorText(rc));

		rc = cuCtxPushCurrent(cuda_context);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuCtxPushCurrent: %s", errorText(rc));

		rc = __gpuStoreLoadCudaModule(&cuda_module);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on __gpuStoreLoadCudaModule: %s", errorText(rc));

		__GpuStoreExecInitialLoad(rel, gs_desc, cuda_module);
	}
	PG_CATCH();
	{
		if (cuda_context)
		{
			rc = cuCtxDestroy(cuda_context);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on cuCtxDestroy: %s", errorText(rc));
		}
		PG_RE_THROW();
	}
	PG_END_TRY();

	rc = cuCtxDestroy(cuda_context);
	if (rc != CUDA_SUCCESS)
		elog(WARNING, "failed on cuCtxDestroy: %s", errorText(rc));
}

/*
 * GpuStoreLookupOrCreateSharedState
 */
static void
GpuStoreLookupOrCreateSharedState(Relation rel,
								  GpuStoreDesc *gs_desc,
								  int64 max_num_rows,
								  int32 cuda_dindex)
{
	GpuStoreSharedState *gs_sstate = NULL;
	GpuStoreRedoBuffer  *redo_buf = NULL;
	dsm_segment *shbuf_seg;
	Oid			hkey[2];
	uint32		hash, hindex;
	slock_t	   *lock;
	dlist_head *slot;
	dlist_iter	iter;

	hkey[0] = MyDatabaseId;
	hkey[1] = RelationGetRelid(rel);
	hash = hash_any((const unsigned char *)hkey, sizeof(hkey));
	hindex = hash % GPUSTORE_SHARED_DESC_NSLOTS;
	lock = &gstore_shared_head->gstore_sstate_lock[hindex];
	slot = &gstore_shared_head->gstore_sstate_slot[hindex];
retry:
	CHECK_FOR_INTERRUPTS();

	SpinLockAcquire(lock);
	dlist_foreach(iter, slot)
	{
		gs_sstate = dlist_container(GpuStoreSharedState, chain, iter.cur);
		if (gs_sstate->database_oid == MyDatabaseId &&
			gs_sstate->table_oid == RelationGetRelid(rel))
		{
			if (gs_sstate->initial_load_in_progress)
			{
				/*
				 * It means someone already allocated GpuStoreSharedState,
				 * however, initial loading is still in-progress.
				 * So, we need to wait for completion of the initial task.
				 */
				SpinLockRelease(lock);

				pg_usleep(10000L);  /* 10ms */
				goto retry;
			}
			SpinLockRelease(lock);
			/* Ok, GpuStoreSharedState is already available */
			shbuf_seg = dsm_attach(gs_sstate->shbuf_handle);
			if (!shbuf_seg)
				elog(ERROR, "GPU Store: failed on dsm_attach: %m");
			gs_desc->gs_sstate = gs_sstate;
			gs_desc->rowhash   = __gpuStoreRowIdHash(shbuf_seg);
			gs_desc->rowmap    = __gpuStoreRowIdMap(shbuf_seg);
			gs_desc->redo_buf  = __gpuStoreRedoBuffer(shbuf_seg);

			return;
		}
	}
	gs_sstate = NULL;

	/*
	 * Hmm, there is no GpuStoreSharedState, so create a new one
	 * then load relation's contents to GPU Store. A tough work.
	 */
	PG_TRY();
	{
		/* allocation of GpuStoreSharedState */
		gs_sstate = MemoryContextAllocZero(TopSharedMemoryContext,
										   sizeof(GpuStoreSharedState));
		gs_sstate->database_oid = MyDatabaseId;
		gs_sstate->table_oid = RelationGetRelid(rel);
		gs_sstate->initial_load_in_progress = true;		/* !!! blocker !!! */
		gs_sstate->max_num_rows = max_num_rows;
		gs_sstate->cuda_dindex = cuda_dindex;
		pthreadRWLockInit(&gs_sstate->gpu_buffer_lock);
		dlist_push_tail(slot, &gs_sstate->chain);
		SpinLockRelease(lock);

		PG_TRY();
		{
			/* initial loading from the relation */
			gs_desc->gs_sstate = gs_sstate;
			GpuStoreExecInitialLoad(rel, gs_desc);
		}
		PG_CATCH();
		{
			SpinLockAcquire(lock);
			dlist_delete(&gs_sstate->chain);
			PG_RE_THROW();
		}
		PG_END_TRY();
		
		SpinLockAcquire(lock);
		gs_sstate->initial_load_in_progress = false;
	}
	PG_CATCH();
	{
		if (redo_buf)
			pfree(redo_buf);
		if (gs_sstate)
			pfree(gs_sstate);
		SpinLockRelease(lock);
		PG_RE_THROW();
	}
	PG_END_TRY();
	SpinLockRelease(lock);
}
		
/*
 * GpuStoreLookupDesc
 */
static GpuStoreDesc *
GpuStoreLookupDesc(Relation rel)
{
	GpuStoreDesc *gs_desc;
	Oid		hkey[2];
	bool	found;

	hkey[0] = MyDatabaseId;
	hkey[1] = RelationGetRelid(rel);
	gs_desc = (GpuStoreDesc *) hash_search(gstore_desc_htab,
										   hkey,
										   HASH_ENTER,
										   &found);
	if (!found)
	{
		PG_TRY();
		{
			int64	max_num_rows;
			int32	cuda_dindex;

			memset(&gs_desc->gs_sstate, 0,
				   sizeof(GpuStoreDesc) - offsetof(GpuStoreDesc, gs_sstate));
			if (relationHasSynchronizer(rel, &max_num_rows, &cuda_dindex))
			{
				GpuStoreLookupOrCreateSharedState(rel,
												  gs_desc,
												  max_num_rows,
												  cuda_dindex);
			}
			dlist_init(&gs_desc->pending_rowid_list);
		}
		PG_CATCH();
		{
			hash_search(gstore_desc_htab, hkey, HASH_REMOVE, NULL);
			PG_RE_THROW();
		}
		PG_END_TRY();
	}
	return (gs_desc->gs_sstate != NULL ? gs_desc : NULL);
}

/*
 * __gpuStoreAllocateRowId
 */
static cl_uint
__gpuStoreAllocateRowId(GpuStoreDesc *gs_desc, ItemPointer ctid)
{
	GpuStoreRowIdHash *rowhash = gs_desc->rowhash;
	GpuStoreRowId *rowmap = gs_desc->rowmap;
	GpuStoreRowId *r_item;
	cl_uint		hash;
	cl_uint		index;
	cl_uint		rowid;

	hash = hash_any((unsigned char *)ctid, sizeof(ItemPointerData));
	index = hash % rowhash->nslots;

	SpinLockAcquire(&rowhash->lock);
	if (rowhash->free_list >= rowhash->nrooms)
	{
		SpinLockRelease(&rowhash->lock);
		elog(ERROR, "No more rooms in the GPU Store");
	}
	rowid = rowhash->free_list;
	r_item = &rowmap[rowid];
	
	Assert(!ItemPointerIsValid(&r_item->ctid));
	rowhash->free_list = r_item->next;

	ItemPointerCopy(&r_item->ctid, ctid);
	r_item->next = rowhash->hash_slot[index];
	rowhash->hash_slot[index] = rowid;

	SpinLockRelease(&rowhash->lock);

	return rowid;
}

/*
 * __gpuStoreLookupRowId / __gpuStoreReleaseRowId
 */
static cl_uint
__gpuStoreLookupOrReleaseRowId(GpuStoreDesc *gs_desc, ItemPointer ctid,
							   bool release_rowid)
{
	GpuStoreRowIdHash *rowhash = gs_desc->rowhash;
	GpuStoreRowId *rowmap = gs_desc->rowmap;
	GpuStoreRowId *r_item;
	GpuStoreRowId *r_prev;
	cl_uint		hash;
	cl_uint		index;
	cl_uint		rowid;

	hash = hash_any((unsigned char *)ctid, sizeof(ItemPointerData));
	index = hash % rowhash->nslots;

	SpinLockAcquire(&rowhash->lock);
	for (rowid = rowhash->hash_slot[index], r_prev = NULL;
		 rowid < rowhash->nrooms;
		 rowid = r_item->next, r_prev = r_item)
	{
		r_item = &rowmap[rowid];

		if (ItemPointerEquals(&r_item->ctid, ctid))
		{
			if (release_rowid)
			{
				if (!r_prev)
					rowhash->hash_slot[index] = r_item->next;
				else
					r_prev->next = r_item->next;
				ItemPointerSetInvalid(&r_item->ctid);
				r_item->next = rowhash->free_list;
				rowhash->free_list = rowid;
			}
			SpinLockRelease(&rowhash->lock);
			return rowid;
		}
	}
	SpinLockRelease(&rowhash->lock);

	return UINT_MAX;
}

static inline cl_uint
__gpuStoreLookupRowId(GpuStoreDesc *gs_desc, ItemPointer ctid)
{
	return __gpuStoreLookupOrReleaseRowId(gs_desc, ctid, false);
}

static inline cl_uint
__gpuStoreReleaseRowId(GpuStoreDesc *gs_desc, ItemPointer ctid)
{
	return __gpuStoreLookupOrReleaseRowId(gs_desc, ctid, true);
}

/*
 * __gpuStoreAppendLog
 */
static void
__gpuStoreAppendLog(GpuStoreDesc *gs_desc, GstoreTxLogCommon *tx_log)
{
	GpuStoreRedoBuffer *redo = gs_desc->redo_buf;
	uint64		offset;
	uint64		sync_pos;
	bool		append_done = false;

	Assert(tx_log->length == MAXALIGN(tx_log->length));
	for (;;)
	{
		SpinLockAcquire(&redo->lock);
		Assert(redo->write_pos >= redo->read_pos &&
			   redo->write_pos <= redo->read_pos + redo->length &&
			   redo->sync_pos >= redo->read_pos &&
			   redo->sync_pos <= redo->write_pos);
		offset = redo->write_pos % redo->length;
		/* rewind to the head */
		if (offset + tx_log->length > redo->length)
		{
			size_t	sz = redo->length - offset;

			/* oops, it looks overwrites... */
			if (redo->write_pos + sz > redo->read_pos + redo->length)
				goto skip;
			/* fill-up by zero */
			memset(redo->buffer + offset, 0, sz);
			redo->write_pos += sz;
			offset = 0;
		}

		/* check overwrites */
		if (redo->write_pos + tx_log->length > redo->read_pos + redo->length)
			goto skip;

		/* Ok, append the log item */
		memcpy(redo->buffer + offset, tx_log, tx_log->length);
		redo->write_pos += tx_log->length;
		redo->timestamp = GetCurrentTimestamp();
		append_done = true;
	skip:
		/* 25% of REDO buffer is in-use. Async kick of GPU kernel */
		if (redo->write_pos > redo->sync_pos + redo->length / 4)
		{
			sync_pos = redo->sync_pos = redo->write_pos;
			SpinLockRelease(&redo->lock);
			gpuStoreInvokeApplyRedo(gs_desc->gs_sstate, sync_pos, true);
		}
		else
		{
			SpinLockRelease(&redo->lock);
		}
		if (append_done)
			break;
		pg_usleep(1000L);	/* 1ms wait */
	}
}

/*
 * __gpuStoreGetPendingRowIdBuffer
 */
static PendingRowIdArray *
__gpuStoreGetPendingRowIdArray(GpuStoreDesc *gs_desc)
{
	PendingRowIdArray *result = gs_desc->pending_rowid_last;
	TransactionId	xid = GetCurrentTransactionId();

	if (!result || result->xid != xid)
	{
		dlist_iter		iter;
		MemoryContext	oldcxt;

		dlist_foreach (iter, &gs_desc->pending_rowid_list)
		{
			result = dlist_container(PendingRowIdArray,
									 chain, iter.cur);
			if (result->xid == xid)
				goto out;
		}
		/* allocate a new one */
		oldcxt = MemoryContextSwitchTo(CacheMemoryContext);
		result = palloc0(sizeof(PendingRowIdArray));
		result->xid = xid;
		result->nitems = 0;
		initStringInfo(&result->buf);
		dlist_push_head(&gs_desc->pending_rowid_list, &result->chain);
		MemoryContextSwitchTo(oldcxt);
	out:
		gs_desc->pending_rowid_last = result;
	}
	return result;
}

/*
 * __gpuStoreInsertLog
 */
static void
__gpuStoreInsertLog(HeapTuple tuple,
					GpuStoreDesc *gs_desc,
					PendingRowIdArray *pending)
{
	GstoreTxLogInsert *item;
	PendingRowIdItem rlog;
	cl_uint		rowid;
	size_t		sz;

	/* Track RowId allocation */
	enlargeStringInfo(&pending->buf, sizeof(PendingRowIdItem));
	rowid = __gpuStoreAllocateRowId(gs_desc, &tuple->t_self);
	rlog.tag = 'I';
	rlog.ctid = tuple->t_self;
	rlog.rowid = rowid;
	appendBinaryStringInfo(&pending->buf,
						   (char *)&rlog,
						   sizeof(PendingRowIdItem));

	/* INSERT Log */
	sz = MAXALIGN(offsetof(GstoreTxLogInsert, htup) + tuple->t_len);
	item = alloca(sz);
	item->type = GSTORE_TX_LOG__INSERT;
	item->length = sz;
	item->timestamp = GetCurrentTimestamp();
	item->rowid = rowid;
	memcpy(&item->htup, tuple->t_data, tuple->t_len);
	HeapTupleHeaderSetXmin(&item->htup, GetCurrentTransactionId());
	HeapTupleHeaderSetXmax(&item->htup, InvalidTransactionId);
	HeapTupleHeaderSetCmin(&item->htup, InvalidCommandId);

	__gpuStoreAppendLog(gs_desc, (GstoreTxLogCommon *)item);
}

/*
 * __gpuStoreDeleteLog
 */
static void
__gpuStoreDeleteLog(HeapTuple tuple,
					GpuStoreDesc *gs_desc,
					PendingRowIdArray *pending)
{
	GstoreTxLogDelete item;
	PendingRowIdItem rlog;
	cl_uint		rowid;

	/* Track RowId Release */
	enlargeStringInfo(&pending->buf, sizeof(PendingRowIdItem));
	rowid = __gpuStoreLookupRowId(gs_desc, &tuple->t_self);
	rlog.tag = 'D';
	rlog.ctid = tuple->t_self;
	rlog.rowid = rowid;
	appendBinaryStringInfo(&pending->buf,
						   (char *)&rlog,
						   sizeof(PendingRowIdItem));
	/* DELETE Log */
	item.type = GSTORE_TX_LOG__DELETE;
	item.length = MAXALIGN(sizeof(GstoreTxLogDelete));
	item.timestamp = GetCurrentTimestamp();
	item.rowid = rowid;
	item.xid = GetCurrentTransactionId();

	__gpuStoreAppendLog(gs_desc, (GstoreTxLogCommon *)&item);
}

/*
 * pgstrom_gpustore_synchronizer
 */
Datum
pgstrom_gpustore_synchronizer(PG_FUNCTION_ARGS)
{
	TriggerData	   *trigdata = (TriggerData *) fcinfo->context;
	TriggerEvent	tg_event = trigdata->tg_event;
	Relation		rel = trigdata->tg_relation;
	GpuStoreDesc   *gs_desc;
	PendingRowIdArray *pending;

	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "%s: must be called as trigger",
			 __FUNCTION__);
	if (!TRIGGER_FIRED_FOR_ROW(tg_event) ||
		!TRIGGER_FIRED_AFTER(tg_event))
		elog(ERROR, "%s: must be called as ROW-AFTER trigger",
			 __FUNCTION__);

	gs_desc = GpuStoreLookupDesc(rel);
	if (!gs_desc)
		elog(ERROR, "%s: GPU Store is not configured at %s",
			 __FUNCTION__, RelationGetRelationName(rel));

	pending = __gpuStoreGetPendingRowIdArray(gs_desc);

	if (TRIGGER_FIRED_BY_INSERT(tg_event))
	{
		__gpuStoreInsertLog(trigdata->tg_trigtuple, gs_desc, pending);
	}
	else if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
	{
		__gpuStoreDeleteLog(trigdata->tg_trigtuple, gs_desc, pending);
		__gpuStoreInsertLog(trigdata->tg_newtuple, gs_desc, pending);
	}
	else if (TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
	{
		__gpuStoreDeleteLog(trigdata->tg_trigtuple, gs_desc, pending);
	}
	else
	{
		elog(ERROR, "%s: must be called for INSERT, DELETE or UPDATE",
			__FUNCTION__);
	}
	PG_RETURN_NULL();
}

/* ---------------------------------------------------------------- *
 *
 * Executor callbacks
 *
 * ---------------------------------------------------------------- */
GpuStoreState *
ExecInitGpuStore(ScanState *ss, int eflags, Bitmapset *outer_refs)
{
	return NULL;
}

pgstrom_data_store *
ExecScanChunkGpuStore(GpuTaskState *gts)
{
	return NULL;
}

void
ExecReScanGpuStore(GpuStoreState *gstore_state)
{}

void
ExecEndGpuStore(GpuStoreState *gstore_state)
{}

Size
ExecEstimateDSMGpuStore(GpuStoreState *gstore_state)
{
	return 0;
}

void
ExecInitDSMGpuStore(GpuStoreState *gstore_state,
					pg_atomic_uint64 *gstore_read_pos)
{}

void
ExecReInitDSMGpuStore(GpuStoreState *gstore_state)
{}

void
ExecInitWorkerGpuStore(GpuStoreState *gstore_state,
					   pg_atomic_uint64 *gstore_read_pos)
{}

void
ExecShutdownGpuStore(GpuStoreState *gstore_state)
{}

void
ExplainGpuStore(GpuStoreState *gstore_state,
				Relation frel, ExplainState *es)
{}

CUresult
gpuStoreMapDeviceMemory(GpuContext *gcontext,
						pgstrom_data_store *pds)
{
	return CUDA_ERROR_OUT_OF_MEMORY;
}

void
gpuStoreUnmapDeviceMemory(GpuContext *gcontext,
						  pgstrom_data_store *pds)
{

}





















static void
gpuStorePostDeletion(ObjectAccessType access,
					 Oid classId,
					 Oid objectId,
					 int subId,
					 void *arg)
{
	if (object_access_next)
		object_access_next(access, classId, objectId, subId, arg);



	
}

/*
 * gpuStoreXactCallback
 */
static void
gpuStoreXactCallback(XactEvent event, void *arg)
{

}

/*
 * gpuStoreSubXactCallback 
 */
static void
gpuStoreSubXactCallback(SubXactEvent event,
                         SubTransactionId mySubid,
                         SubTransactionId parentSubid, void *arg)
{


}

/*
 * __gpuStoreInvokeBackgroundCommand
 */
static CUresult
__gpuStoreInvokeBackgroundCommand(Oid database_oid,
								  Oid table_oid,
								  int cuda_dindex,
								  bool is_async,
								  int command,
								  uint64 end_pos)
{
	GpuStoreBackgroundCommand *cmd = NULL;
	dlist_node	   *dnode;
	Latch		   *latch;
	CUresult		retval = CUDA_SUCCESS;

	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	for (;;)
	{
		if (gstore_shared_head->bgworkers[cuda_dindex].latch &&
			!dlist_is_empty(&gstore_shared_head->bgworker_free_cmds))
		{
			/*
			 * Ok, GPU memory keeper is alive, and GpuStoreBackgroundCommand
			 * is available now.
			 */
			break;
		}
		SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
		CHECK_FOR_INTERRUPTS();
		pg_usleep(2000L);	/* 2ms */
		SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	}
	latch = gstore_shared_head->bgworkers[cuda_dindex].latch;
	dnode = dlist_pop_head_node(&gstore_shared_head->bgworker_free_cmds);
	cmd = dlist_container(GpuStoreBackgroundCommand, chain, dnode);

	memset(cmd, 0, sizeof(GpuStoreBackgroundCommand));
    cmd->database_oid = database_oid;
    cmd->table_oid = table_oid;
    cmd->backend = (is_async ? NULL : MyLatch);
    cmd->command = command;
    cmd->retval  = (CUresult) UINT_MAX;
    cmd->end_pos = end_pos;
	dlist_push_tail(&gstore_shared_head->bgworkers[cuda_dindex].cmd_queue,
					&cmd->chain);
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
	SetLatch(latch);

	if (!is_async)
	{
		SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
		while (cmd->retval == (CUresult) UINT_MAX)
		{
			SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
			PG_TRY();
			{
				int		ev;

				ev = WaitLatch(MyLatch,
							   WL_LATCH_SET |
							   WL_TIMEOUT |
							   WL_POSTMASTER_DEATH,
							   1000L,
							   PG_WAIT_EXTENSION);
				ResetLatch(MyLatch);
				if (ev & WL_POSTMASTER_DEATH)
					elog(FATAL, "unexpected postmaster dead");
				CHECK_FOR_INTERRUPTS();
			}
			PG_CATCH();
			{
				SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
				if (cmd->retval == (CUresult) UINT_MAX)
				{
					/*
					 * If not completed yet, the command is switched to
					 * asynchronous mode - because nobody can return the
					 * GpuStoreBackgroundCommand to free-list no longer.
					 */
					cmd->backend = NULL;
				}
				else
				{
					/* completed, so back to the free-list by itself */
					dlist_push_tail(&gstore_shared_head->bgworker_free_cmds,
									&cmd->chain);
				}
                SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
				PG_RE_THROW();
			}
			PG_END_TRY();
			SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
		}
		retval = cmd->retval;
		dlist_push_tail(&gstore_shared_head->bgworker_free_cmds,
						&cmd->chain);
		SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
	}
	return retval;
}

/*
 * GSTORE_BACKGROUND_CMD__APPLY_REDO
 */
static CUresult
gpuStoreInvokeApplyRedo(GpuStoreSharedState *gs_sstate,
						uint64 end_pos,
						bool is_async)
{
	return __gpuStoreInvokeBackgroundCommand(gs_sstate->database_oid,
											 gs_sstate->table_oid,
											 gs_sstate->cuda_dindex,
											 is_async,
											 GSTORE_BACKGROUND_CMD__APPLY_REDO,
											 end_pos);
}

/*
 * GSTORE_BACKGROUND_CMD__COMPACTION
 */
static CUresult
gpuStoreInvokeCompaction(GpuStoreSharedState *gs_sstate, bool is_async)
{
	return __gpuStoreInvokeBackgroundCommand(gs_sstate->database_oid,
											 gs_sstate->table_oid,
											 gs_sstate->cuda_dindex,
											 is_async,
											 GSTORE_BACKGROUND_CMD__COMPACTION,
											 0);
}


/*
 * gstore_xact_redo_hook
 */
static void
gstore_xact_redo_hook(XLogReaderState *record)
{
	gstore_xact_redo_next(record);
	if (InRecovery)
	{
		//add transaction logs

	}
}

/*
 * gstore_heap_redo_hook
 */
static void
gstore_heap_redo_hook(XLogReaderState *record)
{
	gstore_heap_redo_next(record);
	if (InRecovery)
	{
		//add redo logs
		
	}
}

/*
 * gpuStoreBgWorkerBegin
 */
void
gpuStoreBgWorkerBegin(int cuda_dindex)
{}

/*
 * gpuStoreBgWorkerDispatch
 */
bool
gpuStoreBgWorkerDispatch(int cuda_dindex)
{
	return false;
}

/*
 * gpuStoreBgWorkerIdleTask
 */
bool
gpuStoreBgWorkerIdleTask(int cuda_dindex)
{
	return false;
}

/*
 * gpuStoreBgWorkerEnd
 */
void
gpuStoreBgWorkerEnd(int cuda_dindex)
{}

/*
 * pgstrom_startup_gpu_store
 */
static void
pgstrom_startup_gpu_store(void)
{
	size_t	sz;
	bool	found;
	int		i;

	if (shmem_startup_next)
		(*shmem_startup_next)();

	sz = offsetof(GpuStoreSharedHead, bgworkers[numDevAttrs]);
	gstore_shared_head = ShmemInitStruct("GpuStore Shared Head", sz, &found);
	if (found)
		elog(ERROR, "Bug? GpuStoreSharedHead already exists");
	memset(gstore_shared_head, 0, sz);
	for (i=0; i < GPUSTORE_SHARED_DESC_NSLOTS; i++)
	{
		SpinLockInit(&gstore_shared_head->gstore_sstate_lock[i]);
		dlist_init(&gstore_shared_head->gstore_sstate_slot[i]);
	}
	/* IPC to GPU memory keeper background worker */
	SpinLockInit(&gstore_shared_head->bgworker_cmd_lock);
	dlist_init(&gstore_shared_head->bgworker_free_cmds);
	for (i=0; i < lengthof(gstore_shared_head->__bgworker_cmds); i++)
	{
		GpuStoreBackgroundCommand *cmd;

		cmd = &gstore_shared_head->__bgworker_cmds[i];
		dlist_push_tail(&gstore_shared_head->bgworker_free_cmds,
						&cmd->chain);
	}
	for (i=0; i < numDevAttrs; i++)
	{
		dlist_init(&gstore_shared_head->bgworkers[i].cmd_queue);
	}
}

/*
 * pgstrom_init_gpu_store
 */
void
pgstrom_init_gpu_store(void)
{
	static bool gpustore_auto_preload;
	static bool gpustore_with_replication;
	HASHCTL		hctl;
	BackgroundWorker worker;

	/* GUC: pg_strom.gpustore_auto_preload */
	DefineCustomBoolVariable("pg_strom.gpustore_auto_preload",
							 "Enables auto preload of GPU memory store",
							 NULL,
							 &gpustore_auto_preload,
							 false,
							 PGC_POSTMASTER,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* GPU: pg_strom.gpustore_with_replication */
	DefineCustomBoolVariable("pg_strom.gpustore_with_replication",
							 "Enables to synchronize GPU Store on replication slave",
							 NULL,
							 &gpustore_with_replication,
							 true,
							 PGC_POSTMASTER,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/*
	 * Local hash table for GpuStoreDesc
	 */
	memset(&hctl, 0, sizeof(HASHCTL));
	hctl.keysize    = 2 * sizeof(Oid);
	hctl.entrysize  = sizeof(GpuStoreDesc);
	hctl.hcxt       = CacheMemoryContext;
	gstore_desc_htab = hash_create("GpuStoreDesc Hash-table", 32,
								   &hctl,
								   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	/*
	 * Background worke to load GPU Store on startup
	 */
	if (gpustore_auto_preload)
	{
		memset(&worker, 0, sizeof(BackgroundWorker));
		snprintf(worker.bgw_name, sizeof(worker.bgw_name),
				 "GPU Store Startup Preloader");
		worker.bgw_flags = (BGWORKER_SHMEM_ACCESS |
							BGWORKER_BACKEND_DATABASE_CONNECTION);
		worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
		worker.bgw_restart_time = 1;
		snprintf(worker.bgw_library_name, BGW_MAXLEN,
				 "$libdir/pg_strom");
		snprintf(worker.bgw_function_name, BGW_MAXLEN,
				 "GpuStoreStartupPreloader");
		worker.bgw_main_arg = 0;
		RegisterBackgroundWorker(&worker);
	}

	/*
	 * Add hook for WAL replaying
	 */	
	if (gpustore_with_replication)
	{
		uintptr_t	start = TYPEALIGN_DOWN(PAGE_SIZE, &RmgrTable[0]);
		uintptr_t	end = TYPEALIGN(PAGE_SIZE, &RmgrTable[RM_MAX_ID+1]);
		int			i;

		if (mprotect((void *)start, end - start,
					 PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
		{
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not enable GPU store on replication slave: %m"),
					 errhint("try to turn off pg_strom.gpustore_with_replication")));
		}

		for (i=0; i <= RM_MAX_ID; i++)
		{
			if (strcmp(RmgrTable[i].rm_name, "Transaction") == 0)
			{
				gstore_xact_redo_next = RmgrTable[i].rm_redo;
				*((void **)&RmgrTable[i].rm_redo) = gstore_xact_redo_hook;
			}
			else if (strcmp(RmgrTable[i].rm_name, "Heap") == 0)
			{
				gstore_heap_redo_next = RmgrTable[i].rm_redo;
				*((void **)&RmgrTable[i].rm_redo) = gstore_heap_redo_hook;
			}
		}
		Assert(gstore_xact_redo_next != NULL &&
			   gstore_heap_redo_next != NULL);
	}
	/* request for the static shared memory */
	RequestAddinShmemSpace(STROMALIGN(offsetof(GpuStoreSharedHead,
											   bgworkers[numDevAttrs])));
	shmem_startup_next = shmem_startup_hook;
	shmem_startup_hook = pgstrom_startup_gpu_store;

	/* callback when trigger is dropped */
	object_access_next = object_access_hook;
	object_access_hook = gpuStorePostDeletion;

	/* transaction callbacks */
	RegisterXactCallback(gpuStoreXactCallback, NULL);
	RegisterSubXactCallback(gpuStoreSubXactCallback, NULL);
}
