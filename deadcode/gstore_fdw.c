/*
 * gstore_fdw.c
 *
 * GPU data store based on Apache Arrow and fast updatabled REDO logs.
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
#include "gstore_fdw.h"
#include <libpmem.h>		/* requires libpmem-devel package */

/*
 * GpuStoreBackgroundCommand
 */
#define GSTORE_BACKGROUND_CMD__INITIAL_LOAD		'I'
#define GSTORE_BACKGROUND_CMD__APPLY_REDO		'A'
#define GSTORE_BACKGROUND_CMD__COMPACTION		'C'
#define GSTORE_BACKGROUND_CMD__DROP_UNLOAD		'D'
typedef struct
{
	dlist_node	chain;
	Oid			database_oid;
	Oid			ftable_oid;
	Latch	   *backend;		/* MyLatch of the backend, if any */
	int			command;		/* one of GSTORE_MAINTAIN_CMD__* */
	CUresult	retval;
	uint64		end_pos;		/* for APPLY_REDO */
} GpuStoreBackgroundCommand;

/*
 * GpuStoreSharedHead
 */
#define GPUSTORE_SHARED_DESC_NSLOTS		107
typedef struct
{
	/* Sync object for Row-level Locks */
	ConditionVariable row_lock_cond;
	
	/* Hash slot for GpuStoreSharedState */
	slock_t		gstore_sstate_lock[GPUSTORE_SHARED_DESC_NSLOTS];
	dlist_head	gstore_sstate_slot[GPUSTORE_SHARED_DESC_NSLOTS];

	/* debug counter */
	pg_atomic_uint64 debug_count0;
	pg_atomic_uint64 debug_count1;
	pg_atomic_uint64 debug_count2;
	pg_atomic_uint64 debug_count3;
	pg_atomic_uint64 debug_count4;
	pg_atomic_uint64 debug_count5;
	pg_atomic_uint64 debug_count6;
	pg_atomic_uint64 debug_count7;
	pg_atomic_uint64 debug_count8;
	pg_atomic_uint64 debug_count9;

	/* database name for process */
	int			kicker_database_status;
	char		kicker_database_name[NAMEDATALEN];

	/* IPC to GstoreFdw background worker */
	slock_t		bgworker_cmd_lock;
	dlist_head	bgworker_free_cmds;
	GpuStoreBackgroundCommand __bgworker_cmds[300];
	struct {
		Latch	   *latch;
		dlist_head	cmd_queue;
	} bgworkers[FLEXIBLE_ARRAY_MEMBER];
} GpuStoreSharedHead;

typedef struct
{
	dlist_node		hash_chain;
	Oid				database_oid;
	Oid				ftable_oid;
	uint32			hash;
	/* FDW options */
	cl_int			cuda_dindex;
	ssize_t			max_num_rows;
	ssize_t			num_hash_slots;
	AttrNumber		primary_key;
	bool			preserve_files;
	const char	   *base_file;
	const char	   *redo_log_file;
	size_t			redo_log_limit;
	cl_long			gpu_update_interval;
	size_t			gpu_update_threshold;

#define GSTORE_NUM_BASE_ROW_LOCKS		1000
#define GSTORE_NUM_HASH_SLOT_LOCKS		1200
	/* Runtime state */
	LWLock			base_mmap_lock;
	uint32			base_mmap_revision;
	slock_t			rowid_map_lock;		/* lock for RowID-map */

	/* NOTE: hash_slot_lock must be acquired outside of the base_row_lock */
	slock_t			base_row_lock[GSTORE_NUM_BASE_ROW_LOCKS];
	slock_t			hash_slot_lock[GSTORE_NUM_HASH_SLOT_LOCKS];

	slock_t			redo_pos_lock;
	uint64			redo_write_nitems;
	uint64			redo_write_pos;
	uint64			redo_read_nitems;
	uint64			redo_read_pos;
	volatile uint64	redo_sync_pos;
	uint64			redo_repl_pos[4];		/* under the replication */
	uint64			redo_last_timestamp;	/* time when last command sent.
											 * not a timestamp redo-logs are
											 * applied on the GPU buffer. */
	/* Device data store */
	pthread_rwlock_t gpu_bufer_lock;
	CUipcMemHandle	gpu_main_mhandle;		/* mhandle to main portion */
	CUipcMemHandle	gpu_extra_mhandle;		/* mhandle to extra portion */
	size_t			gpu_main_size;
	size_t			gpu_extra_size;
} GpuStoreSharedState;

typedef struct
{
	Oid				database_oid;
	Oid				ftable_oid;
	TransactionId	xmin_ftable;		/* xid that defines the foreign table */
	TransactionId	xmax_ftable;
	GpuStoreSharedState *gs_sstate;
	dlist_head		gs_undo_logs;		/* list of GpuStoreUndoLogs */
	/* base file mapping */
	GpuStoreBaseFileHead *base_mmap;
	uint32			base_mmap_revision;
	size_t			base_mmap_sz;
	int				base_mmap_is_pmem;
	GpuStoreRowIdMapHead *rowid_map;	/* RowID map section */
	GpuStoreHashIndexHead *hash_index;	/* Hash-index section (optional) */
	/* redo log mapping */
	char		   *redo_mmap;
	size_t			redo_mmap_sz;
	int				redo_mmap_is_pmem;
	/* fields below are valid only GpuStore Maintainer */
	CUdeviceptr		gpu_main_devptr;
	CUdeviceptr		gpu_extra_devptr;
} GpuStoreDesc;

/*
 * GpuStoreFdwState - runtime state object for READ
 */
struct GpuStoreFdwState
{
	GpuStoreDesc   *gs_desc;

	pg_atomic_uint64  __read_pos;
	pg_atomic_uint64 *read_pos;

	Bitmapset	   *referenced;
	cl_bool			sysattr_refs;
	cl_uint			nitems;			/* kds->nitems on BeginScan */
	cl_bool			is_first;
	cl_uint			last_rowid;		/* last rowid returned */
	ExprState	   *indexExprState;
};

/*
 * GpuStoreUndoLogs 
 */
typedef struct
{
	dlist_node		chain;
	TransactionId	curr_xid;
	cl_uint			nitems;
	StringInfoData	buf;
} GpuStoreUndoLogs;

/*
 * GpuStoreFdwModify - runtime state object for WRITE
 */
typedef struct
{
	GpuStoreDesc   *gs_desc;
	Bitmapset	   *updatedCols;
	TransactionId	oldestXmin;
	AttrNumber		ctid_attno;
	GpuStoreUndoLogs *gs_undo;
} GpuStoreFdwModify;

/* ---- static variables ---- */
static FdwRoutine	pgstrom_gstore_fdw_routine;
static GpuStoreSharedHead  *gstore_shared_head = NULL;
static HTAB		   *gstore_desc_htab = NULL;
static shmem_startup_hook_type shmem_startup_next = NULL;
static bool			gstore_fdw_enabled;		/* GUC */
static char		   *gstore_fdw_default_base_dir;	/* GUC */
static char		   *gstore_fdw_default_redo_dir;	/* GUC */
static object_access_hook_type object_access_next = NULL;

/* ---- Forward declarations ---- */
Datum pgstrom_gstore_fdw_handler(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_validator(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_apply_redo(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_compaction(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_post_creation(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_sysattr_in(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_sysattr_out(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_replication_base(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_replication_redo(PG_FUNCTION_ARGS);
Datum pgstrom_gstore_fdw_read_debug(PG_FUNCTION_ARGS);
void  GstoreFdwStartupKicker(Datum arg);
void  GstoreFdwMaintainerMain(Datum arg);

static bool		gstoreFdwRemapBaseFile(GpuStoreDesc *gs_desc,
									   bool abort_on_error);
static GpuStoreDesc *gstoreFdwLookupGpuStoreDesc(Relation frel);
static CUresult	gstoreFdwInvokeInitialLoad(Oid ftable_oid,
										   int cuda_dindex, bool is_async);
static CUresult gstoreFdwInvokeApplyRedo(Oid ftable_oid, uint64 end_pos,
										 int cuda_dindex, bool is_async);
static CUresult gstoreFdwInvokeCompaction(Oid ftable_oid,
										  int cuda_dindex, bool is_async);
static CUresult gstoreFdwInvokeDropUnload(Oid ftable_oid,
										  int cuda_dindex, bool is_async);
static cl_uint	gstoreFdwAllocateRowId(GpuStoreSharedState *gs_sstate,
									   GpuStoreRowIdMapHead *rowid_map);
static void		gstoreFdwReleaseRowId(GpuStoreSharedState *gs_sstate,
									  GpuStoreRowIdMapHead *rowid_map,
									  cl_uint rowid);
static void		gstoreFdwReleaseRowIdMulti(GpuStoreSharedState *gs_sstate,
										   GpuStoreRowIdMapHead *rowid_map,
										   cl_uint rowid, List *unused_rowids);
static bool		gstoreFdwCheckRowId(GpuStoreSharedState *gs_sstate,
									GpuStoreRowIdMapHead *rowid_map,
									cl_uint rowid);
static void		gstoreFdwInsertIntoPrimaryKey(GpuStoreDesc *gs_desc,
											  GpuStoreUndoLogs *gs_undo,
											  cl_uint rowid);
static void		gstoreFdwRemoveFromPrimaryKey(GpuStoreDesc *gs_desc,
											  GpuStoreUndoLogs *gs_undo,
											  cl_uint rowid);

#define __SpinLockAcquire(NUM,LOCK)										\
	do {																\
		struct timespec tp1, tp2;										\
		uint64		diff;												\
																		\
		clock_gettime(CLOCK_MONOTONIC, &tp1);							\
		SpinLockAcquire(LOCK);											\
		clock_gettime(CLOCK_MONOTONIC, &tp2);							\
		diff = ((tp2.tv_sec - tp1.tv_sec) * 1000000000UL +				\
				(tp2.tv_nsec - tp1.tv_nsec));							\
		pg_atomic_add_fetch_u64(&gstore_shared_head->debug_count##NUM, diff); \
	} while(0)

/* ---- Atomic operations ---- */
static inline cl_ulong atomicRead64(volatile cl_ulong *ptr)
{
	return *ptr;
}

static inline cl_bool atomicCAS64(volatile cl_ulong *ptr,
								  cl_ulong *oldval, cl_ulong newval)
{
	return __atomic_compare_exchange_n(ptr, oldval, newval,
									   false,
									   __ATOMIC_SEQ_CST,
									   __ATOMIC_SEQ_CST);
}

static inline cl_ulong atomicMax64(volatile cl_ulong *ptr, cl_ulong newval)
{
	cl_ulong	oldval;

	do {
		oldval = atomicRead64(ptr);
		if (oldval >= newval)
			return oldval;
	} while (!atomicCAS64(ptr, &oldval, newval));

	return newval;
}

static inline cl_ulong atomicRead32(volatile cl_uint *ptr)
{
	return *ptr;
}

static inline cl_bool atomicCAS32(volatile cl_uint *ptr,
                                  cl_uint *oldval, cl_uint newval)
{
	return __atomic_compare_exchange_n(ptr, oldval, newval,
									   false,
									   __ATOMIC_SEQ_CST,
									   __ATOMIC_SEQ_CST);
}

static inline cl_uint atomicMax32(volatile cl_uint *ptr, cl_uint newval)
{
	cl_uint		oldval;

	do {
		oldval = atomicRead32(ptr);
		if (oldval >= newval)
			return oldval;
	} while (!atomicCAS32(ptr, &oldval, newval));

	return newval;
}

/* ---- Lock/unlock rows/hash-slot ---- */
static inline bool
gstoreFdwSpinLockBaseRow(GpuStoreDesc *gs_desc, cl_uint rowid)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	cl_uint		lindex = rowid % GSTORE_NUM_BASE_ROW_LOCKS;

	SpinLockAcquire(&gs_sstate->base_row_lock[lindex]);

	return true;
}

static inline bool
gstoreFdwSpinUnlockBaseRow(GpuStoreDesc *gs_desc, cl_uint rowid)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	cl_uint		lindex = rowid % GSTORE_NUM_BASE_ROW_LOCKS;

	SpinLockRelease(&gs_sstate->base_row_lock[lindex]);

	return false;
}

static inline bool
gstoreFdwSpinLockHashSlot(GpuStoreDesc *gs_desc, Datum hash)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	cl_uint		lindex = hash % GSTORE_NUM_HASH_SLOT_LOCKS;

	SpinLockAcquire(&gs_sstate->hash_slot_lock[lindex]);

	return true;
}

static inline bool
gstoreFdwSpinUnlockHashSlot(GpuStoreDesc *gs_desc, Datum hash)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	cl_uint		lindex = hash % GSTORE_NUM_HASH_SLOT_LOCKS;

	SpinLockRelease(&gs_sstate->hash_slot_lock[lindex]);

	return false;
}

/*
 * baseRelIsGstoreFdw
 */
bool
baseRelIsGstoreFdw(RelOptInfo *baserel)
{
	if ((baserel->reloptkind == RELOPT_BASEREL ||
		 baserel->reloptkind == RELOPT_OTHER_MEMBER_REL) &&
		baserel->rtekind == RTE_RELATION &&
		OidIsValid(baserel->serverid) &&
		baserel->fdwroutine &&
		memcmp(baserel->fdwroutine,
			   &pgstrom_gstore_fdw_routine,
			   sizeof(FdwRoutine)) == 0)
		return true;

	return false;
}

/*
 * RelationIsGstoreFdw
 */
bool
RelationIsGstoreFdw(Relation frel)
{
	if (RelationGetForm(frel)->relkind == RELKIND_FOREIGN_TABLE)
	{
		FdwRoutine *routine = GetFdwRoutineForRelation(frel, false);

		if (memcmp(routine, &pgstrom_gstore_fdw_routine,
				   sizeof(FdwRoutine)) == 0)
			return true;
	}
	return false;
}

static void
GstoreGetForeignRelSize(PlannerInfo *root,
						RelOptInfo *baserel,
						Oid foreigntableid)
{
	Relation	frel;
	GpuStoreDesc *gs_desc;

	frel = table_open(foreigntableid, AccessShareLock);
	gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	table_close(frel, AccessShareLock);

	baserel->tuples = (double) gs_desc->base_mmap->schema.nitems;
	baserel->rows = baserel->tuples *
		clauselist_selectivity(root,
							   baserel->baserestrictinfo,
							   0,
							   JOIN_INNER,
							   NULL);
	baserel->fdw_private = gs_desc;
}

static bool
GstoreIsForeignScanParallelSafe(PlannerInfo *root,
								RelOptInfo *rel,
								RangeTblEntry *rte)
{
	return true;
}

static Node *
match_clause_to_primary_key(PlannerInfo *root,
							RelOptInfo *baserel,
							RestrictInfo *rinfo,
							int primary_key)
{
	OpExpr	   *op = (OpExpr *)rinfo->clause;
	Node	   *left;
	Node	   *right;
	TypeCacheEntry *tcache;

	if (!IsA(op, OpExpr) || list_length(op->args) != 2)
		return false;	/* binary operator */

	left = (Node *) linitial(op->args);
	right = (Node *) lsecond(op->args);
	if (exprType(left) != exprType(right))
		return false;	/* type not compatible */
	tcache = lookup_type_cache(exprType(left),
							   TYPECACHE_EQ_OPR);
	if (tcache->eq_opr != op->opno)
		return false;	/* opno is not equal operator */

	if (IsA(left, RelabelType))
		left = (Node *)((RelabelType *)left)->arg;
	if (IsA(right, RelabelType))
		right = (Node *)((RelabelType *)right)->arg;	
	if (IsA(left, Var))
	{
		Var	   *var = (Var *)left;

		if (var->varno == baserel->relid &&
			var->varattno == primary_key &&
			!bms_is_member(baserel->relid, rinfo->right_relids) &&
			!contain_volatile_functions(right))
		{
			/* Ok, Left-VAR = Right-Expression */
			return right;
		}
	}

	if (IsA(right, Var))
	{
		Var	   *var = (Var *)right;

		if (var->varno == baserel->relid &&
			var->varattno == primary_key &&
			!bms_is_member(baserel->relid, rinfo->left_relids) &&
			!contain_volatile_functions(left))
		{
			/* Ok, Right-Var = Left-Expression */
			return left;
		}
	}
	return NULL;
}

/*
 * GetOptimalGpuForGstoreFdw
 */
int
GetOptimalGpuForGstoreFdw(PlannerInfo *root,
						  RelOptInfo *baserel)
{
	GpuStoreDesc   *gs_desc;
	
	if (!baserel->fdw_private)
	{
		RangeTblEntry *rte = root->simple_rte_array[baserel->relid];

		GstoreGetForeignRelSize(root, baserel, rte->relid);
	}
	gs_desc = baserel->fdw_private;
	return gs_desc->gs_sstate->cuda_dindex;
}

static void
GstoreGetForeignPaths(PlannerInfo *root,
					  RelOptInfo *baserel,
					  Oid foreigntableid)
{
	GpuStoreDesc   *gs_desc = baserel->fdw_private;
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	AttrNumber		primary_key = gs_sstate->primary_key;
	Relids			required_outer = baserel->lateral_relids;
	ParamPathInfo  *param_info;
	ForeignPath	   *fpath;
	ListCell	   *lc;
	Node		   *indexExpr = NULL;
	QualCost		qual_cost;
	Cost			startup_cost = 0.0;
	Cost			run_cost = 0.0;
	double			ntuples = baserel->tuples;

	/* gstore_fdw.enabled */
	if (!gstore_fdw_enabled)
		startup_cost += disable_cost;

	if (primary_key > 0)
	{
		foreach (lc, baserel->baserestrictinfo)
		{
			RestrictInfo   *rinfo = lfirst(lc);

			indexExpr = match_clause_to_primary_key(root,
													baserel,
													rinfo,
													primary_key);
			if (indexExpr)
				break;
		}
	}
	/* simple cost estimation */
	param_info = get_baserel_parampathinfo(root, baserel, required_outer);
	if (param_info)
		cost_qual_eval(&qual_cost, param_info->ppi_clauses, root);
	else
		qual_cost = baserel->baserestrictcost;
	if (indexExpr)
		ntuples = 1.0;
	startup_cost += qual_cost.startup;
	startup_cost += baserel->reltarget->cost.startup;
	run_cost += (cpu_tuple_cost + qual_cost.per_tuple) * ntuples;
	run_cost += baserel->reltarget->cost.per_tuple * baserel->rows;

	fpath = create_foreignscan_path(root,
									baserel,
									NULL,	/* default pathtarget */
									baserel->rows,
									startup_cost,
									startup_cost + run_cost,
									NIL,	/* no pathkeys */
									required_outer,
									NULL,	/* no extra plan */
									list_make1(indexExpr));
	add_path(baserel, (Path *)fpath);
	
	//TODO: parameterized paths
}

/*
 * gstoreCheckVisibilityForRead
 *
 * It checks visibility of row when reader tries to fetch it.
 * Caller must have the spinlock of the row.
 */
static bool
gstoreCheckVisibilityForRead(GpuStoreDesc *gs_desc, cl_uint rowid,
							 Snapshot snapshot,
							 GstoreFdwSysattr *p_sysattr)
{
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	kern_colmeta   *cmeta = &kds->colmeta[kds->ncols - 1];
	GstoreFdwSysattr *sysattr;
	Datum			datum;
	bool			isnull;

	Assert(kds->format == KDS_FORMAT_COLUMN &&
		   kds->ncols >= 1 &&
		   rowid < kds->nrooms);
	datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	Assert(!isnull);
	sysattr = (GstoreFdwSysattr *)DatumGetPointer(datum);
	if (p_sysattr)
		memcpy(p_sysattr, sysattr, sizeof(GstoreFdwSysattr));

	if (sysattr->xmin != FrozenTransactionId)
	{
		if (TransactionIdIsCurrentTransactionId(sysattr->xmin))
		{
			if (sysattr->cid >= snapshot->curcid)
				return false;	/* inserted after scan started */
			if (sysattr->xmax == InvalidTransactionId)
				return true;	/* not deleted yet */
			if (sysattr->xmax == FrozenTransactionId)
				return false;	/* deleted, and committed */
			if (!TransactionIdIsCurrentTransactionId(sysattr->xmax))
				return true;	/* deleted by others, but not committed */
		}
		else if (TransactionIdDidCommit(sysattr->xmin))
		{
			/* inserted, and already committed */
			sysattr->xmin = FrozenTransactionId;
		}
		else if (TransactionIdIsInProgress(sysattr->xmin))
		{
			/* inserted by other session, and not committed */
			return false;
		}
		else
		{
			/* it must be aborted, or crashed */
			sysattr->xmin = InvalidTransactionId;
			return false;
		}
	}
	/* by here, the inserting transaction has committed */
	if (sysattr->xmax == InvalidTransactionId)
		return true;			/* not deleted yet */
	if (sysattr->xmax != FrozenTransactionId)
	{
		if (TransactionIdIsCurrentTransactionId(sysattr->xmax))
		{
			if (sysattr->cid >= snapshot->curcid)
				return true;	/* deleted after scan started */
			else
				return false;	/* deleted before scan started */
		}
		else if (TransactionIdIsInProgress(sysattr->xmax))
		{
			/* removed by other transaction in-progress */
			return true;
		}
		else if (TransactionIdDidCommit(sysattr->xmax))
		{
			/* transaction that removed this row has been committed */
			sysattr->xmax = FrozenTransactionId;
		}
		else
		{
			/* deleter is aborted or crashed */
			sysattr->xmax = InvalidTransactionId;
		}
	}
	/* deleted, and transaction committed */
	return false;
}

/*
 * gstoreCheckVisibilityForInsert
 */
static bool
gstoreCheckVisibilityForInsert(GpuStoreDesc *gs_desc, cl_uint rowid,
							   TransactionId oldestXmin)
{
	/* see logic in HeapTupleSatisfiesVacuum */
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	kern_colmeta   *cmeta = &kds->colmeta[kds->ncols - 1];
	GstoreFdwSysattr *sysattr;
	Datum			datum;
	bool			isnull;	

	datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	Assert(!isnull);
	sysattr = (GstoreFdwSysattr *)DatumGetPointer(datum);

	if (sysattr->xmin != FrozenTransactionId)
	{
		if (sysattr->xmin == InvalidTransactionId)
			return true;	/* not written yet */
		else if (TransactionIdIsCurrentTransactionId(sysattr->xmin))
			return false;	/* already inserted by itself */
		else if (TransactionIdIsInProgress(sysattr->xmin))
			return false;	/* inserted by other, but not committed yet */
		else if (TransactionIdDidCommit(sysattr->xmin))
			sysattr->xmin = FrozenTransactionId;	/* already committed */
		else
		{
			/* not in progress, not committed, so either aborted or crashed */
			sysattr->xmin = InvalidTransactionId;
			return true;
		}
	}
	/* Ok, INSERT is commited */
	if (sysattr->xmax == InvalidTransactionId)
		return false;		/* row still lives */
	if (sysattr->xmax != FrozenTransactionId)
	{
		if (TransactionIdIsInProgress(sysattr->xmax))
			return false;	/* DELETE is in progress, so find another one */
		else if (TransactionIdDidCommit(sysattr->xmax))
		{
			/*
			 * Deleter committed, but perhaps it was recent enough that some
			 * open transactions could still see the tuple.
			 */
			if (!TransactionIdPrecedes(sysattr->xmax, oldestXmin))
				return false;
			sysattr->xmax = FrozenTransactionId;
		}
		else
		{
			/* not in progress, not committed, so either aborted or crashed */
			sysattr->xmax = InvalidTransactionId;
			return false;
		}
	}
	return true;	/* completely dead, and removable */
}

/*
 * gstoreCheckVisibilityTryDelete
 *
 * it checks visibility and mark 'deleted' if possible
 */
static int
__gstoreCheckVisibilityTryDelete(GpuStoreDesc *gs_desc, cl_uint rowid,
								 TransactionId curr_xid,
								 GstoreFdwSysattr *sysattr)
{
	if (sysattr->xmin != FrozenTransactionId)
	{
		if (sysattr->xmin == InvalidTransactionId)
		{
			elog(WARNING, "tried to update/delete xmin=Invalid at rowid=%u", rowid);
			return 0;		/* not written */
		}
		else if (TransactionIdIsCurrentTransactionId(sysattr->xmin))
		{
			if (sysattr->xmax == InvalidTransactionId)
			{
				sysattr->xmax = curr_xid;
				sysattr->cid  = GetCurrentCommandId(true);
				return 1;
			}
			else if (TransactionIdIsCurrentTransactionId(sysattr->xmax))
			{
				elog(WARNING, "tried to update/remove a row already removed by itself at rowid=%u", rowid);
				return 0;
			}
			else
			{
				/* not in progress, not committed, so either aborted or crashed */
				Assert(sysattr->xmax != FrozenTransactionId &&
					   !TransactionIdDidCommit(sysattr->xmax));
				sysattr->xmax = curr_xid;
				sysattr->cid = GetCurrentCommandId(true);
				return 1;
			}
		}
		else if (TransactionIdIsInProgress(sysattr->xmin))
		{
			return -1;		/* inserted by others, but not committed yet */
		}
		else if (TransactionIdDidCommit(sysattr->xmin))
		{
			sysattr->xmin = FrozenTransactionId;
		}
		else
		{
			/* not in progress, not committed, so either aborted or crashed */
			sysattr->xmin = InvalidTransactionId;
			return 0;
		}
	}
	/* Ok, the row is committed */
	if (sysattr->xmax == InvalidTransactionId)
	{
		sysattr->xmax = curr_xid;
		sysattr->cid = GetCurrentCommandId(true);
		return 1;
	}
	if (sysattr->xmax != FrozenTransactionId)
	{
		if (TransactionIdIsCurrentTransactionId(sysattr->xmax))
		{
			elog(WARNING, "tried to update/delete a row already removed by itself, at rowid=%u", rowid);
			return 0;
		}
		else if (TransactionIdIsInProgress(sysattr->xmax))
		{
			/* concurrent transaction removed, but not committed yet */
			return -1;
		}
		else if (!TransactionIdDidCommit(sysattr->xmax))
		{
			/* not in progress, not committed, so either aborted or crashed */
			sysattr->xmax = curr_xid;
			sysattr->cid = GetCurrentCommandId(true);
			return 1;
		}
	}
	return 0;		/* already removed */
}

static int
gstoreCheckVisibilityTryDelete(GpuStoreDesc *gs_desc, cl_uint rowid,
                               TransactionId curr_xid,
                               GstoreFdwSysattr *p_sysattr)
{
    /* see logic in HeapTupleSatisfiesVacuum */
    kern_data_store *kds = &gs_desc->base_mmap->schema;
    kern_colmeta   *cmeta = &kds->colmeta[kds->ncols - 1];
    GstoreFdwSysattr *sysattr;
    Datum           datum;
    bool            isnull;
	int				rv;

	datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
    Assert(!isnull);
    sysattr = (GstoreFdwSysattr *)DatumGetPointer(datum);
	rv = __gstoreCheckVisibilityTryDelete(gs_desc, rowid, curr_xid, sysattr);
	if (p_sysattr)
		memcpy(p_sysattr, sysattr, sizeof(GstoreFdwSysattr));
	return rv;
}

/*
 * gstoreCheckVisibilityForIndex
 *
 * It checks row's visibility on the primary-key duplication checks.
 * Caller must not hold any row-spinlock.
 * It returns positive (1) for visible, zero for invisible, or -1 for pending to
 * update/delete. If -1 is returned, caller must wait for commit/abort of the
 * blocker transaction, then retry violation checks.
 */
static int
__gstoreCheckVisibilityForIndexNoLock(GpuStoreDesc *gs_desc, cl_uint rowid)
{
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	kern_colmeta   *cmeta = &kds->colmeta[kds->ncols - 1];
	GstoreFdwSysattr *sysattr;
	Datum			datum;
	bool			isnull;	

	datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	Assert(!isnull);
	sysattr = (GstoreFdwSysattr *)DatumGetPointer(datum);

	if (sysattr->xmin != FrozenTransactionId)
	{
		if (sysattr->xmin == InvalidTransactionId)
		{
			/* row is not written yet, but on the index. corruption? */
			elog(WARNING, "index corruption? rowid=%u has xmin=Invalid", rowid);
			return 0;
		}
		else if (TransactionIdIsCurrentTransactionId(sysattr->xmin))
		{
			if (sysattr->xmax == InvalidTransactionId)
				return 1;	/* not deleted yet */
			if (sysattr->xmax == FrozenTransactionId)
				return 0;	/* deleted, and committed */
			if (!TransactionIdIsCurrentTransactionId(sysattr->xmax))
				return -1;	/* deleted in other transaction, but not commited.
							 * so, caller shall be blocked by row-lock. */
		}
		else if (TransactionIdIsInProgress(sysattr->xmin))
		{
			/* inserted by the concurrent transaction; must be blocked */
			return -1;
		}
		else if (!TransactionIdDidCommit(sysattr->xmin))
		{
			/* not in progress, not committed, so either aborted or crashed */
			return 0;
		}
	}
	/* Ok, row is inserted and committed */
	if (sysattr->xmax == InvalidTransactionId)
		return 1;		/* row still lives */
	if (sysattr->xmax != FrozenTransactionId)
	{
		if (TransactionIdIsCurrentTransactionId(sysattr->xmax))
		{
			/*
			 * deleted by the current transaction. it should be invisible
			 * for primary key checks, regardless of the command-id.
			 */
			return 0;
		}
		else if (TransactionIdIsInProgress(sysattr->xmax))
		{
			/* removed by other transaction, but not committed yet */
			return -1;
		}
		else if (TransactionIdDidCommit(sysattr->xmax))
		{
			/* deleter is already committed */
			return 0;
		}
		else
		{
			/* deleter is aborted or crashed */
			return 1;
		}
	}
	return 0;	/* completely dead, and removable */
}

static int
gstoreCheckVisibilityForIndex(GpuStoreDesc *gs_desc, cl_uint rowid)
{
	int		retval;

	gstoreFdwSpinLockBaseRow(gs_desc, rowid);
	PG_TRY();
	{
		retval = __gstoreCheckVisibilityForIndexNoLock(gs_desc, rowid);
	}
	PG_CATCH();
	{
		gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
		PG_RE_THROW();
	}
	PG_END_TRY();
	gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);

	return retval;
}



static ForeignScan *
GstoreGetForeignPlan(PlannerInfo *root,
					 RelOptInfo *baserel,
					 Oid foreigntableid,
					 ForeignPath *best_path,
					 List *tlist,
					 List *scan_clauses,
					 Plan *outer_plan)
{
	Bitmapset  *referenced = NULL;
	List	   *outer_refs = NIL;
	List	   *scan_tlist = baserel->reltarget->exprs;
	int			j, k;

	/* pick up referenced columns */
	scan_clauses = extract_actual_clauses(scan_clauses, false);
	pull_varattnos((Node *)scan_tlist, baserel->relid, &referenced);
	pull_varattnos((Node *)scan_clauses, baserel->relid, &referenced);
	for (j = bms_next_member(referenced, -1);
		 j >= 0;
		 j = bms_next_member(referenced, j))
	{
		k = j + FirstLowInvalidHeapAttributeNumber;
		outer_refs = lappend_int(outer_refs, k);
	}
	return make_foreignscan(tlist,
							scan_clauses,
							baserel->relid,
							best_path->fdw_private,	/* indexExpr */
							outer_refs,	/* referenced attnums */
							NIL,		/* no custom tlist */
							NIL,		/* no remote quals */
							outer_plan);
}

static CUresult
gstoreFdwApplyRedoDeviceBuffer(GpuStoreSharedState *gs_sstate)
{
	size_t		end_pos;

	/* see  __gstoreFdwAppendRedoLog */
	SpinLockAcquire(&gs_sstate->redo_pos_lock);
	end_pos = gs_sstate->redo_write_pos;
	SpinLockRelease(&gs_sstate->redo_pos_lock);

	return gstoreFdwInvokeApplyRedo(gs_sstate->ftable_oid, end_pos,
									gs_sstate->cuda_dindex, false);
}

static GpuStoreFdwState *
__ExecInitGstoreFdw(ScanState *ss, Bitmapset *outer_refs, Expr *indexExpr,
					bool apply_redo_log)
{
	Relation		frel = ss->ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(frel);
	GpuStoreFdwState *fdw_state = palloc0(sizeof(GpuStoreFdwState));
	GpuStoreDesc   *gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	Bitmapset	   *referenced = NULL;
	int				j, k;

	for (j = bms_next_member(outer_refs, -1);
		 j >= 0;
		 j = bms_next_member(outer_refs, j))
	{
		int		anum = j + FirstLowInvalidHeapAttributeNumber;

		if (anum < 0)
		{
#if PG_VERSION_NUM >= 120000
			/*
			 * PG12 adds tts_tid to carry ItemPointer without forming
			 * a HeapTuple; an optimization of TupleTableSlot.
			 */
			if (anum != SelfItemPointerAttributeNumber)
				fdw_state->sysattr_refs = true;
#else
			fdw_state->sysattr_refs = true;
#endif
		}
		else if (anum == 0)
		{
			for (k=0; k < tupdesc->natts; k++)
			{
				Form_pg_attribute attr = tupleDescAttr(tupdesc,k);

				if (attr->attisdropped)
					continue;
				referenced = bms_add_member(referenced, attr->attnum -
											FirstLowInvalidHeapAttributeNumber);
			}
		}
		else
		{
			referenced = bms_add_member(referenced, anum -
										FirstLowInvalidHeapAttributeNumber);
        }
	}
	
	/* setup GpuStoreExecState */
	fdw_state->gs_desc = gs_desc;
	pg_atomic_init_u64(&fdw_state->__read_pos, 0);
	fdw_state->read_pos = &fdw_state->__read_pos;
	fdw_state->nitems = gs_desc->base_mmap->schema.nitems;
	fdw_state->last_rowid = UINT_MAX;
	fdw_state->is_first = true;
	fdw_state->referenced = referenced;
	if (indexExpr != NULL)
		fdw_state->indexExprState = ExecInitExpr(indexExpr, &ss->ps);
	/* synchronize device buffer prior to the kernel call */
	if (apply_redo_log)
		gstoreFdwApplyRedoDeviceBuffer(gs_desc->gs_sstate);

	return fdw_state;
}

GpuStoreFdwState *
ExecInitGstoreFdw(ScanState *ss, int eflags,
				  Bitmapset *outer_refs)
{
	bool	apply_redo_log = ((eflags & EXEC_FLAG_EXPLAIN_ONLY) == 0);

	return __ExecInitGstoreFdw(ss, outer_refs, NULL, apply_redo_log);
}

static void
GstoreBeginForeignScan(ForeignScanState *node, int eflags)
{
	ForeignScan	   *fscan = (ForeignScan *)node->ss.ps.plan;
	Bitmapset	   *outer_refs = NULL;
	Expr		   *indexExpr = NULL;
	ListCell	   *lc;

	foreach (lc, fscan->fdw_private)
	{
		int		anum = lfirst_int(lc);

		outer_refs = bms_add_member(outer_refs, anum -
									FirstLowInvalidHeapAttributeNumber);
	}

	if (fscan->fdw_exprs != NIL)
		indexExpr = linitial(fscan->fdw_exprs);

	node->fdw_state = __ExecInitGstoreFdw(&node->ss, outer_refs, indexExpr, false);
}

/*
 * ExecScanChunkGstoreFdw
 */
pgstrom_data_store *
ExecScanChunkGstoreFdw(GpuTaskState *gts)
{
	Relation		frel = gts->css.ss.ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(frel);
	GpuStoreFdwState *fdw_state = gts->gs_state;
	pgstrom_data_store *pds = NULL;

	if (pg_atomic_fetch_add_u64(fdw_state->read_pos, 1) == 0)
	{
		EState		   *estate = gts->css.ss.ps.state;
		GpuStoreDesc   *gs_desc = fdw_state->gs_desc;
		GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
		size_t			sz = KDS_calculateHeadSize(tupdesc);

		pds = MemoryContextAllocZero(estate->es_query_cxt,
									 offsetof(pgstrom_data_store, kds) + sz);
		pg_atomic_init_u32(&pds->refcnt, 1);
		pds->gs_sstate = gs_sstate;
		init_kernel_data_store(&pds->kds, tupdesc, sz, KDS_FORMAT_COLUMN, 0);
	}
	return pds;
}

/*
 * gstoreFdwMapDeviceMemory
 */
CUresult
gstoreFdwMapDeviceMemory(GpuContext *gcontext, pgstrom_data_store *pds)
{
	GpuStoreSharedState *gs_sstate = pds->gs_sstate;
	CUdeviceptr	m_kds_base = 0UL;
	CUdeviceptr	m_kds_extra = 0UL;
	CUresult	rc;

	Assert(pds->kds.format == KDS_FORMAT_COLUMN);
	pthreadRWLockReadLock(&gs_sstate->gpu_bufer_lock);
	if (gs_sstate->gpu_main_size > 0)
	{
		rc = gpuIpcOpenMemHandle(gcontext,
								 &m_kds_base,
								 gs_sstate->gpu_main_mhandle,
								 CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		if (rc != CUDA_SUCCESS)
			goto error_1;
	}

	if (gs_sstate->gpu_extra_size > 0)
	{
		rc = gpuIpcOpenMemHandle(gcontext,
								 &m_kds_extra,
								 gs_sstate->gpu_extra_mhandle,
								 CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		if (rc != CUDA_SUCCESS)
			goto error_2;
	}
	pds->m_kds_base = m_kds_base;
	pds->m_kds_extra = m_kds_extra;

	return CUDA_SUCCESS;

error_2:
	gpuIpcCloseMemHandle(gcontext, m_kds_base);
error_1:
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);
	return rc;
}

void
gstoreFdwUnmapDeviceMemory(GpuContext *gcontext, pgstrom_data_store *pds)
{
	GpuStoreSharedState *gs_sstate = pds->gs_sstate;

	Assert(pds->kds.format == KDS_FORMAT_COLUMN);
	if (pds->m_kds_base != 0UL)
	{
		gpuIpcCloseMemHandle(gcontext, pds->m_kds_base);
		pds->m_kds_base = 0UL;
	}
	if (pds->m_kds_extra != 0UL)
	{
		gpuIpcCloseMemHandle(gcontext, pds->m_kds_extra);
		pds->m_kds_extra = 0UL;
	}
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);
}

/*
 * GstoreIterateForeignScan
 */
static TupleTableSlot *
__gstoreFillupTupleTableSlot(TupleTableSlot *slot,
							 GpuStoreDesc *gs_desc,
							 cl_uint rowid,
							 GstoreFdwSysattr *sysattr,
							 GpuStoreFdwState *fdw_state)
{
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	Datum		datum;
	bool		isnull;
	int			j;

	/* user defined attributes are immutable out of the row-spinlock */
	Assert(tupdesc->natts == kds->ncols - 1);
	for (j=0; j < tupdesc->natts; j++)
	{
		int		k = j + 1 - FirstLowInvalidHeapAttributeNumber;

		if (!bms_is_member(k, fdw_state->referenced))
		{
			slot->tts_values[j] = 0;
			slot->tts_isnull[j] = true;
		}
		else
		{
			kern_colmeta *cmeta = &kds->colmeta[j];
			
			datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
			slot->tts_values[j] = datum;
			slot->tts_isnull[j] = isnull;
		}
	}
	ExecStoreVirtualTuple(slot);
	/*
	 * PG12 modified the definition of TupleTableSlot; it allows to carry
	 * ctid (32bit row-id in Gstore_Fdw) in the virtual-tuple form.
	 * 'sysattr_refs' is only set if any system-columns are referenced,
	 * except for the SelfItemPointer in PG12.
	 */
#if PG_VERSION_NUM >= 120000
	slot->tts_tid.ip_blkid.bi_hi = (rowid >> 16);
	slot->tts_tid.ip_blkid.bi_lo = (rowid & 0x0000ffffU);
	slot->tts_tid.ip_posid       = 0;
#endif
	if (fdw_state->sysattr_refs)
	{
		HeapTuple	tuple = heap_form_tuple(tupdesc,
											slot->tts_values,
											slot->tts_isnull);
		HeapTupleHeaderSetXmin(tuple->t_data, sysattr->xmin);
		HeapTupleHeaderSetXmax(tuple->t_data, sysattr->xmax);
		HeapTupleHeaderSetCmin(tuple->t_data, sysattr->cid);
		tuple->t_self.ip_blkid.bi_hi = (rowid >> 16);
		tuple->t_self.ip_blkid.bi_lo = (rowid & 0x0000ffff);
		tuple->t_self.ip_posid       = 0;

		ExecForceStoreHeapTuple(tuple, slot, false);
	}
	return slot;
}

static TupleTableSlot *
__gstoreIterateForeignIndexScan(ForeignScanState *node)
{
	Relation		frel __attribute__((unused))
		= node->ss.ss_currentRelation;
	EState		   *estate = node->ss.ps.state;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	GpuStoreFdwState *fdw_state = node->fdw_state;
	GpuStoreDesc   *gs_desc = fdw_state->gs_desc;
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	GpuStoreHashIndexHead *hash_index = gs_desc->hash_index;
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	kern_colmeta *cmeta = &kds->colmeta[gs_sstate->primary_key - 1];
	cl_uint		   *rowmap;
	TypeCacheEntry *tcache;
	cl_uint			rowid = UINT_MAX;
	Datum			kdatum;
	Datum			vdatum;
	Datum			hash;
	bool			isnull;
	GstoreFdwSysattr sysattr;

	Assert(hash_index != NULL &&
		   gs_sstate->primary_key > 0 &&
		   gs_sstate->primary_key <= RelationGetNumberOfAttributes(frel));
	if (pg_atomic_fetch_add_u64(fdw_state->read_pos, 1) > 0)
		return NULL;
	rowmap = &hash_index->slots[hash_index->nslots];
		
	/* extract the key value */
	kdatum = ExecEvalExpr(fdw_state->indexExprState,
						  node->ss.ps.ps_ExprContext,
						  &isnull);
	if (isnull)
		return NULL;
	/* calculation of hash-value */
	tcache = lookup_type_cache(cmeta->atttypid,
							   TYPECACHE_HASH_PROC_FINFO |
							   TYPECACHE_EQ_OPR_FINFO);
	hash = FunctionCall1(&tcache->hash_proc_finfo, kdatum);

	/* walk on the hash-table */
	gstoreFdwSpinLockHashSlot(gs_desc, hash);
	PG_TRY();
	{
		GstoreFdwSysattr __sysattr;
		cl_uint		curr_id;

		curr_id = hash_index->slots[hash % hash_index->nslots];
		while (curr_id < hash_index->nrooms)
		{
			gstoreFdwSpinLockBaseRow(gs_desc, curr_id);
			PG_TRY();
			{
				if (gstoreCheckVisibilityForRead(gs_desc, curr_id,
												 estate->es_snapshot,
												 &__sysattr))
				{
					vdatum = KDS_fetch_datum_column(kds, cmeta,
													curr_id,
													&isnull);
					if (!isnull && FunctionCall2(&tcache->eq_opr_finfo,
												 kdatum, vdatum))
					{
						if (rowid != UINT_MAX)
							elog(ERROR, "index corruption? duplicate primary key");
						rowid = curr_id;
						sysattr = __sysattr;
					}
				}
			}
			PG_CATCH();
			{
				gstoreFdwSpinUnlockBaseRow(gs_desc, curr_id);
				PG_RE_THROW();
			}
			PG_END_TRY();
			gstoreFdwSpinUnlockBaseRow(gs_desc, curr_id);

			curr_id = rowmap[curr_id];
		}
	}
	PG_CATCH();
	{
		gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
		PG_RE_THROW();
	}
	PG_END_TRY();
	gstoreFdwSpinUnlockHashSlot(gs_desc, hash);

	if (rowid == UINT_MAX)
		return NULL;	/* not found */

	return __gstoreFillupTupleTableSlot(slot, gs_desc,
										rowid, &sysattr,
										fdw_state);
}

static TupleTableSlot *
__gstoreIterateForeignSeqScan(ForeignScanState *node)
{
	Relation		frel __attribute__((unused))
		= node->ss.ss_currentRelation;
	EState		   *estate = node->ss.ps.state;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	GpuStoreFdwState *fdw_state = node->fdw_state;
	GpuStoreDesc   *gs_desc = fdw_state->gs_desc;
	kern_data_store *kds __attribute__((unused)) = &gs_desc->base_mmap->schema;
	cl_uint			rowid;
	bool			visible;
	GstoreFdwSysattr sysattr;

	Assert(RelationGetNumberOfAttributes(frel) + 1 == kds->ncols);
	do {
		rowid = pg_atomic_fetch_add_u64(fdw_state->read_pos, 1);
		if (rowid >= fdw_state->nitems)
			return NULL;
		gstoreFdwSpinLockBaseRow(gs_desc, rowid);
		visible = gstoreCheckVisibilityForRead(gs_desc, rowid,
											   estate->es_snapshot,
											   &sysattr);
		gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
	} while (!visible);

	return __gstoreFillupTupleTableSlot(slot, gs_desc,
										rowid, &sysattr,
										fdw_state);
}

static TupleTableSlot *
GstoreIterateForeignScan(ForeignScanState *node)
{
	GpuStoreFdwState *fdw_state = node->fdw_state;

	ExecClearTuple(node->ss.ss_ScanTupleSlot);
	if (fdw_state->indexExprState)
		return __gstoreIterateForeignIndexScan(node);
	else
		return __gstoreIterateForeignSeqScan(node);
}

void
ExecReScanGstoreFdw(GpuStoreFdwState *fdw_state)
{
	pg_atomic_write_u64(fdw_state->read_pos, 0);
}

static void
GstoreReScanForeignScan(ForeignScanState *node)
{
	ExecReScanGstoreFdw((GpuStoreFdwState *)node->fdw_state);
}

void
ExecEndGstoreFdw(GpuStoreFdwState *fdw_state)
{
	/* nothing to do */
}

static void
GstoreEndForeignScan(ForeignScanState *node)
{
	ExecEndGstoreFdw((GpuStoreFdwState *)node->fdw_state);
}

/*
 * NOTE: Right now, gstore_fdw does not support CPU parallel because
 *       it makes little sense. So, routines below are just dummy.
 */
Size
ExecEstimateDSMGstoreFdw(GpuStoreFdwState *fdw_state)
{
	return MAXALIGN(sizeof(pg_atomic_uint64));
}

void
ExecInitDSMGstoreFdw(GpuStoreFdwState *fdw_state,
					 pg_atomic_uint64 *gstore_read_pos)
{
	pg_atomic_write_u64(gstore_read_pos, 0);
	fdw_state->read_pos = gstore_read_pos;
}

void
ExecReInitDSMGstoreFdw(GpuStoreFdwState *fdw_state)
{
	pg_atomic_write_u64(fdw_state->read_pos, 0);
}

void
ExecInitWorkerGstoreFdw(GpuStoreFdwState *fdw_state,
						pg_atomic_uint64 *gstore_read_pos)
{
	fdw_state->read_pos = gstore_read_pos;
}

void
ExecShutdownGstoreFdw(GpuStoreFdwState *fdw_state)
{
	/* nothing to do */
}

static uint64
__gstoreFdwAppendRedoLog(GpuStoreDesc *gs_desc,
						 GstoreTxLogCommon *tx_log)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	size_t		required = tx_log->length + sizeof(uint32);
	uint64		written_pos = 0;
	bool		has_base_mmap_lock = false;

	Assert(tx_log->length == MAXALIGN(tx_log->length));
	if (required > gs_sstate->redo_log_limit)
		elog(ERROR, "gstore_fdw: length of REDO must be larger than 'redo_log_limit'");
	for (;;)
	{
		char	   *dest_ptr;
		size_t		dest_pos;
		size_t		len;

		SpinLockAcquire(&gs_sstate->redo_pos_lock);
		Assert(gs_sstate->redo_write_pos >= gs_sstate->redo_read_pos);
		/*
		 * If this redo-log makes the write position rewound, we must ensure
		 * the base_mmap is up-to-date prior to the overwrites of redo-log
		 * buffer.
		 */
		dest_pos = gs_sstate->redo_write_pos % gs_sstate->redo_log_limit;
		if (dest_pos + required > gs_sstate->redo_log_limit)
		{
			struct timeval	tv1, tv2;

			if (!has_base_mmap_lock)
			{
				SpinLockRelease(&gs_sstate->redo_pos_lock);

				LWLockAcquire(&gs_sstate->base_mmap_lock, LW_SHARED);
				if (gs_desc->base_mmap_revision != gs_sstate->base_mmap_revision)
					gstoreFdwRemapBaseFile(gs_desc, true);
				has_base_mmap_lock = true;
				continue;
			}
			len = gs_sstate->redo_log_limit - dest_pos;
			memset(gs_desc->redo_mmap + dest_pos, 0, len);
			gs_sstate->redo_write_pos += len;

			/* checkpoint of the base file */
			gettimeofday(&tv1, NULL);
			if (gs_desc->base_mmap_is_pmem)
				pmem_persist(gs_desc->base_mmap,
							 gs_desc->base_mmap_sz);
			else if (pmem_msync(gs_desc->base_mmap,
								gs_desc->base_mmap_sz) != 0)
			{
				elog(WARNING, "failed on pmem_msync('%s'): %m", gs_sstate->base_file);
			}
			gettimeofday(&tv2, NULL);

			elog(LOG, "gstore_fdw: checkpoint applied on '%s' [%.2fms]",
				 gs_sstate->base_file, TV_DIFF(tv2,tv1));
			dest_pos = 0;
		}

		len = gs_sstate->redo_write_pos - gs_sstate->redo_read_pos;
		if (len + required > gs_sstate->redo_log_limit)
		{
			/*
			 * We have no space to write out redo-log any more, so we must
			 * kick the background worker to apply redo-log, and wait for
			 * completion of the task.
			 * If redo_last_timestamp is very recently updated, concurrent
			 * session might kick APPLY_REDO command. In this case, we just
			 * sleep for a moment, and recheck it.
			 */
			uint64	curr_timestamp = GetCurrentTimestamp();
			uint64	last_timestamp = gs_sstate->redo_last_timestamp;

			if (curr_timestamp < last_timestamp + 20000)	/* 20ms margin */
			{
				SpinLockRelease(&gs_sstate->redo_pos_lock);
				pg_usleep(4000L);	/* wait for 4ms */
			}
			else
			{
				uint64		end_pos = gs_sstate->redo_write_pos;
				gs_sstate->redo_last_timestamp = curr_timestamp;
				SpinLockRelease(&gs_sstate->redo_pos_lock);
				gstoreFdwInvokeApplyRedo(gs_sstate->ftable_oid, end_pos,
										 gs_sstate->cuda_dindex, false);
			}
			continue;
		}
		/* Ok, we have enough space to write out redo-log buffer */
		if (len > gs_sstate->gpu_update_threshold)
		{
			uint64	curr_timestamp = GetCurrentTimestamp();
			uint64	last_timestamp = gs_sstate->redo_last_timestamp;

			if (curr_timestamp >= last_timestamp + 20000)	/* 20ms margin */
			{
				/*
				 * Even though redo-log buffer has space to write out, amount of
				 * logs not applied yet exceeds the threshold to kick the baclground
				 * worker, but to be asynchronous.
				 */
				uint64		end_pos = gs_sstate->redo_write_pos;
				gs_sstate->redo_last_timestamp = curr_timestamp;
				gstoreFdwInvokeApplyRedo(gs_sstate->ftable_oid, end_pos,
										 gs_sstate->cuda_dindex, true);
			}
		}
		dest_ptr = gs_desc->redo_mmap + dest_pos;
		gs_sstate->redo_write_pos += tx_log->length;
		gs_sstate->redo_write_nitems++;
		memcpy(dest_ptr, tx_log, tx_log->length);
		written_pos = gs_sstate->redo_write_pos;
		SpinLockRelease(&gs_sstate->redo_pos_lock);
		break;
	}
	if (has_base_mmap_lock)
		LWLockRelease(&gs_sstate->base_mmap_lock);
	return written_pos;
}

static void
gstoreFdwAppendInsertLog(Relation frel,
						 GpuStoreDesc *gs_desc,
						 cl_uint rowid,
						 cl_uint oldid,		/* UINT_MAX, if INSERT */
						 TransactionId xmin,
						 HeapTuple tuple)
{
	GstoreTxLogInsert *i_log;
	size_t		sz;

	sz = MAXALIGN(offsetof(GstoreTxLogInsert, htup) + tuple->t_len);
	i_log = alloca(sz + sizeof(cl_uint));
	memset(i_log, 0, sz + sizeof(cl_uint));
	i_log->type = GSTORE_TX_LOG__INSERT;
	i_log->length = sz;
	i_log->timestamp = GetCurrentTimestamp();
	i_log->rowid = rowid;
	memcpy(&i_log->htup, tuple->t_data, tuple->t_len);
	HeapTupleHeaderSetXmin(&i_log->htup, xmin);
	HeapTupleHeaderSetXmax(&i_log->htup, InvalidTransactionId);
	HeapTupleHeaderSetCmin(&i_log->htup, InvalidCommandId);
	i_log->htup.t_ctid.ip_blkid.bi_hi = (oldid >> 16);
	i_log->htup.t_ctid.ip_blkid.bi_lo = (oldid & 0x0000ffffU);
	i_log->htup.t_ctid.ip_posid = 0;

	__gstoreFdwAppendRedoLog(gs_desc, (GstoreTxLogCommon *)i_log);
}

static void
gstoreFdwAppendDeleteLog(Relation frel,
						 GpuStoreDesc *gs_desc,
						 cl_uint rowid,
						 TransactionId xmin,
						 TransactionId xmax)
{
	GstoreTxLogDelete d_log;

	memset(&d_log, 0, sizeof(GstoreTxLogDelete));
	d_log.type = GSTORE_TX_LOG__DELETE;
	d_log.length = MAXALIGN(sizeof(GstoreTxLogDelete));
	d_log.timestamp = GetCurrentTimestamp();
	d_log.rowid = rowid;
	d_log.xmin = xmin;
	d_log.xmax = xmax;

	__gstoreFdwAppendRedoLog(gs_desc, (GstoreTxLogCommon *)&d_log);
}

static GpuStoreUndoLogs *
gstoreFdwLookupUndoLogs(GpuStoreDesc *gs_desc)
{
	TransactionId	curr_xid = GetCurrentTransactionId();
	dlist_iter		iter;
	GpuStoreUndoLogs *gs_undo;
	MemoryContext	oldcxt;

	dlist_foreach(iter, &gs_desc->gs_undo_logs)
	{
		gs_undo = dlist_container(GpuStoreUndoLogs, chain, iter.cur);
		if (gs_undo->curr_xid == curr_xid)
			return gs_undo;
	}
	/* construct a new one */
	oldcxt = MemoryContextSwitchTo(CacheMemoryContext);
	gs_undo = palloc0(sizeof(GpuStoreUndoLogs));
	gs_undo->curr_xid = curr_xid;
	gs_undo->nitems = 0;
	initStringInfo(&gs_undo->buf);
	MemoryContextSwitchTo(oldcxt);

	dlist_push_head(&gs_desc->gs_undo_logs,
					&gs_undo->chain);
	return gs_undo;
}

static void
GstoreAddForeignUpdateTargets(Query *parsetree,
							  RangeTblEntry *target_rte,
							  Relation target_relation)
{
	TargetEntry *tle;
	Var	   *var;

	/*
	 * Gstore_Fdw carries rowid, using ctid system column
	 */
	var = makeVar(parsetree->resultRelation,
				  SelfItemPointerAttributeNumber,
				  TIDOID,
				  -1,
				  InvalidOid,
				  0);
	tle = makeTargetEntry((Expr *)var,
						  list_length(parsetree->targetList) + 1,
						  pstrdup("ctid"),
						  true);
	parsetree->targetList = lappend(parsetree->targetList, tle);
}

static List *
GstorePlanForeignModify(PlannerInfo *root,
						ModifyTable *plan,
						Index resultRelation,
						int subplan_index)
{
	RangeTblEntry *rte = planner_rt_fetch(resultRelation, root);
	List	   *updatedColsList = NIL;
	int			j = -1;

	while ((j = bms_next_member(rte->updatedCols, j)) >= 0)
	{
		updatedColsList = lappend_int(updatedColsList, j +
									  FirstLowInvalidHeapAttributeNumber);
	}
	return updatedColsList;		/* anything others? */
}

static void
GstoreBeginForeignModify(ModifyTableState *mtstate,
						 ResultRelInfo *rinfo,
						 List *fdw_private,
						 int subplan_index,
						 int eflags)
{
	GpuStoreFdwModify *gs_mstate = palloc0(sizeof(GpuStoreFdwModify));
	Relation	frel = rinfo->ri_RelationDesc;
	List	   *updatedColsList = fdw_private;
	Bitmapset  *updatedCols = NULL;
	AttrNumber	ctid_attno = InvalidAttrNumber;
	Plan	   *subplan = mtstate->mt_plans[subplan_index]->plan;
	ListCell   *lc;

	if (mtstate->operation == CMD_UPDATE)
	{
		foreach (lc, updatedColsList)
		{
			int		attnum = lfirst_int(lc);

			if (attnum > 0)
				updatedCols = bms_add_member(updatedCols, attnum);
		}
	}
	if (mtstate->operation == CMD_UPDATE ||
		mtstate->operation == CMD_DELETE)
	{
		ctid_attno = ExecFindJunkAttributeInTlist(subplan->targetlist,
												  "ctid");
		if (!AttributeNumberIsValid(ctid_attno))
			elog(ERROR, "could not find junk ctid column");
	}
	gs_mstate->gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	gs_mstate->updatedCols = updatedCols;
	gs_mstate->oldestXmin = GetOldestXmin(frel, PROCARRAY_FLAGS_VACUUM);
	gs_mstate->ctid_attno = ctid_attno;
	gs_mstate->gs_undo = gstoreFdwLookupUndoLogs(gs_mstate->gs_desc);
	rinfo->ri_FdwState = gs_mstate;
}

static char *
__gstoreAllocExtraBuffer(GpuStoreDesc *gs_desc, size_t extra_sz)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	kern_data_store *kds;
	kern_data_extra *extra;
	bool		has_exclusive_lock = false;

	/* must be aligned */
	Assert(extra_sz == MAXALIGN(extra_sz));
	LWLockAcquire(&gs_sstate->base_mmap_lock, LW_SHARED);
retry:
	if (gs_desc->base_mmap_revision != gs_sstate->base_mmap_revision)
		gstoreFdwRemapBaseFile(gs_desc, true);
	kds = &gs_desc->base_mmap->schema;
	extra = (kern_data_extra *)((char *)kds + kds->extra_hoffset);
	for (;;)
	{
		cl_ulong	old_usage = atomicRead64(&extra->usage);
		cl_ulong	new_usage = old_usage + extra_sz;

		Assert(old_usage >= offsetof(kern_data_extra, data));
		if (new_usage <= extra->length)
		{
			if (atomicCAS64(&extra->usage, &old_usage, new_usage))
			{
				LWLockRelease(&gs_sstate->base_mmap_lock);

				return (char *)extra + old_usage;
			}
		}
		else if (!has_exclusive_lock)
		{
			/* oops, we have to expand the base file, but no exclusive lock */
			LWLockRelease(&gs_sstate->base_mmap_lock);
			LWLockAcquire(&gs_sstate->base_mmap_lock, LW_EXCLUSIVE);
			has_exclusive_lock = true;
			goto retry;
		}
		else
		{
			/* expand the base file */
			size_t		sz = extra->length;
			size_t		off;
			int			rawfd;
			uint32		revision;

			sz = extra->length;
			if (kds->nitems > 0)
				sz = ((double)kds->nrooms / (double)kds->nitems) * (double)sz;
			sz = Max(sz, extra->length + (64UL << 20));
			sz = PAGE_ALIGN(sz);
			off = offsetof(GpuStoreBaseFileHead, schema) + kds->extra_hoffset;
			
			rawfd = open(gs_sstate->base_file, O_RDWR);
			if (rawfd < 0)
				elog(ERROR, "failed on open('%s'): %m", gs_sstate->base_file);
			if (posix_fallocate(rawfd, off, sz) != 0)
			{
				close(rawfd);
				elog(ERROR, "failed on posix_fallocate('%s',%zu): %m",
					 gs_sstate->base_file, sz);
			}
			close(rawfd);
			extra->length = sz;

			do {
				revision = random();
			} while (revision == UINT_MAX ||
					 revision == gs_sstate->base_mmap_revision);
			gs_sstate->base_mmap_revision = revision;
			/* Ok, remap base and retry */
			goto retry;
		}
	}
}

/*
 * __gstoreExecForeignInsert
 */
static void
__gstoreExecForeignInsert(Relation frel,
						  GpuStoreFdwModify *gs_mstate,
						  TupleTableSlot *slot,		/* NEW tuple */
						  cl_uint oldid)			/* if UPDATE */
{
	GpuStoreDesc   *gs_desc = gs_mstate->gs_desc;
	GpuStoreUndoLogs *gs_undo = gs_mstate->gs_undo;
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	Bitmapset	   *updatedCols = gs_mstate->updatedCols;
	TransactionId	curr_xid = GetCurrentTransactionId();
	cl_uint			rowid = UINT_MAX;
	size_t			extra_sz = 0;
	char		   *extra_buf = NULL;
	List		   *unused_rowids = NIL;
	int				j, natts = RelationGetNumberOfAttributes(frel);
	bool			locked = false;
	char			temp[10];

	/* calculation of required extra buffer size */
	slot_getallattrs(slot);
	if (kds->has_varlena)
	{
		for (j=0; j < kds->ncols; j++)
		{
			kern_colmeta *cmeta = &kds->colmeta[j];
			Datum		datum = slot->tts_values[j];
			bool		isnull = slot->tts_isnull[j];

			if (cmeta->attlen == -1 && !isnull &&
				(!updatedCols || bms_is_member(cmeta->attnum, updatedCols)))
				extra_sz += MAXALIGN(VARSIZE_ANY(datum));
		}
	}

	/* new RowId allocation */
	PG_TRY();
	{
		GstoreFdwSysattr sysattr;
		HeapTuple		tuple;

		for (;;)
		{
			rowid = gstoreFdwAllocateRowId(gs_desc->gs_sstate,
										   gs_desc->rowid_map);
			if (rowid >= kds->nrooms)
				elog(ERROR, "gstore_fdw: '%s' has no room to INSERT any rows %u",
					 RelationGetRelationName(frel), rowid);
			locked = gstoreFdwSpinLockBaseRow(gs_desc, rowid);
			if (gstoreCheckVisibilityForInsert(gs_desc, rowid,
											   gs_mstate->oldestXmin))
				break;
			locked = gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
			unused_rowids = lappend_int(unused_rowids, rowid);
		}
		/* Put INSERT Log */
		tuple = ExecFetchSlotHeapTuple(slot, false, false);
		gstoreFdwAppendInsertLog(frel, gs_desc, rowid, oldid, curr_xid, tuple);
		/* UNDO Log also */
		temp[0] = 'I';
		*((uint32 *)(temp + 1)) = rowid;
		appendBinaryStringInfo(&gs_undo->buf, temp, 5);
		gs_undo->nitems++;

		if (extra_sz > 0)
			extra_buf = __gstoreAllocExtraBuffer(gs_desc, extra_sz);
		kds = &gs_desc->base_mmap->schema;
		for (j=0; j < natts; j++)
		{
			kern_colmeta *cmeta = &kds->colmeta[j];
			Datum		datum = slot->tts_values[j];
			bool		isnull = slot->tts_isnull[j];

			if (cmeta->attlen == -1 && !isnull)
			{
				size_t		sz = VARSIZE_ANY(datum);

				if (!updatedCols || bms_is_member(cmeta->attnum, updatedCols))
				{
					memcpy(extra_buf, DatumGetPointer(datum), sz);
					datum = PointerGetDatum(extra_buf);
					extra_buf += MAXALIGN(sz);
				}
				else
				{
					/*
					 * If UPDATE does not change this varlena column,
					 * we don't need to consume redundant extra buffer for
					 * identicalsame value. So, we reuse the older version
					 * of the unchanged value. It also saves consumption of
					 * GPU device memory.
					 */
					kern_data_extra *extra __attribute__((unused))
						= (kern_data_extra *)((char *)kds + kds->extra_hoffset);
					datum = KDS_fetch_datum_column(kds, cmeta, oldid, &isnull);
					if (isnull)
						elog(ERROR, "Bug? unchanged column has different value");
					Assert((char *)datum >= (char *)extra &&
						   (char *)datum <  (char *)extra + extra->length);
				}
			}
			__KDS_store_datum_column(kds, cmeta, rowid, datum, isnull);
		}
		sysattr.xmin = curr_xid;
		sysattr.xmax = InvalidTransactionId;
		sysattr.cid  = GetCurrentCommandId(true);
		KDS_store_datum_column(kds, &kds->colmeta[natts], rowid,
							   PointerGetDatum(&sysattr),
							   false);
		atomicMax32(&kds->nitems, rowid + 1);
	}
	PG_CATCH();
	{
		if (locked)
			gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
		gstoreFdwReleaseRowIdMulti(gs_desc->gs_sstate,
								   gs_desc->rowid_map,
								   rowid, unused_rowids);
		PG_RE_THROW();
	}
	PG_END_TRY();
	if (locked)
		gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
	gstoreFdwReleaseRowIdMulti(gs_desc->gs_sstate,
							   gs_desc->rowid_map,
							   UINT_MAX, unused_rowids);
	/* Add PK entry, if any */
	Assert(rowid != UINT_MAX);
	gstoreFdwInsertIntoPrimaryKey(gs_desc, gs_undo, rowid);
}

/*
 * __gstoreExecForeignDelete
 *
 * It marks 'removed' on the old tuples; it also works as row-level lock
 * for other concurrent transactions.
 * If Gstore_Fdw has PK, its entry deletion ('R' log) must be added prior to
 * deletion of the base row ('D' log) onto the undo log.
 */
static cl_uint
__gstoreExecForeignDelete(Relation frel,
						  GpuStoreFdwModify *gs_mstate,
						  TupleTableSlot *slot)		/* OLD tuple */
{
	GpuStoreDesc   *gs_desc = gs_mstate->gs_desc;
	GpuStoreUndoLogs *gs_undo = gs_mstate->gs_undo;
	GstoreFdwSysattr sysattr;
	Datum			datum;
	bool			isnull;
	bool			locked = false;
	ItemPointer		ctid;
	cl_uint			rowid;
	char			temp[10];

	/* fetch row-id to be removed */
	datum = ExecGetJunkAttribute(slot, gs_mstate->ctid_attno, &isnull);
	if (isnull)
		elog(ERROR, "Bug? ctid is NULL");
	ctid = (ItemPointer)DatumGetPointer(datum);
	rowid = (((cl_uint)ctid->ip_blkid.bi_hi << 16) |
			 ((cl_uint)ctid->ip_blkid.bi_lo));

	/* ensure rowid exists on the hash-index, if any */
	gstoreFdwRemoveFromPrimaryKey(gs_desc, gs_undo, rowid);

	/* do deletion */
	ConditionVariablePrepareToSleep(&gstore_shared_head->row_lock_cond);
	PG_TRY();
	{
		int		visible;

		for (;;)
		{
			locked = gstoreFdwSpinLockBaseRow(gs_desc, rowid);
			visible = gstoreCheckVisibilityTryDelete(gs_desc,
													 rowid,
													 GetCurrentTransactionId(),
													 &sysattr);
			locked = gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
			if (visible > 0)
				break;
			if (visible == 0)
				elog(ERROR, "concurrent update of foreign table '%s' at rowid=%u",
					 RelationGetRelationName(frel), rowid);

			ConditionVariableSleep(&gstore_shared_head->row_lock_cond,
								   PG_WAIT_LOCK);
		}
	}
	PG_CATCH();
	{
		if (locked)
			gstoreFdwSpinUnlockBaseRow(gs_desc, rowid);
		ConditionVariableCancelSleep();
		PG_RE_THROW();
	}
	PG_END_TRY();
	ConditionVariableCancelSleep();

	/* Put DELETE log */
	gstoreFdwAppendDeleteLog(frel, gs_desc, rowid,
							 sysattr.xmin,
							 sysattr.xmax);
	/* UNDO Log also */
	temp[0] = 'D';
	*((uint32 *)(temp + 1)) = rowid;
	appendBinaryStringInfo(&gs_undo->buf, temp, 5);
	gs_undo->nitems++;

	return rowid;
}

static TupleTableSlot *
GstoreExecForeignInsert(EState *estate,
						ResultRelInfo *rinfo,
						TupleTableSlot *slot,
						TupleTableSlot *planSlot)
{
	__gstoreExecForeignInsert(rinfo->ri_RelationDesc,
							  rinfo->ri_FdwState, slot, UINT_MAX);
	return slot;
}

static TupleTableSlot *
GstoreExecForeignUpdate(EState *estate,
						ResultRelInfo *rinfo,
						TupleTableSlot *slot,
						TupleTableSlot *planSlot)
{
	cl_uint		oldid;

	oldid = __gstoreExecForeignDelete(rinfo->ri_RelationDesc,
									  rinfo->ri_FdwState, planSlot);
	__gstoreExecForeignInsert(rinfo->ri_RelationDesc,
							  rinfo->ri_FdwState, slot, oldid);
    return slot;
}

static TupleTableSlot *
GstoreExecForeignDelete(EState *estate,
						ResultRelInfo *rinfo,
						TupleTableSlot *slot,
						TupleTableSlot *planSlot)
{
	__gstoreExecForeignDelete(rinfo->ri_RelationDesc,
							  rinfo->ri_FdwState, planSlot);
	return slot;
}

static void
GstoreEndForeignModify(EState *estate, ResultRelInfo *rinfo)
{
	/* do nothing */
}

#if PG_VERSION_NUM >= 110000
/*
 * MEMO: executor begin/end routine, if gstore_fdw is partitioned-leaf
 * relations. In this case, GstoreBeginForeignModify shall not be called.
 */
static void
GstoreBeginForeignInsert(ModifyTableState *mtstate,
						 ResultRelInfo *rinfo)
{
	GpuStoreFdwModify *gs_mstate = palloc0(sizeof(GpuStoreFdwModify));
	Relation		frel = rinfo->ri_RelationDesc;

	gs_mstate->gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	gs_mstate->updatedCols = NULL;
	gs_mstate->oldestXmin = GetOldestXmin(frel, PROCARRAY_FLAGS_VACUUM);
	gs_mstate->ctid_attno = InvalidAttrNumber;
	gs_mstate->gs_undo = gstoreFdwLookupUndoLogs(gs_mstate->gs_desc);

	rinfo->ri_FdwState = gs_mstate;
}

static void
GstoreEndForeignInsert(EState *estate, ResultRelInfo *rinfo)
{
	/* do nothing */
}
#endif

void
ExplainGstoreFdw(GpuStoreFdwState *fdw_state,
				 Relation frel, ExplainState *es)
{
	TupleDesc		tupdesc = RelationGetDescr(frel);
	GpuStoreDesc   *gs_desc = fdw_state->gs_desc;
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	List		   *dcontext;
	int				j = -1;
	StringInfoData	buf;

	/* deparse context */
	dcontext = deparse_context_for(RelationGetRelationName(frel),
								   RelationGetRelid(frel));

	/* shows referenced columns */
	initStringInfo(&buf);
	if (es->verbose)
	{
		while ((j = bms_next_member(fdw_state->referenced, j)) >= 0)
		{
			int		anum = j + FirstLowInvalidHeapAttributeNumber;
			Form_pg_attribute attr;

			if (anum <= 0)
				continue;
			attr = tupleDescAttr(tupdesc, anum-1);
			if (buf.len > 0)
				appendStringInfoString(&buf, ", ");
			appendStringInfo(&buf, "%s", NameStr(attr->attname));
		}
		ExplainPropertyText("Referenced", buf.data, es);
	}

	/* shows index condition */
	resetStringInfo(&buf);
	if (fdw_state->indexExprState)
	{
		Node	   *indexExpr = (Node *)fdw_state->indexExprState->expr;
		Form_pg_attribute attr;

		Assert(gs_sstate->primary_key > 0 &&
			   gs_sstate->primary_key <= tupdesc->natts);
		attr = tupleDescAttr(tupdesc, gs_sstate->primary_key - 1);
		appendStringInfo(&buf, "%s = %s",
						 quote_identifier(NameStr(attr->attname)),
						 deparse_expression(indexExpr, dcontext, false, false));
		ExplainPropertyText("Index Cond", buf.data, es);
	}

	/* shows base&redo filename */
	if (es->verbose)
	{
		ExplainPropertyText("Base file", gs_sstate->base_file, es);
		ExplainPropertyText("Redo log", gs_sstate->redo_log_file, es);
	}
	pfree(buf.data);
}

static void
GstoreExplainForeignScan(ForeignScanState *node, ExplainState *es)
{
	ExplainGstoreFdw((GpuStoreFdwState *)node->fdw_state,
					 node->ss.ss_currentRelation, es);
}

static void
GstoreExplainForeignModify(ModifyTableState *mtstate,
						   ResultRelInfo *rinfo,
						   List *fdw_private,
						   int subplan_index,
						   ExplainState *es)
{}

static bool
GstoreAnalyzeForeignTable(Relation relation,
						  AcquireSampleRowsFunc *func,
						  BlockNumber *totalpages)
{
	return false;
}

Datum
pgstrom_gstore_fdw_validator(PG_FUNCTION_ARGS)
{
	List	   *options = untransformRelOptions(PG_GETARG_DATUM(0));
	Oid			catalog = PG_GETARG_OID(1);
	ListCell   *lc;

	if (catalog != ForeignTableRelationId)
	{
		if (options != NIL)
			elog(ERROR, "unknown FDW options");
		PG_RETURN_VOID();
	}
	/*
	 * Only syntax shall be checked here, then OAT_POST_CREATE hook
	 * actually validates the configuration.
	 */
	foreach (lc, options)
	{
		DefElem	   *def = (DefElem *) lfirst(lc);
		char	   *endp;

		if (catalog != ForeignTableRelationId)
		{
			const char *suffix;
			
			if (catalog == AttributeRelationId)
				suffix = " at columns";
			if (catalog == ForeignServerRelationId)
				suffix = " at foreign-servers";
			if (catalog == ForeignDataWrapperRelationId)
				suffix = " at foreign-data-wrappers";
			elog(ERROR, "No FDW options are supported%s.", suffix);
		}
		else if (strcmp(def->defname, "gpu_device_id") == 0)
		{
			char   *token = defGetString(def);

			if (strtol(token, &endp, 10) < 0 || *endp != '\0')
				elog(ERROR, "gpu_device_id = '%s' is not valid", token);
		}
		else if (strcmp(def->defname, "max_num_rows") == 0)
		{
			char   *token = defGetString(def);

			if (strtol(token, &endp, 10) < 0 || *endp != '\0')
				elog(ERROR, "max_num_rows = '%s' is not valid", token);
		}
		else if (strcmp(def->defname, "base_file") == 0 ||
				 strcmp(def->defname, "redo_log_file") == 0)
		{
			/* file pathname shall be checked at post-creation steps */
		}
		else if (strcmp(def->defname, "redo_log_limit") == 0 ||
				 strcmp(def->defname, "gpu_update_threshold") == 0)
		{
			char   *token = defGetString(def);

			if (strtol(token, &endp, 10) <= 0 ||
				(strcasecmp(endp, "k")  != 0 &&
				 strcasecmp(endp, "kb") != 0 &&
				 strcasecmp(endp, "m")  != 0 &&
				 strcasecmp(endp, "mb") != 0 &&
				 strcasecmp(endp, "g")  != 0 &&
				 strcasecmp(endp, "gb") != 0))
				elog(ERROR, "'%s' is not a valid configuration for '%s'",
					 token, def->defname);
		}
		else if (strcmp(def->defname, "gpu_update_interval") == 0)
		{
			char   *token = defGetString(def);
			long	interval = strtol(token, &endp, 10);

			if (interval <= 0 || interval > INT_MAX || *endp != '\0')
				elog(ERROR, "'%s' is not a valid configuration for '%s'",
					 token, def->defname);
		}
		else if (strcmp(def->defname, "primary_key") == 0)
		{
			/* column name shall be validated later */
		}
		else if (strcmp(def->defname, "preserve_files") == 0)
		{
			/* boolean values */
			defGetBoolean(def);
		}
		else
		{
			ereport(ERROR,
					(errcode(ERRCODE_FDW_INVALID_OPTION_NAME),
					 errmsg("invalid option \"%s\"", def->defname)));
		}
	}
	PG_RETURN_VOID();
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_validator);

static void
gstoreFdwExtractOptions(Relation frel,
						cl_int *p_cuda_dindex,
						ssize_t *p_max_num_rows,
						const char **p_base_file,
						const char **p_redo_log_file,
						size_t *p_redo_log_limit,
						cl_long *p_gpu_update_interval,
						size_t *p_gpu_update_threshold,
						AttrNumber *p_primary_key,
						bool *p_preserve_files)
{
	ForeignTable *ft = GetForeignTable(RelationGetRelid(frel));
	TupleDesc	tupdesc = RelationGetDescr(frel);
	ListCell   *lc;
	cl_int		cuda_dindex = 0;
	ssize_t		max_num_rows = -1;
	const char *base_file = NULL;
	const char *redo_log_file = NULL;
	ssize_t		redo_log_limit = (512U << 20);	/* default: 512MB */
	cl_long		gpu_update_interval = 15;		/* default: 15s */
	ssize_t		gpu_update_threshold = -1;		/* default: 20% of redo_log_limit */
	AttrNumber	primary_key = -1;
	bool		preserve_files = false;

	/*
	 * check foreign relation's option
	 */
	foreach (lc, ft->options)
	{
		DefElem	   *def = lfirst(lc);
		char	   *endp;

		if (strcmp(def->defname, "gpu_device_id") == 0)
		{
			long	device_id = strtol(defGetString(def), &endp, 10);
			int		i;

			if (device_id < 0 || device_id > INT_MAX || *endp != '\0')
				elog(ERROR, "unexpected input for gpu_device_id: %s",
					 defGetString(def));
			cuda_dindex = -1;
			for (i=0; i < numDevAttrs; i++)
			{
				if (devAttrs[i].DEV_ID == device_id)
				{
					cuda_dindex = i;
					break;
				}
			}
			if (cuda_dindex < 0)
				elog(ERROR, "gpu_device_id = %ld was not found", device_id);
		}
		else if (strcmp(def->defname, "max_num_rows") == 0)
		{
			max_num_rows = strtol(defGetString(def), &endp, 10);
			if (max_num_rows < 0 || max_num_rows >= UINT_MAX || *endp != '\0')
				elog(ERROR, "unexpected input for max_num_rows: %s",
					 defGetString(def));
		}
		else if (strcmp(def->defname, "base_file") == 0)
		{
			char   *path = defGetString(def);
			char   *d_name;

			if (access(path, R_OK | W_OK) != 0)
			{
				if (errno != ENOENT)
					elog(ERROR, "base_file '%s' is not accesible: %m", path);

				d_name = dirname(pstrdup(path));
				if (access(d_name, R_OK | W_OK | X_OK) != 0)
					elog(ERROR, "unable to create base_file '%s': %m", path);
			}
			base_file = path;
		}
		else if (strcmp(def->defname, "redo_log_file") == 0)
		{
			char   *path = defGetString(def);
			char   *d_name;

			if (access(path, R_OK | W_OK) != 0)
			{
				if (errno != ENOENT)
					elog(ERROR, "redo_log_file '%s' is not accesible: %m",
						 path);
				d_name = dirname(pstrdup(path));
				if (access(d_name, R_OK | W_OK | X_OK) != 0)
					elog(ERROR, "unable tp create redo_log_file '%s': %m",
						 path);
			}
			redo_log_file = path;
		}
		else if (strcmp(def->defname, "redo_log_limit") == 0)
		{
			char   *value = defGetString(def);
			ssize_t	limit = strtol(value, &endp, 10);

			if (limit <= 0)
				elog(ERROR, "invalid redo_log_limit: %s", value);
			if (strcmp(endp, "k") == 0 || strcmp(endp, "kb") == 0)
				limit *= (1UL << 10);
			else if (strcmp(endp, "m") == 0 || strcmp(endp, "mb") == 0)
				limit *= (1UL << 20);
			else if (strcmp(endp, "g") == 0 || strcmp(endp, "gb") == 0)
				limit *= (1UL << 30);
			else if (*endp != '\0')
				elog(ERROR, "invalid redo_log_limit: %s", value);
			if (limit % PAGE_SIZE != 0)
				elog(ERROR, "redo_log_limit must be multiple of PAGE_SIZE");
			if (limit < (128UL << 20))
				elog(ERROR, "redo_log_limit must be larger than 128MB");
			redo_log_limit = limit;
		}
		else if (strcmp(def->defname, "gpu_update_interval") == 0)
		{
			char   *value = defGetString(def);
			long	interval = strtol(value, &endp, 10);

			if (interval <= 0 || interval > INT_MAX || *endp != '\0')
				elog(ERROR, "invalid gpu_update_interval: %s", value);
			gpu_update_interval = interval;
		}
		else if (strcmp(def->defname, "gpu_update_threshold") == 0)
		{
			char   *value = defGetString(def);
			ssize_t	threshold = strtol(value, &endp, 10);

			if (threshold <= 0)
				elog(ERROR, "invalid gpu_update_threshold: %s", value);
			if (strcmp(endp, "k") == 0 || strcmp(endp, "kb") == 0)
				threshold *= (1UL << 10);
			else if (strcmp(endp, "m") == 0 || strcmp(endp, "mb") == 0)
				threshold *= (1UL << 20);
			else if (strcmp(endp, "g") == 0 || strcmp(endp, "gb") == 0)
				threshold *= (1UL << 30);
			else if (*endp != '\0')
				elog(ERROR, "invalid redo_log_sz: %s", value);
			gpu_update_threshold = threshold;
		}
		else if (strcmp(def->defname, "primary_key") == 0)
		{
			char   *pk_name = defGetString(def);
			int		j;

			for (j=0; j < tupdesc->natts; j++)
			{
				Form_pg_attribute attr = tupleDescAttr(tupdesc,j);

				if (strcmp(pk_name, NameStr(attr->attname)) == 0)
				{
					primary_key = attr->attnum;
					break;
				}
			}
			if (primary_key < 0)
				elog(ERROR, "'%s' specified by 'primary_key' option not found",
					 pk_name);
		}
		else if (strcmp(def->defname, "preserve_files") == 0)
		{
            preserve_files = defGetBoolean(def);
		}
		else
			elog(ERROR, "gstore_fdw: unknown option: %s", def->defname);
	}

	/*
	 * Check Mandatory Options
	 */
	if (max_num_rows < 0)
		elog(ERROR, "max_num_rows must be specified");
	if (!redo_log_file)
		elog(ERROR, "redo_log_file must be specified");
	if (gpu_update_threshold < 0)
		gpu_update_threshold = redo_log_limit / 5;
	else if (gpu_update_threshold < redo_log_limit / 50 ||
			 gpu_update_threshold > redo_log_limit / 2)
		elog(ERROR, "gpu_update_threshold is out of range: must be [%zu..%zu]",
			 redo_log_limit / 50, redo_log_limit / 2);
	/*
	 * Write-back Results
	 */
	*p_cuda_dindex          = cuda_dindex;
	*p_max_num_rows         = max_num_rows;
	*p_base_file            = base_file;
	*p_redo_log_file        = redo_log_file;
	*p_redo_log_limit       = redo_log_limit;
	*p_gpu_update_interval  = gpu_update_interval;
	*p_gpu_update_threshold = gpu_update_threshold;
	*p_primary_key          = primary_key;
	*p_preserve_files       = preserve_files;
}

/*
 * gstoreFdwAssignDefaultFiles
 *
 * assign default name for base/redo files if not specified the options.
 * the supplied 'frel' must have AccessExclusiveLock
 */
static void
gstoreFdwAssignDefaultFiles(Relation frel)
{
	Oid			ftable_oid = RelationGetRelid(frel);
	ForeignTable *ft = GetForeignTable(ftable_oid);
	DefElem	   *base_file = NULL;
	DefElem	   *redo_file = NULL;
	ListCell   *lc;
	List	   *ftoptions;
	char	   *dir_name;
	char	   *filename;
	StringInfoData buf;
	ArrayType  *ap;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	Relation	crel;
	Datum		values[Natts_pg_foreign_table];
	bool		isnull[Natts_pg_foreign_table];
	bool		update[Natts_pg_foreign_table];
	HeapTuple	tuple;

	foreach (lc, ft->options)
	{
		DefElem	   *def = lfirst(lc);

		if (strcmp(def->defname, "base_file") == 0)
			base_file = def;
		else if (strcmp(def->defname, "redo_log_file") == 0)
			redo_file = def;
	}
	if (base_file && redo_file)
		return;		/* nothing to do */

	ftoptions = list_copy(ft->options);
	if (!base_file)
	{
		if (gstore_fdw_default_base_dir && *gstore_fdw_default_base_dir != '\0')
			dir_name = gstore_fdw_default_base_dir;
		else
			dir_name = GetDatabasePath(MyDatabaseId, MyDatabaseTableSpace);
		filename = psprintf("%s/gstore_fdw_%u.base", dir_name, ftable_oid);
		base_file = makeDefElem("base_file",
								(Node *)makeString(filename), -1);
		ftoptions = lappend(ftoptions, base_file);
	}

	if (!redo_file)
	{
		if (gstore_fdw_default_redo_dir && *gstore_fdw_default_redo_dir != '\0')
			dir_name = gstore_fdw_default_redo_dir;
		else
			dir_name = GetDatabasePath(MyDatabaseId, MyDatabaseTableSpace);
		filename = psprintf("%s/gstore_fdw_%u.redo", dir_name, ftable_oid);
		redo_file = makeDefElem("redo_log_file",
								(Node *)makeString(filename), -1);
		ftoptions = lappend(ftoptions, redo_file);
	}

	/* setup pg_foreign_table.ftoptions */
	get_typlenbyvalalign(TEXTOID, &typlen, &typbyval, &typalign);
	Assert(typlen == -1 && !typbyval);
	initStringInfo(&buf);
	enlargeStringInfo(&buf, ARR_OVERHEAD_NONULLS(1));
	ap = (ArrayType *)buf.data;
	ap->ndim = 1;
	ap->dataoffset = 0;
	ap->elemtype = TEXTOID;
	ARR_DIMS(ap)[0] = list_length(ftoptions);
	ARR_LBOUND(ap)[0] = 1;
	buf.len += ARR_OVERHEAD_NONULLS(1);

	foreach (lc, ftoptions)
	{
		DefElem    *def = lfirst(lc);
		uint32		vl_off = att_align_nominal(buf.len, typalign);

		while (buf.len < vl_off)
			appendStringInfoChar(&buf, '\0');
		appendStringInfoSpaces(&buf, sizeof(uint32));	/* varlena head */
		appendStringInfo(&buf, "%s=%s", def->defname, defGetString(def));
		SET_VARSIZE(buf.data + vl_off, buf.len - vl_off);
	}
	SET_VARSIZE(buf.data, buf.len);

	/* update pg_foreign_table */
	crel = table_open(ForeignTableRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy1(FOREIGNTABLEREL, ftable_oid);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for foreign table \"%s\"",
			 RelationGetRelationName(frel));
	memset(values, 0, sizeof(values));
	memset(isnull, 0, sizeof(isnull));
	memset(update, 0, sizeof(update));

	values[Anum_pg_foreign_table_ftoptions - 1] = PointerGetDatum(buf.data);
	update[Anum_pg_foreign_table_ftoptions - 1] = true;
	tuple = heap_modify_tuple(tuple, RelationGetDescr(crel),
							  values, isnull, update);
	CatalogTupleUpdate(crel, &tuple->t_self, tuple);

	CacheInvalidateRelcache(crel);

	table_close(crel, RowExclusiveLock);

	CommandCounterIncrement();

	heap_freetuple(tuple);
	pfree(buf.data);
}

/*
 * gstoreFdwDeviceTupleDesc
 *
 * GstoreFdw appends a virtual system column at the tail of user-defined
 * columns to control visibility of rows. This function generates a pseudo
 * TupleDesc that contains the system column. It shall be released by pfree().
 */
static TupleDesc
gstoreFdwDeviceTupleDesc(Relation frel)
{
	TupleDesc	tupdesc = RelationGetDescr(frel);
	TupleDesc	__tupdesc = CreateTemplateTupleDesc(tupdesc->natts + 1);
	int			j;

	for (j=0; j < tupdesc->natts; j++)
	{
		memcpy(tupleDescAttr(__tupdesc, j),
			   tupleDescAttr(tupdesc, j),
			   ATTRIBUTE_FIXED_PART_SIZE);
	}
	TupleDescInitEntry(__tupdesc,
					   __tupdesc->natts,
					   "..gstore_fdw.sysattr..",
					   GSTORE_FDW_SYSATTR_OID, -1, 0);
	tupleDescAttr(__tupdesc, __tupdesc->natts - 1)->attnotnull = true;

	return __tupdesc;
}

/*
 * gstoreFdwAllocSharedState
 */
static GpuStoreSharedState *
gstoreFdwAllocSharedState(Relation frel)
{
	GpuStoreSharedState *gs_sstate;
	cl_int		cuda_dindex;
	ssize_t		max_num_rows;
	ssize_t		num_hash_slots = -1;
	const char *base_file;
	const char *redo_log_file;
	size_t		redo_log_limit;
	cl_long		gpu_update_interval;
	size_t		gpu_update_threshold;
	AttrNumber	primary_key;
	bool		preserve_files;
	size_t		len;
	char	   *pos;
	cl_int		i;

	/* extract table/column options */
	gstoreFdwExtractOptions(frel,
							&cuda_dindex,
							&max_num_rows,
							&base_file,
							&redo_log_file,
							&redo_log_limit,
							&gpu_update_interval,
							&gpu_update_threshold,
							&primary_key,
							&preserve_files);
	/* allocation of GpuStoreSharedState */
	len = MAXALIGN(sizeof(GpuStoreSharedState));
	if (base_file)
		len += MAXALIGN(strlen(base_file) + 1);
	if (redo_log_file)
		len += MAXALIGN(strlen(redo_log_file) + 1);
	if (primary_key >= 0)
	{
		/* num_hash_slots >= (2^32) does not make sense because hash_any
		 * shall return hash-value in uint32. */
		num_hash_slots = 1.2 * (double)max_num_rows + 1000.0;
		num_hash_slots = Min(num_hash_slots, UINT_MAX);
	}

	gs_sstate = MemoryContextAllocZero(TopSharedMemoryContext, len);
	pos = (char *)gs_sstate + MAXALIGN(sizeof(GpuStoreSharedState));
	if (base_file)
	{
		strcpy(pos, base_file);
		gs_sstate->base_file = pos;
		pos += MAXALIGN(strlen(base_file) + 1);
	}
	if (redo_log_file)
	{
		strcpy(pos, redo_log_file);
		gs_sstate->redo_log_file = pos;
		pos += MAXALIGN(strlen(redo_log_file) + 1);
	}
	Assert(pos - (char *)gs_sstate == len);

	gs_sstate->database_oid = MyDatabaseId;
	gs_sstate->ftable_oid = RelationGetRelid(frel);
	gs_sstate->hash = hash_any((const unsigned char *)&gs_sstate->database_oid,
							   2 * sizeof(Oid));
	gs_sstate->cuda_dindex = cuda_dindex;
	gs_sstate->max_num_rows = max_num_rows;
	gs_sstate->num_hash_slots = num_hash_slots;
	gs_sstate->primary_key = primary_key;
	gs_sstate->preserve_files = preserve_files;
	gs_sstate->redo_log_limit = redo_log_limit;
	gs_sstate->gpu_update_interval = gpu_update_interval;
	gs_sstate->gpu_update_threshold = gpu_update_threshold;

	LWLockInitialize(&gs_sstate->base_mmap_lock, -1);
	gs_sstate->base_mmap_revision = UINT_MAX;

	SpinLockInit(&gs_sstate->rowid_map_lock);
	for (i=0; i < GSTORE_NUM_BASE_ROW_LOCKS; i++)
		SpinLockInit(&gs_sstate->base_row_lock[i]);
	for (i=0; i < GSTORE_NUM_HASH_SLOT_LOCKS; i++)
		SpinLockInit(&gs_sstate->hash_slot_lock[i]);
	SpinLockInit(&gs_sstate->redo_pos_lock);
	gs_sstate->redo_write_pos = 0;
	gs_sstate->redo_read_pos = 0;
	
	pthreadRWLockInit(&gs_sstate->gpu_bufer_lock);

	return gs_sstate;
}

/* ----------------------------------------------------------------
 *
 * Routines to allocate/release RowIDs
 *
 * ----------------------------------------------------------------
 */
static inline size_t
gstoreFdwRowIdMapSize(cl_uint nrooms)
{
	return MAXALIGN(offsetof(GpuStoreRowIdMapHead, rowid_chain[nrooms]));
}

static cl_uint
gstoreFdwAllocateRowId(GpuStoreSharedState *gs_sstate,
                       GpuStoreRowIdMapHead *rowid_map)
{
	cl_uint		rowid;

	SpinLockAcquire(&gs_sstate->rowid_map_lock);
	rowid = rowid_map->first_free_rowid;
	if (rowid != UINT_MAX)
	{
		Assert(rowid < rowid_map->nrooms);
		rowid_map->first_free_rowid = rowid_map->rowid_chain[rowid];
		rowid_map->rowid_chain[rowid] = UINT_MAX;	/* currently in-use */
	}
	SpinLockRelease(&gs_sstate->rowid_map_lock);

	return rowid;
}

static void
gstoreFdwReleaseRowId(GpuStoreSharedState *gs_sstate,
					  GpuStoreRowIdMapHead *rowid_map,
					  cl_uint rowid)
{
	SpinLockAcquire(&gs_sstate->rowid_map_lock);
	Assert(rowid < rowid_map->nrooms);
	Assert(rowid_map->rowid_chain[rowid] == UINT_MAX);
	rowid_map->rowid_chain[rowid] = rowid_map->first_free_rowid;
	rowid_map->first_free_rowid = rowid;
	SpinLockRelease(&gs_sstate->rowid_map_lock);
}

static void
gstoreFdwReleaseRowIdMulti(GpuStoreSharedState *gs_sstate,
						   GpuStoreRowIdMapHead *rowid_map,
						   cl_uint rowid, List *unused_rowids)
{
	ListCell   *lc;

    SpinLockAcquire(&gs_sstate->rowid_map_lock);
	if (rowid != UINT_MAX)
	{
		Assert(rowid < rowid_map->nrooms);
		Assert(rowid_map->rowid_chain[rowid] == UINT_MAX);
		rowid_map->rowid_chain[rowid] = rowid_map->first_free_rowid;
		rowid_map->first_free_rowid = rowid;
	}

	foreach (lc, unused_rowids)
	{
		rowid = lfirst_int(lc);

		Assert(rowid < rowid_map->nrooms);
		Assert(rowid_map->rowid_chain[rowid] == UINT_MAX);
		rowid_map->rowid_chain[rowid] = rowid_map->first_free_rowid;
		rowid_map->first_free_rowid = rowid;
	}
	SpinLockRelease(&gs_sstate->rowid_map_lock);
}

static bool
gstoreFdwCheckRowId(GpuStoreSharedState *gs_sstate,
					GpuStoreRowIdMapHead *rowid_map,
					cl_uint rowid)
{
	bool	retval = false;

	if (rowid < rowid_map->nrooms)
	{
		SpinLockAcquire(&gs_sstate->rowid_map_lock);
		if (rowid_map->rowid_chain[rowid] == UINT_MAX)
			retval = true;
		SpinLockRelease(&gs_sstate->rowid_map_lock);
	}
	return retval;
}

/* ----------------------------------------------------------------
 *
 * Routines for hash-base primary key index
 *
 * ----------------------------------------------------------------
 */
static void
gstoreFdwInsertIntoPrimaryKey(GpuStoreDesc *gs_desc,
							  GpuStoreUndoLogs *gs_undo, cl_uint rowid)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	GpuStoreHashIndexHead *hash_index = gs_desc->hash_index;
	kern_data_store	*kds = &gs_desc->base_mmap->schema;
	kern_colmeta   *cmeta;
	TypeCacheEntry *tcache;
	Datum			kdatum;
	Datum			hash;
	bool			isnull;
	bool			is_locked;
	char			temp[10];

	if (!hash_index)
		return;		/* no primary key index */
	Assert(gs_sstate->primary_key > 0 &&
		   gs_sstate->primary_key <= kds->ncols);
	Assert(hash_index->nrooms == kds->nrooms);
	if (rowid >= hash_index->nrooms)
		elog(ERROR, "Bug? rowid=%u is larger than index's nrooms=%lu",
			 rowid, hash_index->nrooms);
	enlargeStringInfo(&gs_undo->buf, sizeof(char) + 2 * sizeof(cl_uint));

	/* calculation of hash-value for the PK */
	cmeta = &kds->colmeta[gs_sstate->primary_key - 1];
	tcache = lookup_type_cache(cmeta->atttypid,
							   TYPECACHE_EQ_OPR_FINFO |
							   TYPECACHE_HASH_PROC_FINFO);
	kdatum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	if (isnull)
		elog(ERROR, "primary key '%s' of foreign table '%s' is NULL",
			 NameStr(cmeta->attname), get_rel_name(kds->table_oid));
	hash = FunctionCall1(&tcache->hash_proc_finfo, kdatum);
	is_locked = gstoreFdwSpinLockHashSlot(gs_desc, hash);
	PG_TRY();
	{
		cl_uint	   *rowmap = &hash_index->slots[hash_index->nslots];
		cl_uint		curr_id;
		cl_uint		k = hash % hash_index->nslots;

		/* duplication check of the primary key */
		ConditionVariablePrepareToSleep(&gstore_shared_head->row_lock_cond);
	wakeup_retry:
		for (curr_id = hash_index->slots[k];
			 curr_id < hash_index->nrooms;
			 curr_id = rowmap[curr_id])
		{
			int		visible;
			Datum	cdatum;

			visible = gstoreCheckVisibilityForIndex(gs_desc, curr_id);
			if (visible == 0)
				continue;
			cdatum = KDS_fetch_datum_column(kds, cmeta, curr_id, &isnull);
			if (isnull)
			{
				elog(WARNING, "Bug? primary key '%s' has NULL at rowid=%u",
					 NameStr(cmeta->attname), curr_id);
				continue;
			}
			if (DatumGetBool(FunctionCall2(&tcache->eq_opr_finfo,
										   kdatum, cdatum)))
			{
				if (visible > 0)
				{
					Oid		typoutput;
					bool	typisvarlena;

					getTypeOutputInfo(cmeta->atttypid,
									  &typoutput,
									  &typisvarlena);
					elog(ERROR,"duplicate primary key violation; %s = %s already exists",
						 NameStr(cmeta->attname),
						 OidOutputFunctionCall(typoutput, kdatum));
				}
				/*
				 * NOTE: This row has duplicated value, however, not committed
				 * yet, thus, this session must be blocked by the row-level lock.
				 */
				is_locked = gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
				ConditionVariableSleep(&gstore_shared_head->row_lock_cond,
									   PG_WAIT_LOCK);
				is_locked = gstoreFdwSpinLockHashSlot(gs_desc, hash);
				goto wakeup_retry;
			}
		}
		/* Undo Log - Add PK with hash(u32) + rowid(u32) */
		temp[0] = 'A';
		*((cl_uint *)(temp + 1)) = hash;
		*((cl_uint *)(temp + 5)) = rowid;
		appendBinaryStringInfo(&gs_undo->buf, temp,
							   sizeof(char) + 2 * sizeof(cl_uint));
		gs_undo->nitems++;
		
		/* Ok, no primary key violation */
		rowmap[rowid] = hash_index->slots[k];
		hash_index->slots[k] = rowid;
	}
	PG_CATCH();
	{
		if (is_locked)
			gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
		ConditionVariableCancelSleep();
		PG_RE_THROW();
	}
	PG_END_TRY();
	Assert(is_locked);
	gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
	ConditionVariableCancelSleep();
//	elog(INFO, "Insert PK of rowid=%u, hash=%08lx", rowid, hash);
}

static void
gstoreFdwRemoveFromPrimaryKey(GpuStoreDesc *gs_desc,
							  GpuStoreUndoLogs *gs_undo,
							  cl_uint rowid)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	GpuStoreHashIndexHead *hash_index = gs_desc->hash_index;
	kern_data_store	*kds = &gs_desc->base_mmap->schema;
	kern_colmeta   *cmeta = &kds->colmeta[gs_sstate->primary_key - 1];
	TypeCacheEntry *tcache;
	Datum			datum;
	Datum			hash;
	bool			isnull;

	if (gs_sstate->primary_key < 1 ||
		gs_sstate->primary_key > kds->ncols)
		return;		/* no primary key is configured */
	Assert(hash_index != NULL);
	if (rowid >= hash_index->nrooms)
		elog(ERROR, "index corruption? rowid=%u is larger than index's nrooms=%lu",
			 rowid, hash_index->nrooms);

	tcache = lookup_type_cache(cmeta->atttypid,
							   TYPECACHE_HASH_PROC |
							   TYPECACHE_HASH_PROC_FINFO);
	datum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	if (isnull)
		elog(ERROR, "primary key '%s' of foreign table '%s' is NULL",
			 NameStr(cmeta->attname), get_rel_name(kds->table_oid));
	hash = FunctionCall1(&tcache->hash_proc_finfo, datum);

	/* ensure PK is on the hash-index */
	gstoreFdwSpinLockHashSlot(gs_desc, hash);
	PG_TRY();
	{
		cl_uint	   *rowmap = &hash_index->slots[hash_index->nslots];
		cl_uint		curr_id;
		char		temp[10];

		for (curr_id = hash_index->slots[hash % hash_index->nslots];
			 curr_id < hash_index->nrooms;
			 curr_id = rowmap[curr_id])
		{
			if (curr_id == rowid)
			{
				/* PK removal from the hash-index */
				temp[0] = 'R';
				*((cl_uint *)(temp + 1)) = hash;
				*((cl_uint *)(temp + 5)) = rowid;
				appendBinaryStringInfo(&gs_undo->buf, temp, 9);
				gs_undo->nitems++;

				goto out;
			}
		}
		elog(WARNING, "primary key '%s' for rowid='%u' not found",
			 NameStr(cmeta->attname), rowid);
	out:
		gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
	}
	PG_CATCH();
	{
		gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
		PG_RE_THROW();
	}
	PG_END_TRY();

//	elog(INFO, "Remove PK of rowid=%u, hash=%08lx", rowid, hash);
}

/*
 * gstoreFdwCreateBaseFile
 */
static void
gstoreFdwCreateBaseFile(Relation frel,
						GpuStoreSharedState *gs_sstate,
						File fdesc)
{
	TupleDesc	__tupdesc = gstoreFdwDeviceTupleDesc(frel);
	GpuStoreBaseFileHead *hbuf;
	kern_data_store *schema;
	int			rawfd = FileGetRawDesc(fdesc);
	const char *base_file = FilePathName(fdesc);
	size_t		hbuf_sz, main_sz, sz;
	size_t		rowmap_sz = 0;
	size_t		hash_sz = 0;
	size_t		extra_sz = 0;
	size_t		file_sz;
	size_t		nrooms = gs_sstate->max_num_rows;
	size_t		nslots = gs_sstate->num_hash_slots;
	int			j, unitsz;

	/*
	 * Setup GpuStoreBaseFileHead
	 */
	main_sz = KDS_calculateHeadSize(__tupdesc);
	hbuf_sz = offsetof(GpuStoreBaseFileHead, schema) + main_sz;
	hbuf = alloca(hbuf_sz);
	memset(hbuf, 0, hbuf_sz);
	memcpy(hbuf->signature, GPUSTORE_BASEFILE_MAPPED_SIGNATURE, 8);
	strcpy(hbuf->ftable_name, RelationGetRelationName(frel));

	init_kernel_data_store(&hbuf->schema,
						   __tupdesc,
						   0,	/* to be set later */
						   KDS_FORMAT_COLUMN,
						   nrooms);
	hbuf->schema.table_oid = RelationGetRelid(frel);
	schema = &hbuf->schema;
	for (j=0; j < __tupdesc->natts; j++)
	{
		Form_pg_attribute	attr = tupleDescAttr(__tupdesc, j);
		kern_colmeta	   *cmeta = &schema->colmeta[j];

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
			extra_sz += MAXALIGN(unitsz) * nrooms;
		}
		else
		{
			elog(ERROR, "unexpected type length (%d) at %s.%s",
				 attr->attlen,
				 RelationGetRelationName(frel),
				 NameStr(attr->attname));
		}
	}
	schema->length = main_sz;

	file_sz = PAGE_ALIGN(offsetof(GpuStoreBaseFileHead, schema) + main_sz);
	hbuf->rowid_map_offset = file_sz;
	rowmap_sz = gstoreFdwRowIdMapSize(nrooms);
	file_sz += PAGE_ALIGN(rowmap_sz);
	if (gs_sstate->primary_key >= 0)
	{
		hbuf->hash_index_offset = file_sz;
		hash_sz = offsetof(GpuStoreHashIndexHead, slots[nslots + nrooms]);
		file_sz += PAGE_ALIGN(hash_sz);
	}
	if (schema->has_varlena)
	{
		hbuf->schema.extra_hoffset
			= file_sz - offsetof(GpuStoreBaseFileHead, schema);
		file_sz += PAGE_ALIGN(extra_sz);
	}
	/* Write out GpuStoreBaseFileHead section */
	if (__writeFile(rawfd, hbuf, hbuf_sz) != hbuf_sz)
		elog(ERROR, "failed on __writeFile('%s'): %m", base_file);
	/* Expand the file size */
	if (posix_fallocate(rawfd, 0, file_sz) != 0)
		elog(ERROR, "failed on posix_fallocate('%s',%zu): %m",
			 base_file, file_sz);
	/* Write out GpuStoreRowIdMapHead section */
	{
		GpuStoreRowIdMapHead *rowid_map = palloc(rowmap_sz);
		cl_uint		i;

		memcpy(rowid_map->signature, GPUSTORE_ROWIDMAP_SIGNATURE, 8);
		rowid_map->length = rowmap_sz;
		rowid_map->nrooms = gs_sstate->max_num_rows;
		rowid_map->first_free_rowid = 0;
		for (i=0; i < gs_sstate->max_num_rows; i++)
			rowid_map->rowid_chain[i] = i+1;
		rowid_map->rowid_chain[gs_sstate->max_num_rows - 1] = UINT_MAX;

		if (lseek(rawfd, hbuf->rowid_map_offset, SEEK_SET) < 0)
			elog(ERROR, "failed on lseek('%s',%zu): %m",
				 base_file, hbuf->rowid_map_offset);
		if (__writeFile(rawfd, rowid_map, rowmap_sz) != rowmap_sz)
			elog(ERROR, "failed on __writeFile('%s'): %m", base_file);
		pfree(rowid_map);
	}
	/* Write out GpuStoreHashHead section (if PK is configured) */
	if (gs_sstate->primary_key >= 0)
	{
		GpuStoreHashIndexHead hindex_buf;
		uint32		rowid_buf[4096];
		size_t		nbytes;

		memset(&hindex_buf, 0, sizeof(GpuStoreHashIndexHead));
		memcpy(hindex_buf.signature, GPUSTORE_HASHINDEX_SIGNATURE, 8);
		hindex_buf.nrooms = gs_sstate->max_num_rows;
		hindex_buf.nslots = gs_sstate->num_hash_slots;

		if (lseek(rawfd, hbuf->hash_index_offset, SEEK_SET) < 0)
			elog(ERROR, "failed on lseek('%s',%zu): %m",
				 base_file, hbuf->hash_index_offset);
		sz = offsetof(GpuStoreHashIndexHead, slots);
		if (__writeFile(rawfd, &hindex_buf, sz) != sz)
			elog(ERROR, "failed on __writeFile('%s'): %m", base_file);

		/* '-1' initialization for all the hash-slots/rowid-array */
		memset(rowid_buf, -1, sizeof(rowid_buf));
		nbytes = sizeof(uint32) * (hindex_buf.nrooms + hindex_buf.nslots);
		while (nbytes > 0)
		{
			sz = Min(nbytes, sizeof(rowid_buf));
			if (__writeFile(rawfd, rowid_buf, sz) != sz)
				elog(ERROR, "failed on __writeFile('%s'): %m", base_file);
			nbytes -= sz;
		}
	}

	/* write out kern_data_extra section (if any varlena) */
	if (schema->has_varlena)
	{
		kern_data_extra		extra;

		memset(&extra, 0, offsetof(kern_data_extra, data));
		memcpy(extra.signature, GPUSTORE_EXTRABUF_SIGNATURE, 8);
		extra.length = extra_sz;
		extra.usage = offsetof(kern_data_extra, data);

		sz = offsetof(GpuStoreBaseFileHead,
					  schema) + hbuf->schema.extra_hoffset;
		if (lseek(rawfd, sz, SEEK_SET) < 0)
			elog(ERROR, "failed on lseek('%s',%zu): %m",
				 base_file, hbuf->schema.extra_hoffset);
		sz = offsetof(kern_data_extra, data);
		if (__writeFile(rawfd, &extra, sz) != sz)
			elog(ERROR, "failed on __writeFile('%s'): %m", base_file);
	}
	pfree(__tupdesc);
}

/*
 * gstoreFdwValidateBaseFile
 */
static bool
gstoreFdwValidateBaseFile(Relation frel,
						  GpuStoreSharedState *gs_sstate,
						  bool validation_by_reuse)
{
	TupleDesc	__tupdesc = gstoreFdwDeviceTupleDesc(frel);
	size_t		nrooms = gs_sstate->max_num_rows;
	size_t		nslots = gs_sstate->num_hash_slots;
	size_t		mmap_sz;
	int			mmap_is_pmem;
	size_t		main_sz, sz;
	size_t		file_pos;
	cl_uint		rowid;
	int			j, unitsz;
	bool		retval = false;
	GpuStoreBaseFileHead *base_mmap;
	GpuStoreRowIdMapHead *rowid_map = NULL;
	GpuStoreHashIndexHead *hash_index = NULL;
	kern_data_store *schema;
	kern_colmeta *cmeta;

	base_mmap = pmem_map_file(gs_sstate->base_file, 0,
							  0, 0600,
							  &mmap_sz,
							  &mmap_is_pmem);
	if (!base_mmap)
		elog(ERROR, "failed on pmem_map_file('%s'): %m",
			 gs_sstate->base_file);
	PG_TRY();
	{
		/* GpuStoreBaseFileHead validation  */
		if (memcmp(base_mmap->signature,
				   GPUSTORE_BASEFILE_SIGNATURE, 8) != 0)
		{
			if (memcmp(base_mmap->signature,
					   GPUSTORE_BASEFILE_MAPPED_SIGNATURE, 8) != 0)
				elog(ERROR, "file '%s' has wrong signature",
                     gs_sstate->base_file);
			/* PostgreSQL might exit by crash last time */
			retval = false;
		}
		main_sz = KDS_calculateHeadSize(__tupdesc);
		if (offsetof(GpuStoreBaseFileHead, schema) + main_sz > mmap_sz)
			elog(ERROR, "file '%s' is too small than expects",
				 gs_sstate->base_file);

		schema = &base_mmap->schema;
		if (schema->ncols != __tupdesc->natts ||
			schema->nrooms != nrooms ||
			schema->format != KDS_FORMAT_COLUMN ||
			schema->tdtypeid != __tupdesc->tdtypeid ||
			schema->tdtypmod != __tupdesc->tdtypmod)
		{
			elog(ERROR, "Base file '%s' has incompatible schema definition",
				 gs_sstate->base_file);
		}

		if (schema->nitems > schema->nrooms)
		{
			elog(ERROR, "Base file '%s' has larger nitems (%u) than nrooms (%u)",
				 gs_sstate->base_file, schema->nitems, schema->nrooms);
		}

		if (schema->table_oid != RelationGetRelid(frel))
		{
			if (!validation_by_reuse)
				elog(ERROR, "Base file '%s' has incompatible schema definition",
					 gs_sstate->base_file);
			schema->table_oid = RelationGetRelid(frel);
		}
		
		for (j=0; j < __tupdesc->natts; j++)
		{
			Form_pg_attribute	attr = tupleDescAttr(__tupdesc, j);
			kern_colmeta	   *cmeta = &schema->colmeta[j];

			if ((cmeta->attbyval && !attr->attbyval) ||
				(!cmeta->attbyval && attr->attbyval) ||
				cmeta->attalign != typealign_get_width(attr->attalign) ||
				cmeta->attnum != attr->attnum ||
				cmeta->atttypid != attr->atttypid ||
				cmeta->atttypmod != attr->atttypmod ||
				(cmeta->nullmap_offset != 0 && attr->attnotnull) ||
				(cmeta->nullmap_offset == 0 && !attr->attnotnull))
				elog(ERROR, "Base file '%s' column '%s' is incompatible",
					 gs_sstate->base_file, NameStr(attr->attname));
			if (strcmp(NameStr(cmeta->attname), NameStr(attr->attname)) != 0)
			{
				if (!validation_by_reuse)
					elog(ERROR, "Base file '%s' column '%s' is incompatible",
						 gs_sstate->base_file,
						 NameStr(attr->attname));
				memcpy(&cmeta->attname, &attr->attname, sizeof(NameData));
			}
			
			if (attr->attnotnull)
			{
				if (cmeta->nullmap_offset != 0 ||
					cmeta->nullmap_length != 0)
					elog(ERROR, "Base file '%s' column '%s' is incompatible",
						 gs_sstate->base_file, NameStr(attr->attname));
			}
			else
			{
				sz = MAXALIGN(BITMAPLEN(nrooms));
				if (cmeta->nullmap_offset != __kds_packed(main_sz) ||
					cmeta->nullmap_length != __kds_packed(sz))
					elog(ERROR, "Base file '%s' column '%s' is incompatible",
						 gs_sstate->base_file, NameStr(attr->attname));
				main_sz += sz;
			}
			
			if (attr->attlen > 0)
			{
				unitsz = att_align_nominal(attr->attlen,
										   attr->attalign);
				sz = MAXALIGN(unitsz * nrooms);
				if (cmeta->values_offset != __kds_packed(main_sz) ||
					cmeta->values_length != __kds_packed(sz))
					elog(ERROR, "Base file '%s' column '%s' is incompatible",
						 gs_sstate->base_file, NameStr(attr->attname));
				main_sz += sz;
			}
			else if (attr->attlen == -1)
			{
				sz = MAXALIGN(sizeof(cl_uint) * nrooms);
				if (cmeta->values_offset != __kds_packed(main_sz) ||
					cmeta->values_length != __kds_packed(sz))
					elog(ERROR, "Base file '%s' column '%s' is incompatible",
						 gs_sstate->base_file, NameStr(attr->attname));
				main_sz += sz;
			}
			else
			{
				elog(ERROR, "unexpected type length (%d) at %s.%s",
					 attr->attlen,
					 RelationGetRelationName(frel),
					 NameStr(attr->attname));
			}
		}
		if (main_sz != schema->length ||
			main_sz >  mmap_sz)
			elog(ERROR, "Base file '%s' is too small then required",
				 gs_sstate->base_file);
		file_pos = PAGE_ALIGN(offsetof(GpuStoreBaseFileHead, schema) + main_sz);

		/*
		 * fixup system attributes for committed rows
		 */
		cmeta = &schema->colmeta[schema->ncols - 1];
		for (rowid=0; rowid < schema->nitems; rowid++)
		{
			GstoreFdwSysattr *sysattr;
			Datum		datum;
			bool		isnull;

			datum = KDS_fetch_datum_column(schema, cmeta, rowid, &isnull);
			if (isnull)
				elog(ERROR, "Base file '%s' rowid=%u has NULL for system attribute",
					 gs_sstate->base_file, rowid);
			sysattr = (GstoreFdwSysattr *)DatumGetPointer(datum);
			if (sysattr->xmin == InvalidTransactionId)
				continue;
			if (sysattr->xmin != FrozenTransactionId)
			{
				if (TransactionIdDidCommit(sysattr->xmin))
					sysattr->xmin = FrozenTransactionId;
				else
				{
					sysattr->xmin = InvalidTransactionId;
					continue;
				}
			}
			if (TransactionIdIsNormal(sysattr->xmax))
			{
				if (TransactionIdDidCommit(sysattr->xmax))
					sysattr->xmax = FrozenTransactionId;
				else
					sysattr->xmax = InvalidTransactionId;
			}
		}

		/*
		 * validate GpuStoreRowIdMapHead section
		 */
		sz = gstoreFdwRowIdMapSize(nrooms);
		if (base_mmap->rowid_map_offset + sz > mmap_sz)
			elog(ERROR, "Base file '%s' is too small then necessity",
				 gs_sstate->base_file);
		rowid_map = (GpuStoreRowIdMapHead *)
			((char *)base_mmap + base_mmap->rowid_map_offset);
		if (base_mmap->rowid_map_offset != file_pos ||
			memcmp(rowid_map->signature,
				   GPUSTORE_ROWIDMAP_SIGNATURE, 8) != 0 ||
			rowid_map->length != sz ||
			rowid_map->nrooms != nrooms)
			elog(ERROR, "Base file '%s' has corrupted RowID-map",
				 gs_sstate->base_file);
		file_pos += PAGE_ALIGN(sz);

		/*
		 * validate GpuStoreHashIndexHead section, if any
		 */
		if (gs_sstate->primary_key < 0)
		{
			if (base_mmap->hash_index_offset != 0)
				elog(ERROR, "Base file '%s' has PK Index, but foreign-table '%s' has no primary key definition",
					 gs_sstate->base_file, RelationGetRelationName(frel));
		}
		else
		{
			if (base_mmap->hash_index_offset == 0)
				elog(ERROR, "Base file '%s' has no PK Index, but foreign-table '%s' has primary key definition",
					 gs_sstate->base_file,
					 RelationGetRelationName(frel));
			sz = offsetof(GpuStoreHashIndexHead, slots[nslots + nrooms]);
			if (base_mmap->hash_index_offset + sz > mmap_sz)
				elog(ERROR, "Base file '%s' is smaller then the estimation",
					 gs_sstate->base_file);
			hash_index = (GpuStoreHashIndexHead *)
				((char *)base_mmap + base_mmap->hash_index_offset);
			if (base_mmap->hash_index_offset != file_pos ||
				memcmp(hash_index->signature,
					   GPUSTORE_HASHINDEX_SIGNATURE, 8) != 0 ||
				hash_index->nrooms != nrooms ||
				hash_index->nslots != nslots)
				elog(ERROR, "Base file '%s' has corrupted Hash-index",
					 gs_sstate->base_file);
			file_pos += PAGE_ALIGN(sz);
		}

		/*
		 * validate Extra Buffer of varlena, if any
		 */
		if (!schema->has_varlena)
		{
			if (base_mmap->schema.extra_hoffset != 0)
				elog(ERROR, "Base file '%s' has extra buffer, but foreign-table '%s' has no variable-length fields",
					 gs_sstate->base_file, RelationGetRelationName(frel));
		}
		else
		{
			kern_data_store *schema = &base_mmap->schema;
			kern_data_extra *extra = (kern_data_extra *)
				((char *)schema + schema->extra_hoffset);

			if (schema->extra_hoffset == 0)
				elog(ERROR, "Base file '%s' has no extra buffer, but foreign-table '%s' has variable-length fields",
					 gs_sstate->base_file, RelationGetRelationName(frel));
			if ((char *)extra - (char *)base_mmap != file_pos ||
				memcmp(extra->signature, GPUSTORE_EXTRABUF_SIGNATURE, 8) != 0)
				elog(ERROR, "Base file '%s' has corrupted extra-buffer %zu %zu",
					 gs_sstate->base_file,
					 (char *)extra - (char *)base_mmap,
					 file_pos

					);
			if (offsetof(GpuStoreBaseFileHead, schema) +
				schema->extra_hoffset + extra->length > mmap_sz)
				elog(ERROR, "Base file '%s' is smaller then the required",
					 gs_sstate->base_file);
			if (extra->usage > extra->length)
				elog(ERROR, "Extra buffer of base file '%s' has larger usage (%lu) than length (%lu)", gs_sstate->base_file, extra->usage, extra->length);
		}
		/* Ok, base-file is sanity */
		retval = true;
	}
	PG_CATCH();
	{
		if (pmem_unmap(base_mmap, mmap_sz) != 0)
			elog(WARNING, "failed on pmem_unmap: %m");
		PG_RE_THROW();
	}
	PG_END_TRY();
	/* Ok, validated */
	memcpy(base_mmap->signature, GPUSTORE_BASEFILE_MAPPED_SIGNATURE, 8);
	if (pmem_unmap(base_mmap, mmap_sz) != 0)
		elog(WARNING, "failed on pmem_unmap: %m");
	pfree(__tupdesc);

	return retval;
}

/*
 * GSTORE_TX_LOG__INSERT
 */
static void
__ApplyRedoLogInsert(Relation frel,
					 GpuStoreBaseFileHead *base_mmap, size_t base_mmap_sz,
					 GstoreTxLogInsert *i_log)
{
	TupleDesc		tupdesc = RelationGetDescr(frel);
	Datum		   *values = alloca(sizeof(Datum) * tupdesc->natts);
	bool		   *isnull = alloca(sizeof(bool) * tupdesc->natts);
	kern_data_store *kds = &base_mmap->schema;
	HeapTupleData	tuple;
	GstoreFdwSysattr sysattr;
	int				j;

	memset(&tuple, 0, sizeof(HeapTupleData));
	tuple.t_data = &i_log->htup;
	heap_deform_tuple(&tuple, tupdesc, values, isnull);
	Assert(kds->ncols == tupdesc->natts + 1);	/* + sysattr */
	for (j=0; j < tupdesc->natts; j++)
	{
		KDS_store_datum_column(kds, &kds->colmeta[j],
							   i_log->rowid,
							   values[j], isnull[j]);
	}
	memset(&sysattr, 0, sizeof(GstoreFdwSysattr));
	sysattr.xmin = HeapTupleHeaderGetRawXmin(&i_log->htup);
	sysattr.xmax = HeapTupleHeaderGetRawXmax(&i_log->htup);
	sysattr.cid  = HeapTupleHeaderGetRawCommandId(&i_log->htup);
	KDS_store_datum_column(kds, &kds->colmeta[kds->ncols-1],
						   i_log->rowid,
						   PointerGetDatum(&sysattr), false);
}

/*
 * GSTORE_TX_LOG__DELETE
 */
static void
__ApplyRedoLogDelete(Relation frel,
					 GpuStoreBaseFileHead *base_mmap, size_t base_mmap_sz,
					 GstoreTxLogDelete *d_log)
{
	kern_data_store *kds = &base_mmap->schema;
	GstoreFdwSysattr *sysattr;
	bool			isnull;

	sysattr = (GstoreFdwSysattr *)
		KDS_fetch_datum_column(kds, &kds->colmeta[kds->ncols-1],
							   d_log->rowid, &isnull);
	Assert(!isnull);
	/* xmax & cid */
	sysattr->xmin = d_log->xmin;
	sysattr->xmax = d_log->xmax;
	sysattr->cid  = InvalidCommandId;
}

/*
 * Rebuild HashIndex
 */
static void
__rebuildHashIndexEntry(GpuStoreSharedState *gs_sstate,
						kern_data_store *kds,
						GpuStoreHashIndexHead *hash_index,
						cl_uint rowid)
{
	kern_colmeta   *cmeta;
	TypeCacheEntry *tcache;
	Datum			hash;
	Datum			kdatum;
	Datum			cdatum;
	bool			isnull;
	cl_uint		   *rowmap = &hash_index->slots[hash_index->nslots];
	cl_uint			curr_id, k;

	Assert(gs_sstate->primary_key > 0 &&
		   gs_sstate->primary_key <= kds->ncols);
	Assert(hash_index->nrooms == kds->nrooms);
	if (rowid >= hash_index->nrooms)
		elog(ERROR, "Bug? rowid=%u is larger than index's nrooms=%lu",
			 rowid, hash_index->nrooms);
	cmeta = &kds->colmeta[gs_sstate->primary_key - 1];
	tcache = lookup_type_cache(cmeta->atttypid,
							   TYPECACHE_EQ_OPR_FINFO |
							   TYPECACHE_HASH_PROC_FINFO);
	kdatum = KDS_fetch_datum_column(kds, cmeta, rowid, &isnull);
	if (isnull)
		elog(ERROR, "primary key '%s' of foreign table '%s' is NULL",
			 NameStr(cmeta->attname), get_rel_name(kds->table_oid));
	hash = FunctionCall1(&tcache->hash_proc_finfo, kdatum);
	k = hash % hash_index->nslots;
	for (curr_id = hash_index->slots[k];
		 curr_id < hash_index->nrooms;
		 curr_id = rowmap[curr_id])
	{
		cdatum = KDS_fetch_datum_column(kds, cmeta, curr_id, &isnull);
		if (isnull)
		{
			elog(WARNING, "Bug? primary key '%s' has NULL at rowid=%u, ignored",
				 NameStr(cmeta->attname), curr_id);
			continue;
		}
		if (DatumGetBool(FunctionCall2(&tcache->eq_opr_finfo,
									   kdatum, cdatum)))
		{
			Oid		typoutput;
			bool	typisvarlena;

			getTypeOutputInfo(cmeta->atttypid,
							  &typoutput,
							  &typisvarlena);
			elog(WARNING, "duplicate PK violation; %s = %s already exists, ignored",
				 NameStr(cmeta->attname),
				 OidOutputFunctionCall(typoutput, kdatum));
		}
	}
	rowmap[rowid] = hash_index->slots[k];
	hash_index->slots[k] = rowid;
}

static void
__rebuildRowIdMapAndHashIndex(Relation frel,
							  GpuStoreSharedState *gs_sstate,
							  GpuStoreBaseFileHead *base_mmap,
							  size_t base_mmap_sz)
{
	kern_data_store *kds = &base_mmap->schema;
	kern_colmeta *smeta = &kds->colmeta[kds->ncols - 1];	/* sysattr */
	GpuStoreRowIdMapHead *rowid_map = NULL;
	GpuStoreHashIndexHead *hash_index = NULL;
	size_t		nrooms = gs_sstate->max_num_rows;
	size_t		nslots = gs_sstate->num_hash_slots;
	size_t		rowid_map_sz;
	cl_uint		i, rowid;

	/* clean-up rowid-map */
	rowid_map_sz = gstoreFdwRowIdMapSize(kds->nrooms);
	rowid_map = (GpuStoreRowIdMapHead *)
		((char *)base_mmap + base_mmap->rowid_map_offset);
	memset(rowid_map, 0, rowid_map_sz);
	memcpy(rowid_map->signature, GPUSTORE_ROWIDMAP_SIGNATURE, 8);
	rowid_map->length = rowid_map_sz;
	rowid_map->nrooms = kds->nrooms;
	rowid_map->first_free_rowid = UINT_MAX;

	/* clean-up hash-index */
	if (base_mmap->hash_index_offset != 0)
	{
		hash_index = (GpuStoreHashIndexHead *)
			((char *)base_mmap + base_mmap->hash_index_offset);
		memcpy(hash_index->signature, GPUSTORE_HASHINDEX_SIGNATURE, 8);
		hash_index->nrooms = nrooms;
		hash_index->nslots = nslots;
		memset(hash_index->slots, -1, sizeof(cl_uint) * (nslots + nrooms));
	}

	for (rowid=0; rowid < kds->nitems; rowid++)
	{
		GstoreFdwSysattr *sysattr;
		bool		isnull;

		sysattr = (GstoreFdwSysattr *)
			KDS_fetch_datum_column(kds, smeta, rowid, &isnull);
		if (isnull)
		{
			elog(WARNING, "foreign table '%s', rowid=%u has NULL on system column",
				 RelationGetRelationName(frel), rowid);
			continue;
		}
		if ((sysattr->xmin == FrozenTransactionId ||
			 TransactionIdDidCommit(sysattr->xmin)) &&
			(sysattr->xmax != FrozenTransactionId &&
			 !TransactionIdDidCommit(sysattr->xmax)))
		{
			rowid_map->rowid_chain[rowid] = UINT_MAX;
			if (hash_index)
				__rebuildHashIndexEntry(gs_sstate, kds, hash_index, rowid);
		}
	}

	for (i=rowid_map->nrooms; i > 0; i--)
	{
		rowid = i - 1;

		if (rowid_map->rowid_chain[rowid] == UINT_MAX)
			continue;
		rowid_map->rowid_chain[rowid] = rowid_map->first_free_rowid;
		rowid_map->first_free_rowid = rowid;
	}
}

static void
gstoreFdwApplyRedoHostBuffer(Relation frel, GpuStoreSharedState *gs_sstate,
							 bool basefile_is_sanity)
{
	GpuStoreBaseFileHead *base_mmap = NULL;
	size_t		base_mmap_sz;
	int			base_is_pmem;
	char	   *redo_mmap = NULL;
	size_t		redo_mmap_sz;
	int			redo_is_pmem;

	PG_TRY();
	{
		cl_uint		i, nitems = 0;
		char	   *pos, *end;
		uint64		start_pos;
		StringInfoData buf;

		base_mmap = pmem_map_file(gs_sstate->base_file, 0,
								  0, 0600,
								  &base_mmap_sz,
								  &base_is_pmem);
		if (!base_mmap)
			elog(ERROR, "failed on pmem_map_file('%s'): %m",
				 gs_sstate->base_file);
		redo_mmap = pmem_map_file(gs_sstate->redo_log_file, 0,
								  0, 0600,
								  &redo_mmap_sz,
								  &redo_is_pmem);
		if (!redo_mmap)
			elog(ERROR, "failed on pmem_map_file('%s'): %m",
				 gs_sstate->redo_log_file);
		/*
		 * Seek to the position where last written
		 */
		initStringInfo(&buf);
		pos = redo_mmap;
		end = redo_mmap + gs_sstate->redo_log_limit;
		while (pos + offsetof(GstoreTxLogCommon, data) <= end)
		{
			GstoreTxLogCommon *curr = (GstoreTxLogCommon *)pos;

			if (((curr->type == GSTORE_TX_LOG__INSERT) ||
				 (curr->type == GSTORE_TX_LOG__DELETE) ||
				 (curr->type == GSTORE_TX_LOG__COMMIT)) &&
				curr->length == MAXALIGN(curr->length) &&
				(char *)curr + curr->length <= end)
			{
				enlargeStringInfo(&buf, sizeof(GstoreTxLogCommon *));
				((GstoreTxLogCommon **)buf.data)[nitems++] = curr;
				buf.len += sizeof(GstoreTxLogCommon *);
				pos += curr->length;
				continue;
			}
			break;
		}

		if (!basefile_is_sanity)
		{
			elog(LOG, "foreign table '%s' begins to apply redo log [%s] onto the base file[%s]",
				 RelationGetRelationName(frel),
				 gs_sstate->redo_log_file,
				 gs_sstate->base_file);
			for (i=0; i < nitems; i++)
			{
				GstoreTxLogCommon *tx_log = ((GstoreTxLogCommon **)buf.data)[i];

				switch (tx_log->type)
				{
					case GSTORE_TX_LOG__INSERT:
						__ApplyRedoLogInsert(frel, base_mmap, base_mmap_sz,
											 (GstoreTxLogInsert *)tx_log);
						break;
					case GSTORE_TX_LOG__DELETE:
						__ApplyRedoLogDelete(frel, base_mmap, base_mmap_sz,
											 (GstoreTxLogDelete *)tx_log);
						break;
					default:
						/* skip GSTORE_TX_LOG__COMMIT - to be fixed up later */
						break;
				}
			}
			/* rebuild row-id map and PK hash-index */
			__rebuildRowIdMapAndHashIndex(frel, gs_sstate, base_mmap, base_mmap_sz);
			if (base_is_pmem)
				pmem_persist(base_mmap, base_mmap_sz);
			else
				pmem_msync(base_mmap, base_mmap_sz);
			elog(LOG, "foreign table '%s' recovery done %u logs were applied",
				RelationGetRelationName(frel), nitems);
		}
		start_pos = (pos - (char *)redo_mmap);
		gs_sstate->redo_write_pos = start_pos;
		gs_sstate->redo_read_pos  = start_pos;
		gs_sstate->redo_sync_pos  = start_pos;
		gs_sstate->redo_repl_pos[0] = ULONG_MAX;
		gs_sstate->redo_repl_pos[1] = ULONG_MAX;
		gs_sstate->redo_repl_pos[2] = ULONG_MAX;
		gs_sstate->redo_repl_pos[3] = ULONG_MAX;
		pfree(buf.data);
	}
	PG_CATCH();
	{
		if (base_mmap)
			pmem_unmap(base_mmap, base_mmap_sz);
		if (redo_mmap)
			pmem_unmap(redo_mmap, redo_mmap_sz);
		PG_RE_THROW();
	}
	PG_END_TRY();
	if (pmem_unmap(base_mmap, base_mmap_sz) != 0)
		elog(WARNING, "failed on pmem_unmap('%s',%zu): %m",
			 gs_sstate->base_file, base_mmap_sz);
	if (pmem_unmap(redo_mmap, redo_mmap_sz) != 0)
		elog(WARNING, "failed on pmem_unmap('%s',%zu): %m",
			 gs_sstate->redo_log_file, redo_mmap_sz);
}

static GpuStoreSharedState *
gstoreFdwCreateSharedState(Relation frel, bool may_create_files)
{
	GpuStoreSharedState *gs_sstate = gstoreFdwAllocSharedState(frel);
	File		fdesc;
	size_t		sz;
	bool		base_is_sanity = true;
	bool		base_create = false;
	bool		redo_create = false;

	PG_TRY();
	{
		/*
		 * Try to create a new base file only if post-creation event trigger.
		 * Or, validate existing base file
		 */
		if (may_create_files)
		{
			fdesc = PathNameOpenFile(gs_sstate->base_file,
									 O_RDWR | O_CREAT | O_EXCL);
			if (fdesc < 0)
			{
				if (errno == EEXIST)
					base_is_sanity = gstoreFdwValidateBaseFile(frel, gs_sstate, true);
				else
					elog(ERROR, "failed on open('%s'): %m", gs_sstate->base_file);
			}
			else
			{
				base_create = true;
				gstoreFdwCreateBaseFile(frel, gs_sstate, fdesc);
				FileClose(fdesc);
			}
		}
		else
		{
			base_is_sanity = gstoreFdwValidateBaseFile(frel, gs_sstate, false);
		}

		/*
		 * Try to allocate a new redo-log file, or only expand the size
		 */
		fdesc = PathNameOpenFile(gs_sstate->redo_log_file, O_RDWR);
		if (fdesc < 0)
		{
			if (errno != ENOENT || !may_create_files)
				elog(ERROR, "failed on open('%s'): %m", gs_sstate->redo_log_file);
			fdesc = PathNameOpenFile(gs_sstate->redo_log_file,
									 O_RDWR | O_CREAT | O_EXCL);
			if (fdesc < 0)
				elog(ERROR, "failed on open('%s'): %m", gs_sstate->redo_log_file);
		}
		sz = PAGE_ALIGN(gs_sstate->redo_log_limit);
		if (posix_fallocate(FileGetRawDesc(fdesc), 0, sz) != 0)
			elog(ERROR, "failed on posix_fallocate('%s',%zu): %m",
				 gs_sstate->redo_log_file, sz);
		FileClose(fdesc);

		/*
		 * Apply redo-log onto the base file, if needed
		 */
        gstoreFdwApplyRedoHostBuffer(frel, gs_sstate, base_is_sanity);
	}
	PG_CATCH();
	{
		if (base_create)
			unlink(gs_sstate->base_file);
		if (redo_create)
			unlink(gs_sstate->redo_log_file);
		pfree(gs_sstate);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return gs_sstate;
}

static bool
gstoreFdwRemapBaseFile(GpuStoreDesc *gs_desc, bool abort_on_error)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	GpuStoreBaseFileHead   *base_mmap;

	if (gs_desc->base_mmap != NULL)
	{
		if (pmem_unmap(gs_desc->base_mmap,
					   gs_desc->base_mmap_sz) != 0)
			elog(WARNING, "failed on pmem_unmap('%s'): %m",
				 gs_sstate->base_file);
	}
	gs_desc->base_mmap = pmem_map_file(gs_sstate->base_file, 0,
									   0, 0600,
									   &gs_desc->base_mmap_sz,
									   &gs_desc->base_mmap_is_pmem);
	if (!gs_desc->base_mmap)
	{
		gs_desc->rowid_map = NULL;
		gs_desc->hash_index = NULL;
		gs_desc->base_mmap_revision = UINT_MAX;
		elog(abort_on_error ? ERROR : LOG,
			 "failed on pmem_map_file('%s'): %m",
			 gs_sstate->base_file);
		return false;
	}
	base_mmap = gs_desc->base_mmap;
	gs_desc->rowid_map = (GpuStoreRowIdMapHead *)
		((char *)base_mmap + base_mmap->rowid_map_offset);
	if (base_mmap->hash_index_offset == 0)
		gs_desc->hash_index = NULL;
	else
		gs_desc->hash_index = (GpuStoreHashIndexHead *)
			((char *)base_mmap + base_mmap->hash_index_offset);
	gs_desc->base_mmap_revision = gs_sstate->base_mmap_revision;

	return true;
}

static GpuStoreSharedState *
gstoreFdwLookupGpuStoreSharedState(Relation frel, bool may_create_files)
{
	GpuStoreSharedState *gs_sstate = NULL;
	GpuStoreSharedState *temp;
	Oid			hkey[2];
	uint32		hash;
	int			hindex;
	slock_t	   *lock;
	dlist_head *slot;
	dlist_iter	iter;

	hkey[0] = MyDatabaseId;
	hkey[1] = RelationGetRelid(frel);
	hash = hash_any((const unsigned char *)hkey, 2 * sizeof(Oid));
	hindex = hash % GPUSTORE_SHARED_DESC_NSLOTS;
	lock = &gstore_shared_head->gstore_sstate_lock[hindex];
	slot = &gstore_shared_head->gstore_sstate_slot[hindex];

	SpinLockAcquire(lock);
	PG_TRY();
	{
		dlist_foreach(iter, slot)
		{
			temp = dlist_container(GpuStoreSharedState,
								   hash_chain, iter.cur);
			if (temp->database_oid == MyDatabaseId &&
				temp->ftable_oid == RelationGetRelid(frel))
			{
				gs_sstate = temp;
				break;
			}
		}
		if (!gs_sstate)
		{
			gs_sstate = gstoreFdwCreateSharedState(frel, may_create_files);
			dlist_push_tail(slot, &gs_sstate->hash_chain);
			gstoreFdwInvokeInitialLoad(gs_sstate->ftable_oid,
									   gs_sstate->cuda_dindex, true);
			Assert(gs_sstate->hash == hash);
		}
	}
	PG_CATCH();
	{
		SpinLockRelease(lock);
		PG_RE_THROW();
	}
	PG_END_TRY();
	SpinLockRelease(lock);

	return gs_sstate;
}

static void
gstoreFdwInitGpuStoreDesc(GpuStoreDesc *gs_desc, GpuStoreSharedState *gs_sstate)
{
	gs_desc->xmin_ftable = FrozenTransactionId;
	gs_desc->xmax_ftable = InvalidTransactionId;
	gs_desc->gs_sstate  = gs_sstate;
	dlist_init(&gs_desc->gs_undo_logs);
	/* base file mapping */
	gs_desc->base_mmap = NULL;
	gs_desc->base_mmap_revision = UINT_MAX;
	gs_desc->base_mmap_is_pmem = 0;
	gs_desc->rowid_map = NULL;
	gs_desc->hash_index = NULL;
	/* redo-log file mapping */
	gs_desc->redo_mmap = NULL;
	gs_desc->redo_mmap_sz = 0;
	gs_desc->redo_mmap_is_pmem = 0;
	/* background-worker only fields */
	gs_desc->gpu_main_devptr = 0UL;
	gs_desc->gpu_extra_devptr = 0UL;
}

static bool
gstoreFdwSetupGpuStoreDesc(GpuStoreDesc *gs_desc, bool abort_on_error)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;

	/* memory map the base-file */
	LWLockAcquire(&gs_sstate->base_mmap_lock, LW_SHARED);
	if (gs_desc->base_mmap == NULL ||
		gs_desc->base_mmap_revision != gs_sstate->base_mmap_revision)
	{
		if (!gstoreFdwRemapBaseFile(gs_desc, abort_on_error))
		{
			LWLockRelease(&gs_sstate->base_mmap_lock);
			return false;
		}
	}
	LWLockRelease(&gs_sstate->base_mmap_lock);

	/* memory map redo-log file */
	if (gs_desc->redo_mmap == NULL)
	{
		gs_desc->redo_mmap = pmem_map_file(gs_sstate->redo_log_file, 0,
										   0, 0600,
										   &gs_desc->redo_mmap_sz,
										   &gs_desc->redo_mmap_is_pmem);
		if (!gs_desc->redo_mmap)
		{
			elog(abort_on_error ? ERROR : LOG,
				 "failed on pmem_map_file('%s'): %m",
				 gs_sstate->redo_log_file);
			LWLockRelease(&gs_sstate->base_mmap_lock);
			return false;
		}
	}
	return true;
}

static GpuStoreDesc *
__gstoreFdwLookupGpuStoreDesc(Relation frel, bool may_create_files)
{
	GpuStoreDesc *gs_desc;
	Oid			hkey[2];
	bool		found;

	if (!RelationIsGstoreFdw(frel))
		elog(ERROR, "relation '%s' is not a foreign table managed by gstore_fdw",
			 RelationGetRelationName(frel));

	hkey[0] = MyDatabaseId;
	hkey[1] = RelationGetRelid(frel);
	gs_desc = (GpuStoreDesc *) hash_search(gstore_desc_htab,
										   &hkey,
										   HASH_ENTER,
										   &found);
	if (!found)
	{
		PG_TRY();
        {
			GpuStoreSharedState *gs_sstate
				= gstoreFdwLookupGpuStoreSharedState(frel, may_create_files);
			gstoreFdwInitGpuStoreDesc(gs_desc, gs_sstate);
		}
		PG_CATCH();
		{
			hash_search(gstore_desc_htab, &hkey, HASH_REMOVE, NULL);
			PG_RE_THROW();
		}
		PG_END_TRY();
	}
	/* ensure base file mapping is latest revision */
	gstoreFdwSetupGpuStoreDesc(gs_desc, true);
	return gs_desc;
}

static GpuStoreDesc *
gstoreFdwLookupGpuStoreDesc(Relation frel)
{
	return __gstoreFdwLookupGpuStoreDesc(frel, false);
}

/*
 * __gstoreFdwXactOnPreCommit
 */
static void
__gstoreFdwXactOnPreCommit(GpuStoreDesc *gs_desc, GpuStoreUndoLogs *gs_undo,
						   uint64 *p_written_pos)
{
	GstoreTxLogCommit *c_log = alloca(GSTORE_TX_LOG_COMMIT_ALLOCSZ);
	char		   *pos = gs_undo->buf.data;
	cl_uint			count = 1;
	uint64			written_pos = 0;

	/* setup commit log buffer */
	c_log->type = GSTORE_TX_LOG__COMMIT;
	c_log->length = offsetof(GstoreTxLogCommit, data);
	c_log->xid = gs_undo->curr_xid;
	c_log->timestamp = GetCurrentTimestamp();
	c_log->nitems = 0;

	while (count <= gs_undo->nitems)
	{
		bool	flush_commit_log = (count == gs_undo->nitems);
		
		switch (*pos)
		{
			case 'I':	/* INSERT with rowid(u32) */
			case 'D':	/* DELETE with rowid(u32) */
				if (c_log->length + 5 > GSTORE_TX_LOG_COMMIT_ALLOCSZ)
				{
					flush_commit_log = true;
					break;
				}
				memcpy((char *)c_log + c_log->length, pos, 5);
				c_log->length += 5;
				c_log->nitems++;
				pos += 5;
				count++;
				break;

			case 'A':	/* Add PK Index with hash(u32) + rowid(u32) */
			case 'R':	/* Remove PK Index + hash(u32) + rowid(u32) */
				/* skip in the pre-commit phase */
				pos += sizeof(char) + 2 * sizeof(cl_uint);
				count++;
				break;
			default:
				elog(FATAL, "Broken internal Undo log: tag='%c'", *pos);
				break;
		}

		if (flush_commit_log)
		{
			int			diff = MAXALIGN(c_log->length) - c_log->length;

			if (diff > 0)
			{
				memset((char *)c_log + c_log->length, 0, diff);
				c_log->length += diff;
			}
			written_pos = __gstoreFdwAppendRedoLog(gs_desc, (GstoreTxLogCommon *)c_log);
			/* rewind */
			c_log->length = offsetof(GstoreTxLogCommit, data);
			c_log->nitems = 0;
		}
	}
	Assert(pos <= gs_undo->buf.data + gs_undo->buf.len);
	if (p_written_pos)
		*p_written_pos = Max(*p_written_pos, written_pos);
}

/*
 * __gstoreFdwXactSyncRedoLog
 */
static void
__gstoreFdwXactSyncRedoLog(GpuStoreDesc *gs_desc, uint64 written_pos)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	uint64		sync_pos = gs_sstate->redo_sync_pos;
	uint64		__sync_pos = sync_pos % gs_sstate->redo_log_limit;
	uint64		__written_pos = written_pos % gs_sstate->redo_log_limit;

	if (written_pos <= sync_pos)
		return;
	if (written_pos >= sync_pos + gs_sstate->redo_log_limit)
	{
		/* corner case - entire redo log buffer must be sync */
		if (gs_desc->redo_mmap_is_pmem)
			pmem_persist(gs_desc->redo_mmap,
						 gs_desc->redo_mmap_sz);
		else if (pmem_msync(gs_desc->redo_mmap,
							gs_desc->redo_mmap_sz) != 0)
			elog(WARNING, "failed on pmem_msync('%s'): %m",
				 gs_sstate->redo_log_file);
	}
	else if (__written_pos > __sync_pos)
	{
		char   *ptr = gs_desc->redo_mmap + __sync_pos;
		size_t	sz = __written_pos - __sync_pos;

		if (gs_desc->redo_mmap_is_pmem)
			pmem_persist(ptr, sz);
		else if (pmem_msync(ptr, sz) != 0)
			elog(WARNING, "failed on pmem_msync('%s'): %m",
				 gs_sstate->redo_log_file);
	}
	else
	{
		char   *ptr = gs_desc->redo_mmap + __sync_pos;
		size_t	sz = gs_sstate->redo_log_limit - __sync_pos;

		if (gs_desc->redo_mmap_is_pmem)
		{
			pmem_persist(ptr, sz);
			pmem_persist(gs_desc->redo_mmap, __written_pos);
		}
		else
		{
			if (pmem_msync(ptr, sz) != 0)
				elog(WARNING, "failed on pmem_msync('%s'): %m",
					 gs_sstate->redo_log_file);
			if (pmem_msync(gs_desc->redo_mmap, __written_pos) != 0)
				elog(WARNING, "failed on pmem_msync('%s'): %m",
					 gs_sstate->redo_log_file);
		}
	}
	atomicMax64(&gs_sstate->redo_sync_pos, written_pos);
}

/*
 * __gstoreFdwXactFinalize
 */
static void
__gstoreFdwXactFinalize(GpuStoreDesc *gs_desc,
						GpuStoreUndoLogs *gs_undo, bool normal_commit)
{
	GpuStoreHashIndexHead *hash_index = gs_desc->hash_index;
	char	   *pos = gs_undo->buf.data;
    cl_uint		count;
	
	for (count=0; count < gs_undo->nitems; count++)
	{
		uint32		rowid;

		switch (*pos)
		{
			case 'I':	/* INSERT */
				if (!normal_commit)
				{
					rowid = *((uint32 *)(pos + 1));
					gstoreFdwReleaseRowId(gs_desc->gs_sstate,
										  gs_desc->rowid_map, rowid);
				}
				pos += sizeof(char) + sizeof(uint32);
				break;
			case 'D':	/* DELETE */
				if (normal_commit)
				{
					rowid = *((uint32 *)(pos + 1));
					gstoreFdwReleaseRowId(gs_desc->gs_sstate,
										  gs_desc->rowid_map, rowid);
				}
				pos += sizeof(char) + sizeof(uint32);
				break;
			case 'A':	/* Add PK */
				if (!normal_commit)
				{
					/* remove rowid from the index on abort  */
					uint32	   *rowmap = &hash_index->slots[hash_index->nslots];
					uint32		hash  = *((uint32 *)(pos + 1));
					uint32		rowid = *((uint32 *)(pos + 5));
					uint32	   *next;

					gstoreFdwSpinLockHashSlot(gs_desc, hash);
                    next = &hash_index->slots[hash % hash_index->nslots];
					while (*next < hash_index->nrooms)
					{
						if (*next == rowid)
						{
							*next = rowmap[rowid];
							rowmap[rowid] = UINT_MAX;
							break;
						}
						next = rowmap + *next;
					}
					gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
				}
				pos += sizeof(char) + 2 * sizeof(uint32);
				break;
			case 'R':	/* Remove PK */
				Assert(hash_index != NULL);
				if (normal_commit)
				{
					/* remove rowid from the index on commit */
					uint32	   *rowmap = &hash_index->slots[hash_index->nslots];
					uint32		hash  = *((uint32 *)(pos + 1));
					uint32		rowid = *((uint32 *)(pos + 5));
					uint32	   *next;

					gstoreFdwSpinLockHashSlot(gs_desc, hash);
					next = &hash_index->slots[hash % hash_index->nslots];
					while (*next < hash_index->nrooms)
					{
						if (*next == rowid)
						{
							*next = rowmap[rowid];
							rowmap[rowid] = UINT_MAX;
							break;
						}
						next = rowmap + *next;
					}
					gstoreFdwSpinUnlockHashSlot(gs_desc, hash);
				}
				pos += sizeof(char) + 2 * sizeof(uint32);
				break;
			default:
				elog(FATAL, "wrong undo log entry tag '%c'", *pos);
		}
	}
	Assert(pos <= gs_undo->buf.data + gs_undo->buf.len);
}

/*
 * __gstoreFdwXactDropResources
 */
static void
__gstoreFdwXactDropResources(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	uint32		hindex = gs_sstate->hash % GPUSTORE_SHARED_DESC_NSLOTS;
	CUresult	rc;

	rc = gstoreFdwInvokeDropUnload(gs_sstate->ftable_oid,
								   gs_sstate->cuda_dindex, false);
	if (rc != CUDA_SUCCESS)
		elog(WARNING, "failed on gstoreFdwInvokeDropUnload: %s", errorText(rc));
	SpinLockAcquire(&gstore_shared_head->gstore_sstate_lock[hindex]);
	dlist_delete(&gs_sstate->hash_chain);
	SpinLockRelease(&gstore_shared_head->gstore_sstate_lock[hindex]);

	if (gs_desc->base_mmap)
	{
		if (pmem_unmap(gs_desc->base_mmap,
					   gs_desc->base_mmap_sz) != 0)
			elog(WARNING, "failed on pmem_unmap(): %m");
		gs_desc->base_mmap = NULL;
	}

	if (gs_desc->redo_mmap)
	{
		if (pmem_unmap(gs_desc->redo_mmap,
					   gs_desc->redo_mmap_sz) != 0)
			elog(WARNING, "failed on pmem_unmap(): %m");
		gs_desc->redo_mmap = NULL;
	}
	hash_search(gstore_desc_htab, gs_desc, HASH_REMOVE, NULL);

	/* cleanup base/redo files */
	if (!gs_sstate->preserve_files)
	{
		if (unlink(gs_sstate->base_file) != 0)
			elog(WARNING, "failed on unlink('%s'): %m", gs_sstate->base_file);
		if (unlink(gs_sstate->redo_log_file) != 0)
			elog(WARNING, "failed on unlink('%s'): %m", gs_sstate->redo_log_file);
	}
	pfree(gs_sstate);
}

/*
 * gstoreFdwXactCallback
 */
static void
gstoreFdwXactCallback(XactEvent event, void *arg)
{
	HASH_SEQ_STATUS	hseq;
	GpuStoreDesc   *gs_desc;
	GpuStoreUndoLogs *gs_undo;
	TransactionId	curr_xid = GetCurrentTransactionIdIfAny();
#if 0
	elog(INFO, "XactCallback: ev=%s xid=%u top-xid=%u",
		 event == XACT_EVENT_COMMIT  ? "XACT_EVENT_COMMIT" :
		 event == XACT_EVENT_ABORT   ? "XACT_EVENT_ABORT"  :
		 event == XACT_EVENT_PREPARE ? "XACT_EVENT_PREPARE" :
		 event == XACT_EVENT_PRE_COMMIT ? "XACT_EVENT_PRE_COMMIT" :
		 event == XACT_EVENT_PRE_PREPARE ? "XACT_EVENT_PRE_PREPARE" : "????",
		 GetCurrentTransactionIdIfAny(),
		 GetTopTransactionIdIfAny());
#endif
	if (hash_get_num_entries(gstore_desc_htab) == 0)
		return;
	
	if (event == XACT_EVENT_PRE_COMMIT)
	{
		dlist_iter		iter;

		hash_seq_init(&hseq, gstore_desc_htab);
		while ((gs_desc = hash_seq_search(&hseq)) != NULL)
		{
			uint64	written_pos = 0;

			dlist_foreach (iter, &gs_desc->gs_undo_logs)
			{
				gs_undo = dlist_container(GpuStoreUndoLogs,
										  chain, iter.cur);
				if (gs_undo->curr_xid == curr_xid)
					__gstoreFdwXactOnPreCommit(gs_desc, gs_undo, &written_pos);
			}
			__gstoreFdwXactSyncRedoLog(gs_desc, written_pos);
		}
	}
	else if (event == XACT_EVENT_COMMIT ||
			 event == XACT_EVENT_ABORT)
	{
		dlist_mutable_iter iter;

		hash_seq_init(&hseq, gstore_desc_htab);
		while ((gs_desc = hash_seq_search(&hseq)) != NULL)
		{
			bool	drop_this = false;

			dlist_foreach_modify(iter, &gs_desc->gs_undo_logs)
			{
				gs_undo = dlist_container(GpuStoreUndoLogs,
										  chain, iter.cur);
				if (gs_undo->curr_xid == curr_xid)
				{
					dlist_delete(&gs_undo->chain);
					__gstoreFdwXactFinalize(gs_desc, gs_undo,
											event == XACT_EVENT_COMMIT);
					pfree(gs_undo->buf.data);
					pfree(gs_undo);
				}
			}
			if (TransactionIdIsNormal(curr_xid) &&
				gs_desc->xmin_ftable == curr_xid)
			{
				if (event == XACT_EVENT_ABORT)
					drop_this = true;
				else
					gs_desc->xmin_ftable = FrozenTransactionId;
			}

			if (TransactionIdIsNormal(curr_xid) &&
				gs_desc->xmax_ftable == curr_xid)
			{
				if (event == XACT_EVENT_COMMIT)
					drop_this = true;
				else
					gs_desc->xmax_ftable = InvalidTransactionId;
			}

			if (drop_this)
				__gstoreFdwXactDropResources(gs_desc);
		}
		/* Wake up other backends blocked by row-level lock */
		ConditionVariableBroadcast(&gstore_shared_head->row_lock_cond);
	}
}

/*
 * gstoreFdwSubXactCallback
 */
static void
gstoreFdwSubXactCallback(SubXactEvent event,
						 SubTransactionId mySubid,
						 SubTransactionId parentSubid, void *arg)
{
#if 0
    elog(INFO, "SubXactCallback: ev=%s xid=%u top-xid=%u",
		 event == SUBXACT_EVENT_START_SUB ? "SUBXACT_EVENT_START_SUB" :
		 event == SUBXACT_EVENT_COMMIT_SUB ? "SUBXACT_EVENT_COMMIT_SUB" :
		 event == SUBXACT_EVENT_ABORT_SUB ? "SUBXACT_EVENT_ABORT_SUB" :
		 event == SUBXACT_EVENT_PRE_COMMIT_SUB ? "SUBXACT_EVENT_PRE_COMMIT_SUB" : "???",
		 GetCurrentTransactionIdIfAny(),
		 GetTopTransactionIdIfAny());
#endif
	if (hash_get_num_entries(gstore_desc_htab) == 0)
		return;
	if (event == SUBXACT_EVENT_ABORT_SUB)
	{
		TransactionId	curr_xid = GetCurrentTransactionIdIfAny();
		HASH_SEQ_STATUS	hseq;
		GpuStoreDesc   *gs_desc;
		GpuStoreUndoLogs *gs_undo;
		dlist_mutable_iter iter;

		hash_seq_init(&hseq, gstore_desc_htab);
		while ((gs_desc = hash_seq_search(&hseq)) != NULL)
		{
			dlist_foreach_modify(iter, &gs_desc->gs_undo_logs)
			{
				gs_undo = dlist_container(GpuStoreUndoLogs, chain, iter.cur);
				if (gs_undo->curr_xid == curr_xid)
				{
					dlist_delete(&gs_undo->chain);
					__gstoreFdwXactFinalize(gs_desc, gs_undo, false);
					pfree(gs_undo->buf.data);
					pfree(gs_undo);
				}
			}
		}
		/* Wake up other backends blocked by row-level lock */
		ConditionVariableBroadcast(&gstore_shared_head->row_lock_cond);
	}
}

/*
 * gstoreFdwOnExitCallback
 */
static void
gstoreFdwOnExitCallback(int code, Datum arg)
{
	int			hindex;
	char		signature[8];

	if (code)
		return;		/* not normal exit */

	memcpy(signature, GPUSTORE_BASEFILE_SIGNATURE, 8);
	for (hindex=0; hindex < GPUSTORE_SHARED_DESC_NSLOTS; hindex++)
	{
		slock_t	   *lock = &gstore_shared_head->gstore_sstate_lock[hindex];
		dlist_head *slot = &gstore_shared_head->gstore_sstate_slot[hindex];
		dlist_iter	iter;
		int			fdesc;

		SpinLockAcquire(lock);
		dlist_foreach(iter, slot)
		{
			GpuStoreSharedState *gs_sstate = (GpuStoreSharedState *)
				dlist_container(GpuStoreSharedState, hash_chain, iter.cur);

			fdesc = open(gs_sstate->base_file, O_RDWR);
			if (fdesc < 0)
			{
				elog(LOG, "failed on open('%s'): %m", gs_sstate->base_file);
				continue;
			}
			if (write(fdesc, signature, 8) != 8)
				elog(LOG, "failed on write('%s'): %m", gs_sstate->base_file);
			close(fdesc);
			elog(LOG, "unmap base file '%s' of foreign table %u",
				 gs_sstate->base_file,
				 gs_sstate->ftable_oid);
		}
		SpinLockRelease(lock);
	}
}

/*
 * callback on DROP FOREIGN TABLE, or cascaded deletion
 */
static void
pgstrom_gstore_fdw_post_deletion(ObjectAccessType access,
								 Oid classId,
								 Oid objectId,
								 int subId,
								 void *arg)
{
	Relation	frel;
	FdwRoutine *routine;

	if (object_access_next)
		object_access_next(access, classId, objectId, subId, arg);

	if (access != OAT_DROP ||
		classId != RelationRelationId ||
		get_rel_relkind(objectId) != RELKIND_FOREIGN_TABLE ||
		subId != InvalidAttrNumber)
		return;		/* not a foreign table */
	frel = table_open(objectId, NoLock);
	routine = GetFdwRoutineForRelation(frel, false);
	if (memcmp(routine, &pgstrom_gstore_fdw_routine,
			   sizeof(FdwRoutine)) == 0)
	{
		MemoryContext	orig_memcxt = CurrentMemoryContext;
		GpuStoreDesc   *gs_desc;

		PG_TRY();
		{
			gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
			gs_desc->xmax_ftable = GetCurrentTransactionId();
		}
		PG_CATCH();
		{
			ErrorData	   *errdata;

			MemoryContextSwitchTo(orig_memcxt);
			errdata = CopyErrorData();
			elog(WARNING, "%s:%d %s",
				 errdata->filename,
				 errdata->lineno,
				 errdata->message);
			FlushErrorState();
		}
		PG_END_TRY();
	}
	table_close(frel, NoLock);
}

/* ----------------------------------------------------------------
 *
 * SQL functions...
 *
 * ---------------------------------------------------------------- */
Datum
pgstrom_gstore_fdw_post_creation(PG_FUNCTION_ARGS)
{
	EventTriggerData   *trigdata;

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "%s must be called as a event trigger", __FUNCTION__);

	trigdata = (EventTriggerData *) fcinfo->context;
	if (strcmp(trigdata->event, "ddl_command_end") != 0)
		elog(ERROR, "%s must be called at ddl_command_end", __FUNCTION__);
	if (strcmp(GetCommandTagName(trigdata->tag),
			   "CREATE FOREIGN TABLE") == 0)
	{
		CreateStmt *stmt = (CreateStmt *)trigdata->parsetree;
		Relation	frel;

		frel = relation_openrv_extended(stmt->relation, AccessExclusiveLock, true);
		if (!frel)
			PG_RETURN_NULL();
		if (RelationIsGstoreFdw(frel))
		{
			GpuStoreDesc *gs_desc;

			gstoreFdwAssignDefaultFiles(frel);
			gs_desc = __gstoreFdwLookupGpuStoreDesc(frel, true);
			gs_desc->xmin_ftable = GetCurrentTransactionId();
		}
		relation_close(frel, NoLock);
	}
	PG_RETURN_NULL();
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_post_creation);

Datum
pgstrom_gstore_fdw_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&pgstrom_gstore_fdw_routine);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_handler);

Datum
pgstrom_gstore_fdw_apply_redo(PG_FUNCTION_ARGS)
{
	Oid				ftable_oid = PG_GETARG_OID(0);
	Relation		frel = table_open(ftable_oid, AccessShareLock);
	GpuStoreDesc   *gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	CUresult		rc;
	
	rc = gstoreFdwApplyRedoDeviceBuffer(gs_desc->gs_sstate);

	table_close(frel, NoLock);

	PG_RETURN_INT32((int)rc);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_apply_redo);

/*
 * __gstoreFdwHostBufferCompaction
 *
 * note; caller must have AccessExclusiveLock
 */
static void
__gstoreFdwHostBufferCompaction(Relation frel)
{
	GpuStoreDesc	*gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	kern_data_store *kds = &gs_desc->base_mmap->schema;
	kern_data_extra	*old_extra;
	kern_data_extra *new_extra;
	uint32			old_revision = gs_sstate->base_mmap_revision;
	size_t			new_length;
	size_t			file_sz;
	cl_uint			i, j;
	int				rawfd;

	if (!kds->has_varlena)
		return;		/* nothing to do */

	old_extra = (kern_data_extra *)((char *)kds + kds->extra_hoffset);
	new_length = PAGE_ALIGN(old_extra->usage);
	new_extra = MemoryContextAllocHuge(CurrentMemoryContext, new_length);
	memcpy(new_extra->signature, GPUSTORE_EXTRABUF_SIGNATURE, 8);
	new_extra->length = new_length;		/* tentative */
	new_extra->usage  = offsetof(kern_data_extra, data);

	Assert(kds->format == KDS_FORMAT_COLUMN);
	for (j=0; j < kds->ncols; j++)
	{
		kern_colmeta   *cmeta = &kds->colmeta[j];
		bits8		   *nullmap = NULL;
		cl_uint		   *values;

		if (cmeta->attlen != -1)
			continue;
		Assert(!cmeta->attbyval);

		if (cmeta->nullmap_offset != 0)
			nullmap = (bits8 *)((char *)kds + __kds_unpack(cmeta->nullmap_offset));
		values = (cl_uint *)((char *)kds + __kds_unpack(cmeta->values_offset));
		for (i=0; i < kds->nitems; i++)
		{
			char	   *vl;
			cl_uint		sz;

			if (!gstoreFdwCheckRowId(gs_desc->gs_sstate,
									 gs_desc->rowid_map, i) ||
				(nullmap && att_isnull(i, nullmap)))
			{
				values[i] = 0;
				continue;
			}
			vl = (char *)old_extra + __kds_unpack(values[i]);
			if (vl < old_extra->data || vl >= (char *)old_extra + old_extra->usage)
				elog(ERROR, "gstore_fdw: varlena datum row=%u column=%u looks corrupted. varlena %p points out of the extra buffer %p-%p",
					 i, j, vl,
					 old_extra->data,
					 (char *)old_extra + old_extra->usage);
			sz = VARSIZE_ANY(vl);
			memcpy((char *)new_extra + new_extra->usage, vl, sz);
			values[i] = __kds_packed(new_extra->usage);
			new_extra->usage += MAXALIGN(sz);
		}
	}
	new_length = Max3(new_extra->usage + (128UL << 20),		/* 128MB margin */
					  (double)new_extra->usage  * 1.15,		/* 15% margin */
					  (double)old_extra->length * 0.80);	/* 80% of old size */
	new_length = PAGE_ALIGN(new_length);

	file_sz = (offsetof(GpuStoreBaseFileHead, schema) +
			   kds->extra_hoffset + new_length);
	rawfd = open(gs_sstate->base_file, O_RDWR);
	if (rawfd < 0)
	{
		elog(WARNING, "failed on open('%s'): %m", gs_sstate->base_file);
		new_length = old_extra->length;
	}
	else
	{
		if (new_length > old_extra->length)
		{
			if (posix_fallocate(rawfd, 0, file_sz) != 0)
			{
				elog(WARNING, "failed on posix_fallocate('%s',%zu): %m",
					 gs_sstate->base_file, file_sz);
				new_length = old_extra->length;
			}
		}
		else if (new_length < old_extra->length)
		{
			if (ftruncate(rawfd, file_sz) != 0)
			{
				elog(WARNING, "failed on ftruncate('%s',%zu): %m",
					 gs_sstate->base_file, file_sz);
				new_length = old_extra->length;
			}
		}
		close(rawfd);
	}
	elog(NOTICE, "gstore_fdw: host extra compaction: usage %zu->%zu, length %zu->%zu",
		 old_extra->usage,  new_extra->usage,
		 old_extra->length, new_extra->length);
	new_extra->length = new_length;
	memcpy(old_extra, new_extra, new_extra->usage);

	/* refresh base-file mapping */
	do {
		gs_desc->base_mmap_revision = random();
	} while (old_revision == gs_desc->base_mmap_revision);
	gstoreFdwRemapBaseFile(gs_desc, true);
}

Datum
pgstrom_gstore_fdw_compaction(PG_FUNCTION_ARGS)
{
	Oid			ftable_oid = PG_GETARG_OID(0);
	bool		only_device_compaction = PG_GETARG_BOOL(1);
	GpuStoreDesc *gs_desc;
	GpuStoreSharedState *gs_sstate;
	LOCKMODE	lockmode;
	Relation	frel;
	CUresult	rc;

	if (only_device_compaction)
		lockmode = AccessShareLock;
	else
		lockmode = AccessExclusiveLock;

	frel = table_open(ftable_oid, lockmode);
	gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	gs_sstate = gs_desc->gs_sstate;
	if (!only_device_compaction)
		__gstoreFdwHostBufferCompaction(frel);
	rc = gstoreFdwInvokeCompaction(gs_sstate->ftable_oid,
								   gs_sstate->cuda_dindex, false);
	table_close(frel, lockmode);

	PG_RETURN_INT32((int)rc);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_compaction);

Datum
pgstrom_gstore_fdw_sysattr_in(PG_FUNCTION_ARGS)
{
	GstoreFdwSysattr *sysatt;
	char	   *str = PG_GETARG_CSTRING(0);
	char	   *buf = pstrdup(str);
	char	   *end = buf + strlen(buf) - 1;
	char	   *saveptr = NULL;
	char	   *tok;
	int			count;
	unsigned long val;

	if (buf[0] != '(' || *end != ')')
		elog(ERROR, "invalid input [%s]", str);
	*end = '\0';

	sysatt = palloc0(sizeof(GstoreFdwSysattr));
	for (tok = strtok_r(buf+1, ",", &saveptr), count=0;
		 tok != NULL;
		 tok = strtok_r(NULL, ",", &saveptr), count++)
	{
		val = strtoul(tok, &end, 10);
		if (val == ULONG_MAX || *end != '\0')
			elog(ERROR, "invalid input [%s]", str);
		switch (count)
		{
			case 0:
				sysatt->xmin = val;
				break;
			case 1:
				sysatt->xmax = val;
				break;
			case 2:
				sysatt->cid = val;
				break;
			default:
				elog(ERROR, "invalid input [%s]", str);
				break;
		}
	}
	if (count != 3)
		elog(ERROR, "invalid input [%s]", str);
	PG_RETURN_POINTER(sysatt);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_sysattr_in);

Datum
pgstrom_gstore_fdw_sysattr_out(PG_FUNCTION_ARGS)
{
	GstoreFdwSysattr *sysatt = (GstoreFdwSysattr *)PG_GETARG_POINTER(0);

	PG_RETURN_CSTRING(psprintf("(%u,%u,%u)",
							   sysatt->xmin,
							   sysatt->xmax,
							   sysatt->cid));
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_sysattr_out);

/*
 * __gstoreFdwInvokeBackgroundCommand
 */
static CUresult
__gstoreFdwInvokeBackgroundCommand(Oid database_oid,
								   Oid ftable_oid,
								   int cuda_dindex,
								   bool is_async,
								   int command,
								   uint64 end_pos)	/* for APPLY_REDO */
{
	GpuStoreBackgroundCommand *cmd;
	dlist_node	   *dnode;
	CUresult		retval = CUDA_SUCCESS;

	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	for (;;)
	{
		if (!gstore_shared_head->bgworkers[cuda_dindex].latch)
		{
			SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
			return CUDA_ERROR_NOT_READY;
		}
		if (!dlist_is_empty(&gstore_shared_head->bgworker_free_cmds))
			break;
		SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
		CHECK_FOR_INTERRUPTS();
		pg_usleep(5000L);		/* 5msec */
		SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	}
	dnode = dlist_pop_head_node(&gstore_shared_head->bgworker_free_cmds);
	cmd = dlist_container(GpuStoreBackgroundCommand, chain, dnode);
	memset(cmd, 0, sizeof(GpuStoreBackgroundCommand));
	cmd->database_oid = database_oid;
	cmd->ftable_oid = ftable_oid;
	cmd->backend = (is_async ? NULL : MyLatch);
	cmd->command = command;
	cmd->retval  = (CUresult) UINT_MAX;
	cmd->end_pos = end_pos;
	dlist_push_tail(&gstore_shared_head->bgworkers[cuda_dindex].cmd_queue,
					&cmd->chain);
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
	SetLatch(gstore_shared_head->bgworkers[cuda_dindex].latch);
	if (!is_async)
	{
		SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
		while (cmd->retval == (CUresult) UINT_MAX)
		{
			SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
			PG_TRY();
			{
				int		ev = WaitLatch(MyLatch,
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
				/*
				 * switch the request to async mode - because nobody can
				 * return the GpuStoreBackgroundCommand to free-list.
				 */
				SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
				if (cmd->retval == (CUresult) UINT_MAX)
					cmd->backend = NULL;
				else
					dlist_push_tail(&gstore_shared_head->bgworker_free_cmds,
									&cmd->chain);
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

static CUresult
gstoreFdwInvokeInitialLoad(Oid ftable_oid, int cuda_dindex, bool is_async)
{
	return __gstoreFdwInvokeBackgroundCommand(MyDatabaseId,
											  ftable_oid,
											  cuda_dindex,
											  is_async,
											  GSTORE_BACKGROUND_CMD__INITIAL_LOAD,
											  0UL);
}

static CUresult
gstoreFdwInvokeApplyRedo(Oid ftable_oid, uint64 end_pos,
						 int cuda_dindex, bool is_async)
{
	return __gstoreFdwInvokeBackgroundCommand(MyDatabaseId,
											  ftable_oid,
											  cuda_dindex,
											  is_async,
											  GSTORE_BACKGROUND_CMD__APPLY_REDO,
											  end_pos);
}

static CUresult
gstoreFdwInvokeCompaction(Oid ftable_oid, int cuda_dindex, bool is_async)
{
	return __gstoreFdwInvokeBackgroundCommand(MyDatabaseId,
											  ftable_oid,
											  cuda_dindex,
											  is_async,
											  GSTORE_BACKGROUND_CMD__COMPACTION,
											  0UL);
}

static CUresult
gstoreFdwInvokeDropUnload(Oid ftable_oid, int cuda_dindex, bool is_async)
{
	return __gstoreFdwInvokeBackgroundCommand(MyDatabaseId,
											  ftable_oid,
											  cuda_dindex,
											  is_async,
											  GSTORE_BACKGROUND_CMD__DROP_UNLOAD,
											  0UL);
}

/*
 * __gstoreFdwGetCudaModule
 */
static CUresult
__gstoreFdwGetCudaModule(CUmodule *p_cuda_module, cl_int cuda_dindex)
{
	static void		*cuda_fatbin_image = NULL;
	static CUmodule *cuda_modules_array = NULL;

	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	if (!cuda_fatbin_image)
	{
		const char *path = PGSHAREDIR "/pg_strom/cuda_gstore.fatbin";
		int			rawfd;
		struct stat	stat_buf;
		ssize_t		nbytes;

		rawfd = open(path, O_RDONLY);
		if (rawfd < 0)
			elog(ERROR, "failed on open('%s'): %m", path);
		PG_TRY();
		{
			if (fstat(rawfd, &stat_buf) != 0)
				elog(ERROR, "failed on fstat('%s'): %m", path);
			cuda_fatbin_image = malloc(stat_buf.st_size);
			nbytes = __readFileSignal(rawfd, cuda_fatbin_image,
									  stat_buf.st_size, false);
			if (nbytes != stat_buf.st_size)
				elog(ERROR, "failed on __readFile('%s'): %m", path);
		}
		PG_CATCH();
		{
			if (cuda_fatbin_image)
			{
				free(cuda_fatbin_image);
				cuda_fatbin_image = NULL;
			}
			close(rawfd);
			PG_RE_THROW();
		}
		PG_END_TRY();
		close(rawfd);
	}
	if (!cuda_modules_array)
	{
		cuda_modules_array = calloc(numDevAttrs, sizeof(CUmodule));
		if (!cuda_modules_array)
			elog(ERROR, "out of memory");
	}
	if (cuda_modules_array[cuda_dindex] == NULL)
	{
		CUmodule	cuda_module;
		CUresult	rc;

		rc = cuModuleLoadFatBinary(&cuda_module, cuda_fatbin_image);
		if (rc != CUDA_SUCCESS)
		{
			elog(LOG, "failed on cuModuleLoadFatBinary: %s", errorText(rc));
			return rc;
		}
		cuda_modules_array[cuda_dindex] = cuda_module;
	}
	*p_cuda_module = cuda_modules_array[cuda_dindex];
	return CUDA_SUCCESS;
}

static CUresult	__gstoreFdwBackgroundCompationNoLock(GpuStoreDesc *gs_desc);
static CUresult	__gstoreFdwBackgroundInitialLoadNoLock(GpuStoreDesc *gs_desc);

/*
 * GstoreFdwBackgrondInitialLoad
 */
static CUresult
__gstoreFdwBackgroundInitialLoadNoLock(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	GpuStoreBaseFileHead *base_mmap = gs_desc->base_mmap;
	kern_data_store *schema = &base_mmap->schema;
	const char *ftable_name = base_mmap->ftable_name;
	CUresult	rc;

	/* main portion of the device buffer */
	rc = cuMemAlloc(&gs_desc->gpu_main_devptr, schema->length);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemAlloc: %s", errorText(rc));
		goto error_0;
	}
	rc = cuMemcpyHtoD(gs_desc->gpu_main_devptr, schema, schema->length);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemcpyHtoD: %s", errorText(rc));
		goto error_1;
	}
	rc = cuIpcGetMemHandle(&gs_sstate->gpu_main_mhandle,
						   gs_desc->gpu_main_devptr);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuIpcGetMemHandle: %s", errorText(rc));
		goto error_1;
	}
	gs_sstate->gpu_main_size = schema->length;
	/*
	 * extra portion of the device buffer (if needed).
	 */
	if (schema->has_varlena)
	{
		kern_data_extra *extra = (kern_data_extra *)
			((char *)schema + schema->extra_hoffset);

		rc = cuMemAllocManaged(&gs_desc->gpu_extra_devptr,
							   extra->length,
							   CU_MEM_ATTACH_GLOBAL);
		if (rc != CUDA_SUCCESS)
		{
			elog(WARNING, "failed on cuMemAllocManaged: %s", errorText(rc));
			goto error_1;
		}
		memcpy((void *)gs_desc->gpu_extra_devptr, extra, extra->usage);

		/* compaction, and swap device extra buffer */
		rc = __gstoreFdwBackgroundCompationNoLock(gs_desc);
		if (rc != CUDA_SUCCESS)
			goto error_2;
	}
	elog(LOG, "gstore_fdw: initial load [%s] - main %zu bytes, extra %zu bytes",
		 ftable_name,
		 gs_sstate->gpu_main_size,
		 gs_sstate->gpu_extra_size);

	return CUDA_SUCCESS;

error_2:
	cuMemFree(gs_desc->gpu_extra_devptr);
error_1:
	cuMemFree(gs_desc->gpu_main_devptr);
error_0:
	gs_desc->gpu_extra_devptr = 0UL;
	gs_desc->gpu_main_devptr = 0UL;
	memset(&gs_sstate->gpu_main_mhandle, 0, sizeof(CUipcMemHandle));
	memset(&gs_sstate->gpu_extra_mhandle, 0, sizeof(CUipcMemHandle));

	return rc;
}

static CUresult
GstoreFdwBackgroundInitialLoad(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	CUresult    rc;

	pthreadRWLockWriteLock(&gs_sstate->gpu_bufer_lock);
	rc = __gstoreFdwBackgroundInitialLoadNoLock(gs_desc);
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);

	return rc;
}

/*
 * GSTORE_BACKGROUND_CMD__COMPACTION command
 */
static CUresult
__gstoreFdwBackgroundCompationNoLock(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	kern_data_extra	h_extra;
	CUdeviceptr		m_new_extra;
	CUdeviceptr		m_temp;
	CUipcMemHandle	new_extra_mhandle;
	CUmodule		cuda_module;
	CUfunction		kfunc_compaction;
	CUresult		rc;
	size_t			curr_usage;
	int				grid_sz, block_sz;
	void		   *kern_args[4];

	memset(&h_extra, 0, offsetof(kern_data_extra, data));
	memcpy(h_extra.signature, GPUSTORE_EXTRABUF_SIGNATURE, 8);
	h_extra.usage  = offsetof(kern_data_extra, data);

	/* device memory must be allocated first of all */
	if (gs_desc->gpu_main_devptr == 0UL)
	{
		rc = GstoreFdwBackgroundInitialLoad(gs_desc);
		if (rc != CUDA_SUCCESS)
			return rc;
	}

	/*
	 * Lookup kern_gpustore_compaction device function
	 */
	rc = __gstoreFdwGetCudaModule(&cuda_module, gs_sstate->cuda_dindex);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on __gstoreFdwGetCudaModule: %s", errorText(rc));
		return rc;
	}

	rc = cuModuleGetFunction(&kfunc_compaction, cuda_module,
							 "kern_gpustore_compaction");
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "GPU kernel function 'kern_gpustore_compaction' not found: %s",
			 errorText(rc));
		return rc;
	}
	rc = __gpuOptimalBlockSize(&grid_sz,
							   &block_sz,
							   kfunc_compaction,
							   gs_sstate->cuda_dindex, 0, 0);
	if (rc != CUDA_SUCCESS)
		return rc;
	grid_sz = Min(grid_sz, (gs_sstate->max_num_rows +
							block_sz - 1) / block_sz);
	/*
	 * estimation of the required device memory. this dummy extra buffer
	 * is initialized usage > length, so compaction kernel never copy
	 * the varlena values.
	 */
	rc = cuMemAllocManaged(&m_new_extra, sizeof(kern_data_extra),
						   CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemAllocManaged: %s", errorText(rc));
		return rc;
	}
	memcpy((void *)m_new_extra, &h_extra, sizeof(kern_data_extra));

	/* 1st invocation for new extra buffer size estimation */
	kern_args[0] = &gs_desc->gpu_main_devptr;
	kern_args[1] = &gs_desc->gpu_extra_devptr;
	kern_args[2] = &m_new_extra;
	rc = cuLaunchKernel(kfunc_compaction,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto bailout;
	}
	/* check status of the kernel execution status */
	rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		goto bailout;
	curr_usage = ((kern_data_extra *)m_new_extra)->usage;

	/*
	 * calculation of the new extra buffer length.
	 *
	 * TODO: logic must be revised for more graceful allocation
	 */
	h_extra.length = Max(curr_usage + (64UL << 20),		/* 64MB margin */
						 (double)curr_usage * 1.15);	/* 15% margin */
	rc = cuMemFree(m_new_extra);
	if (rc != CUDA_SUCCESS)
		elog(WARNING, "failed on cuMemFree: %s", errorText(rc));

	/* main portion of the compaction */
	rc = cuMemAlloc(&m_new_extra, h_extra.length);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemAlloc(%zu): %s",
			 h_extra.length, errorText(rc));
		return rc;
	}
	rc = cuIpcGetMemHandle(&new_extra_mhandle, m_new_extra);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuIpcGetMemHandle: %s", errorText(rc));
		goto bailout;
	}
	rc = cuMemcpyHtoD(m_new_extra, &h_extra, offsetof(kern_data_extra, data));
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemcpyHtoD: %s", errorText(rc));
		goto bailout;
	}
	/* kick the compaction kernel */
	kern_args[0] = &gs_desc->gpu_main_devptr;
	kern_args[1] = &gs_desc->gpu_extra_devptr;
	kern_args[2] = &m_new_extra;
	rc = cuLaunchKernel(kfunc_compaction,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto bailout;
	}
	/* check status of the kernel execution status */
	rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		goto bailout;
	rc = cuMemcpyDtoH(&h_extra, m_new_extra, offsetof(kern_data_extra, data));
	if (rc != CUDA_SUCCESS)
		goto bailout;

	elog(LOG, "gstore_fdw: extra compaction {length=%zu->%zu, usage=%zu}",
		 gs_sstate->gpu_extra_size, h_extra.length, h_extra.usage);
	/* All Ok, swap old and new */
	m_temp = gs_desc->gpu_extra_devptr;
	gs_desc->gpu_extra_devptr = m_new_extra;
	m_new_extra = m_temp;
	gs_sstate->gpu_extra_size = h_extra.length;
	memcpy(&gs_sstate->gpu_extra_mhandle,
		   &new_extra_mhandle, sizeof(CUipcMemHandle));
bailout:
	cuMemFree(m_new_extra);
	return rc;
}

/*
 * GSTORE_BACKGROUND_CMD__COMPACTION command
 */
static CUresult
GstoreFdwBackgroundCompation(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	CUresult	rc;

	pthreadRWLockWriteLock(&gs_sstate->gpu_bufer_lock);
	rc = __gstoreFdwBackgroundCompationNoLock(gs_desc);
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);

	return rc;
}

/*
 * __gstoreFdwCallKernelApplyRedo
 */
static CUresult
__gstoreFdwCallKernelApplyRedo(GpuStoreDesc *gs_desc,
							   kern_gpustore_redolog *h_redo)
{
	size_t		nitems = h_redo->nitems;
	int			cuda_dindex = gs_desc->gs_sstate->cuda_dindex;
	CUmodule	cuda_module;
	CUfunction	kfunc_setup_owner;
	CUfunction	kfunc_apply_redo;
	CUresult	rc;
	int			phase;
	int			grid_sz, __grid_sz;
	int			block_sz, __block_sz;
	void	   *kern_args[4];

	rc = __gstoreFdwGetCudaModule(&cuda_module, cuda_dindex);
	if (rc != CUDA_SUCCESS)
		return rc;
	rc = cuModuleGetFunction(&kfunc_setup_owner, cuda_module,
							 "kern_gpustore_setup_owner");
	if (rc != CUDA_SUCCESS)
		return rc;
	rc = cuModuleGetFunction(&kfunc_apply_redo, cuda_module,
							 "kern_gpustore_apply_redo");
	if (rc != CUDA_SUCCESS)
		return rc;

	rc = __gpuOptimalBlockSize(&grid_sz,
							   &block_sz,
							   kfunc_setup_owner,
							   cuda_dindex, 0, 0);
	if (rc != CUDA_SUCCESS)
		return rc;
	rc = __gpuOptimalBlockSize(&__grid_sz,
                               &__block_sz,
							   kfunc_apply_redo,
							   cuda_dindex, 0, 0);
	if (rc != CUDA_SUCCESS)
		return rc;
	block_sz = Min(block_sz, __block_sz);
	grid_sz = Min3(grid_sz, __grid_sz, (nitems + block_sz - 1) / block_sz);
	
	/*
	 * setup-owner (phase-0) - clear the owner-id field
	 */
retry:
	phase = 0;
	kern_args[0] = &h_redo;
	kern_args[1] = &gs_desc->gpu_main_devptr;
	kern_args[2] = &gs_desc->gpu_extra_devptr;
	kern_args[3] = &phase;
	rc = cuLaunchKernel(kfunc_setup_owner,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto out_error;
	}

	/*
	 * setup-owner (phase-1) - assign largest owner-id for each rows modified
	 */
	phase = 1;
	rc = cuLaunchKernel(kfunc_setup_owner,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto out_error;
	}

	/*
	 * apply redo logs (phase-2) - apply INSERT/DELETE logs
	 */
	phase = 2;
	rc = cuLaunchKernel(kfunc_apply_redo,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto out_error;
	}

	/*
	 * setup-owner (phase-3) - assign largest owner-id of commit-logs
	 */
	phase = 3;
	rc = cuLaunchKernel(kfunc_setup_owner,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto out_error;
	}

	/*
	 * apply redo logs (phase-4) - apply COMMIT logs
	 */
	phase = 4;
	rc = cuLaunchKernel(kfunc_apply_redo,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						0,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuLaunchKernel: %s", errorText(rc));
		goto out_error;
	}
	/* check status of the kernel execution status */
	rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		return rc;

	if (h_redo->kerror.errcode == ERRCODE_OUT_OF_MEMORY)
	{
		rc = __gstoreFdwBackgroundCompationNoLock(gs_desc);
		if (rc == CUDA_SUCCESS)
		{
			memset(&h_redo->kerror, 0, sizeof(kern_errorbuf));
			goto retry;
		}
	}
	return CUDA_SUCCESS;

out_error:
	cuStreamSynchronize(CU_STREAM_PER_THREAD);
	return rc;
}

/*
 * GSTORE_BACKGROUND_CMD__APPLY_REDO command
 */
static CUresult
GstoreFdwBackgroundApplyRedoLog(GpuStoreDesc *gs_desc, uint64 end_pos)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	size_t		length;
	size_t		offset;
	int			index;
	uint64		nitems;
	uint64		head_pos;
	uint64		tail_pos;
	uint64		curr_pos;
	kern_gpustore_redolog *h_redo;
	CUdeviceptr	m_redo = 0UL;
	CUresult	rc;

	/* device memory must be allocated */
	if (gs_desc->gpu_main_devptr == 0UL)
	{
		rc = GstoreFdwBackgroundInitialLoad(gs_desc);
		if (rc != CUDA_SUCCESS)
			return rc;
	}

	SpinLockAcquire(&gs_sstate->redo_pos_lock);
	if (end_pos <= gs_sstate->redo_read_pos)
	{
		/* nothing to do */
		SpinLockRelease(&gs_sstate->redo_pos_lock);
		return CUDA_SUCCESS;
	}
	nitems = gs_sstate->redo_write_nitems - gs_sstate->redo_read_nitems;
	head_pos = gs_sstate->redo_read_pos;
	tail_pos = gs_sstate->redo_write_pos;
	Assert(end_pos <= gs_sstate->redo_write_pos);
	SpinLockRelease(&gs_sstate->redo_pos_lock);

	/*
	 * allocation of managed memory for kern_gpustore_redolog
	 * (index to log and redo-log itself)
	 */
	length = (MAXALIGN(offsetof(kern_gpustore_redolog,
								log_index[nitems])) +
			  MAXALIGN(tail_pos - head_pos));
	rc = cuMemAllocManaged(&m_redo, length, CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
	{
		elog(LOG, "failed on cuMemAllocManaged(%zu): %s",
			 length, errorText(rc));
		return rc;
	}
	h_redo = (kern_gpustore_redolog *)m_redo;
	memset(h_redo, 0, offsetof(kern_gpustore_redolog, log_index));
	h_redo->nrooms = nitems;
	h_redo->length = length;
	offset = MAXALIGN(offsetof(kern_gpustore_redolog,
							   log_index[nitems]));
	index = 0;
	curr_pos = head_pos;
	while (curr_pos < tail_pos && index < nitems)
	{
		uint64		file_pos = (curr_pos % gs_sstate->redo_log_limit);
		GstoreTxLogCommon *tx_log
			= (GstoreTxLogCommon *)(gs_desc->redo_mmap + file_pos);

		if (file_pos + offsetof(GstoreTxLogCommon, data) > gs_sstate->redo_log_limit)
		{
			curr_pos += (gs_sstate->redo_log_limit - file_pos);
			continue;
		}
		if ((tx_log->type & 0xffffff00U) != GSTORE_TX_LOG__MAGIC)
		{
			curr_pos += (gs_sstate->redo_log_limit - file_pos);
			continue;
		}
		Assert(tx_log->length == MAXALIGN(tx_log->length));
		memcpy((char *)h_redo + offset, tx_log, tx_log->length);
		h_redo->log_index[index++] = __kds_packed(offset);
		offset += tx_log->length;
		curr_pos += tx_log->length;
	}
	h_redo->nitems = index;
	h_redo->length = offset;
	
	/*
	 * Kick the kernel to apply REDO log
	 */
	pthreadRWLockWriteLock(&gs_sstate->gpu_bufer_lock);
	rc = __gstoreFdwCallKernelApplyRedo(gs_desc, h_redo);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on GPU Apply Redo Logs: %s", errorText(rc));
	}
	else
	{
		SpinLockAcquire(&gs_sstate->redo_pos_lock);
		/*
		 * Wait for a short moment if any concurrent process fetch redo buffer,
		 * and update of redo_read_pos may overwrite the redo buffer by the
		 * following update by OLTP operations.
		 */
		while (curr_pos > gs_sstate->redo_repl_pos[0] ||
			   curr_pos > gs_sstate->redo_repl_pos[1] ||
			   curr_pos > gs_sstate->redo_repl_pos[2] ||
			   curr_pos > gs_sstate->redo_repl_pos[3])
		{
			SpinLockRelease(&gs_sstate->redo_pos_lock);
			pg_usleep(2000L);	/* 2ms */
			SpinLockAcquire(&gs_sstate->redo_pos_lock);
		}
		gs_sstate->redo_read_pos = curr_pos;
		SpinLockRelease(&gs_sstate->redo_pos_lock);

		elog(LOG, "gstore_fdw: Log applied (nitems=%u, length=%zu, pos %zu => %zu)",
			 h_redo->nitems,
			 h_redo->length,
			 head_pos, curr_pos);
	}
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);

	rc = cuMemFree(m_redo);
	if (rc != CUDA_SUCCESS)
		elog(WARNING, "failed on cuMemFree: %s", errorText(rc));

	return CUDA_SUCCESS;
}

/*
 * GSTORE_BACKGROUND_CMD__DROP_UNLOAD command
 */
static CUresult
GstoreFdwBackgroundDropUnload(GpuStoreDesc *gs_desc)
{
	GpuStoreSharedState *gs_sstate = gs_desc->gs_sstate;
	CUresult	rc;
	
	elog(LOG, "run GSTORE_BACKGROUND_CMD__DROP_UNLOAD");
	pthreadRWLockWriteLock(&gs_sstate->gpu_bufer_lock);
	if (gs_desc->gpu_main_devptr != 0UL)
	{
		rc = cuMemFree(gs_desc->gpu_main_devptr);
		if (rc != CUDA_SUCCESS)
			elog(LOG, "gstore_fdw drop unload: failed on cuMemFree: %s",
				 errorText(rc));
	}
	if (gs_desc->gpu_extra_devptr != 0UL)
	{
		rc = cuMemFree(gs_desc->gpu_extra_devptr);
		if (rc != CUDA_SUCCESS)
			elog(LOG, "gstore_fdw drop unload: failed on cuMemFree: %s",
				 errorText(rc));
	}
	if (gs_desc->base_mmap)
	{
		if (pmem_unmap(gs_desc->base_mmap,
					   gs_desc->base_mmap_sz) != 0)
			elog(LOG, "gstore_fdw drop unload: failed on pmem_unmap(3): %m");
	}
	if (gs_desc->redo_mmap)
	{
		if (pmem_unmap(gs_desc->redo_mmap,
					   gs_desc->redo_mmap_sz) != 0)
			elog(LOG, "gstore_fdw drop unload: failed on pmem_unmap(3): %m");
	}
	hash_search(gstore_desc_htab, gs_desc, HASH_REMOVE, NULL);
	pthreadRWLockUnlock(&gs_sstate->gpu_bufer_lock);

	return CUDA_SUCCESS;
}

/*
 * gstoreFdwBgWorkerXXXX
 */
void
gstoreFdwBgWorkerBegin(int cuda_dindex)
{
	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	gstore_shared_head->bgworkers[cuda_dindex].latch = MyLatch;
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
}

static CUresult
__gstoreFdwBgWorkerDispatchCommand(int cuda_dindex, GpuStoreBackgroundCommand *cmd)
{
	GpuStoreDesc *gs_desc;
	Oid			hkey[2];
	bool		found;
	CUresult	rc;
	
	/*
	 * Lookup GpuStoreDesc, but never construct GpuStoreSharedState
	 * unlike gstoreFdwLookupGpuStoreDesc. It is not our role.
	 */
	hkey[0] = cmd->database_oid;
	hkey[1] = cmd->ftable_oid;
	gs_desc = (GpuStoreDesc *) hash_search(gstore_desc_htab,
										   hkey,
										   HASH_ENTER,
										   &found);
	if (!found)
	{
		GpuStoreSharedState *gs_sstate = NULL;
		dlist_iter	iter;
		uint32		hash;
		int			hindex;

		hash = hash_any((const unsigned char *)&hkey, 2 * sizeof(Oid));
		hindex = hash % GPUSTORE_SHARED_DESC_NSLOTS;
		SpinLockAcquire(&gstore_shared_head->gstore_sstate_lock[hindex]);
		dlist_foreach(iter, &gstore_shared_head->gstore_sstate_slot[hindex])
		{
			GpuStoreSharedState *temp = dlist_container(GpuStoreSharedState,
														hash_chain, iter.cur);
			if (temp->database_oid == cmd->database_oid &&
				temp->ftable_oid   == cmd->ftable_oid &&
				temp->cuda_dindex  == cuda_dindex)
			{
				gs_sstate = temp;
				break;
			}
		}
		SpinLockRelease(&gstore_shared_head->gstore_sstate_lock[hindex]);

		if (!gs_sstate)
		{
			elog(LOG, "No GpuStoreSharedState found for database=%u, ftable=%u",
				 cmd->database_oid, cmd->ftable_oid);
			hash_search(gstore_desc_htab, &hkey, HASH_REMOVE, NULL);
			return CUDA_ERROR_INVALID_VALUE;
		}
		gstoreFdwInitGpuStoreDesc(gs_desc, gs_sstate);
	}
	if (!gstoreFdwSetupGpuStoreDesc(gs_desc, false))
		return CUDA_ERROR_MAP_FAILED;

	/* handle the command for each */
	switch (cmd->command)
	{
		case GSTORE_BACKGROUND_CMD__INITIAL_LOAD:
			rc = GstoreFdwBackgroundInitialLoad(gs_desc);
			break;
		case GSTORE_BACKGROUND_CMD__APPLY_REDO:
			rc = GstoreFdwBackgroundApplyRedoLog(gs_desc, cmd->end_pos);
			break;
		case GSTORE_BACKGROUND_CMD__COMPACTION:
			rc = GstoreFdwBackgroundCompation(gs_desc);
			break;
		case GSTORE_BACKGROUND_CMD__DROP_UNLOAD:
			rc = GstoreFdwBackgroundDropUnload(gs_desc);
			break;
		default:
			elog(LOG, "Unsupported Gstore maintainer command: %d", cmd->command);
			rc = CUDA_ERROR_INVALID_VALUE;
			break;
	}
	return rc;
}

bool
gstoreFdwBgWorkerDispatch(int cuda_dindex)
{
	GpuStoreBackgroundCommand *cmd;
	dlist_node	   *dnode;

	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	if (dlist_is_empty(&gstore_shared_head->bgworkers[cuda_dindex].cmd_queue))
	{
		SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
		return true;	/* gstoreFdw allows bgworker to sleep */
	}
	dnode = dlist_pop_head_node(&gstore_shared_head->bgworkers[cuda_dindex].cmd_queue);
	cmd = dlist_container(GpuStoreBackgroundCommand, chain, dnode);
	memset(&cmd->chain, 0, sizeof(dlist_node));
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);

	cmd->retval = __gstoreFdwBgWorkerDispatchCommand(cuda_dindex, cmd);

	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	if (cmd->backend)
	{
		/*
		 * A backend process who kicked GpuStore maintainer is waiting
		 * for the response. It shall check the retval, and return the
		 * GpuStoreBackgroundCommand to free list again.
		 */
		SetLatch(cmd->backend);
	}
	else
	{
		/*
		 * GpuStore maintainer was kicked asynchronously, so nobody is
		 * waiting for the response, thus, GpuStoreBackgroundCommand
		 * must be backed to the free list again.
		 */
		dlist_push_head(&gstore_shared_head->bgworker_free_cmds,
						&cmd->chain);
	}
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
	return false;
}

bool
gstoreFdwBgWorkerIdleTask(int cuda_dindex)
{
	int			hindex;
	bool		retval = true;

	for (hindex=0; hindex < GPUSTORE_SHARED_DESC_NSLOTS; hindex++)
	{
		slock_t	   *lock = &gstore_shared_head->gstore_sstate_lock[hindex];
		dlist_head *slot = &gstore_shared_head->gstore_sstate_slot[hindex];
		dlist_iter	iter;

		SpinLockAcquire(lock);
		dlist_foreach(iter, slot)
		{
			GpuStoreSharedState *gs_sstate;
			uint64		threshold;

			gs_sstate = dlist_container(GpuStoreSharedState,
										hash_chain, iter.cur);
			if (gs_sstate->cuda_dindex != cuda_dindex)
				continue;
			SpinLockAcquire(&gs_sstate->redo_pos_lock);
			threshold = (gs_sstate->gpu_update_interval * 1000000L +
						 gs_sstate->redo_last_timestamp);
			if (GetCurrentTimestamp () > threshold &&
				gs_sstate->redo_write_nitems > gs_sstate->redo_read_nitems)
			{
				slock_t	   *cmd_lock = &gstore_shared_head->bgworker_cmd_lock;
				dlist_head *cmd_flist = &gstore_shared_head->bgworker_free_cmds;
				dlist_head *cmd_queue =
					&gstore_shared_head->bgworkers[gs_sstate->cuda_dindex].cmd_queue;

				SpinLockAcquire(cmd_lock);
				if (!dlist_is_empty(cmd_flist))
				{
					GpuStoreBackgroundCommand *cmd;

					cmd = dlist_container(GpuStoreBackgroundCommand, chain,
										  dlist_pop_head_node(cmd_flist));
					memset(cmd, 0, sizeof(GpuStoreBackgroundCommand));
					cmd->database_oid = gs_sstate->database_oid;
					cmd->ftable_oid   = gs_sstate->ftable_oid;
					cmd->backend      = NULL;
					cmd->command      = GSTORE_BACKGROUND_CMD__APPLY_REDO;
					cmd->end_pos      = gs_sstate->redo_write_pos;
					cmd->retval       = (CUresult) UINT_MAX;

					dlist_push_tail(cmd_queue, &cmd->chain);

					retval = true;

					gs_sstate->redo_last_timestamp = GetCurrentTimestamp();
				}
				SpinLockRelease(cmd_lock);
			}
			SpinLockRelease(&gs_sstate->redo_pos_lock);
		}
		SpinLockRelease(lock);
	}
	return retval;
}

void
gstoreFdwBgWorkerEnd(int cuda_dindex)
{
	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	SpinLockAcquire(&gstore_shared_head->bgworker_cmd_lock);
	gstore_shared_head->bgworkers[cuda_dindex].latch = NULL;
	SpinLockRelease(&gstore_shared_head->bgworker_cmd_lock);
}

/*
 * GstoreFdwStartupKicker
 */
void
GstoreFdwStartupKicker(Datum arg)
{
	char	   *database_name;
	Relation	srel;
	SysScanDesc	sscan;
	ScanKeyData	skey;
	int			nkeys = 0;
	HeapTuple	tuple;
	bool		exec_gstore_preload = false;
	int			exit_code = 1;

	BackgroundWorkerUnblockSignals();
	if (gstore_shared_head->kicker_database_status == 0)
	{
		/* first invocation case */
		database_name = "template1";
	}
	else if (gstore_shared_head->kicker_database_status == 1)
	{
		/* last invocation is successfully done */
		database_name = pnstrdup(gstore_shared_head->kicker_database_name,
								 NAMEDATALEN);
		ScanKeyInit(&skey,
					Anum_pg_database_datname,
					BTGreaterStrategyNumber, F_NAMEGT,
					CStringGetDatum(database_name));
		nkeys = 1;
		exec_gstore_preload = true;
	}
	else
	{
		/* last invocation is failed, so stop preloading */
		elog(LOG, "Gstore_Fdw Starup Kicker Stopped Preloading");
		proc_exit(0);
	}
	gstore_shared_head->kicker_database_status = -1;
	BackgroundWorkerInitializeConnection(database_name, NULL, 0);

	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	srel = table_open(DatabaseRelationId, AccessShareLock);
	sscan = systable_beginscan(srel,
							   DatabaseNameIndexId,
							   true,
							   NULL,
							   nkeys, &skey);
	while (HeapTupleIsValid((tuple = systable_getnext(sscan))))
	{
		Form_pg_database dat = (Form_pg_database) GETSTRUCT(tuple);

		if (!dat->datallowconn)
			continue;
		strncpy(gstore_shared_head->kicker_database_name,
				NameStr(dat->datname),
				NAMEDATALEN);
		break;
	}
	if (!HeapTupleIsValid(tuple))
		exit_code = 0;		/* no more databases */
	systable_endscan(sscan);
	table_close(srel, AccessShareLock);

	if (exec_gstore_preload)
	{
		Form_pg_foreign_table ftable;
		Relation	frel;

		srel = table_open(ForeignTableRelationId, AccessShareLock);
		sscan = systable_beginscan(srel, InvalidOid, false, NULL, 0, NULL);
		while ((tuple = systable_getnext(sscan)) != NULL)
		{
			ftable = (Form_pg_foreign_table)GETSTRUCT(tuple);
			frel = table_open(ftable->ftrelid, AccessShareLock);
			if (RelationIsGstoreFdw(frel))
			{
				MemoryContext	orig_memcxt = CurrentMemoryContext;

				PG_TRY();
				{
					gstoreFdwLookupGpuStoreDesc(frel);
					elog(LOG, "gstore_fdw: foreign-table '%s' in database '%s' preload",
						 RelationGetRelationName(frel), database_name);
				}
				PG_CATCH();
				{
					ErrorData	   *errdata;

					MemoryContextSwitchTo(orig_memcxt);
					errdata = CopyErrorData();
					elog(WARNING, "gstore_fdw: failed on preloading foreign-table '%s' in database '%s' due to the ERROR: %s (%s:%d)",
						 RelationGetRelationName(frel),
						 database_name,
						 errdata->message,
						 errdata->filename,
						 errdata->lineno);
					FlushErrorState();
				}
				PG_END_TRY();
			}
			table_close(frel, AccessShareLock);
		}
		systable_endscan(sscan);
		table_close(srel, AccessShareLock);
	}
	PopActiveSnapshot();
	CommitTransactionCommand();
	gstore_shared_head->kicker_database_status = 1;		/* successfully done */
	proc_exit(exit_code);
}

/*
 * pgstrom_startup_gstore_fdw
 */
static void
pgstrom_startup_gstore_fdw(void)
{
	bool		found;
	int			i;

	if (shmem_startup_next)
		(*shmem_startup_next)();

	gstore_shared_head = ShmemInitStruct("GpuStore Shared Head",
										 offsetof(GpuStoreSharedHead,
												  bgworkers[numDevAttrs]),
										 &found);
	if (found)
		elog(ERROR, "Bug? GpuStoreSharedHead already exists");
	memset(gstore_shared_head, 0, offsetof(GpuStoreSharedHead,
										   bgworkers[numDevAttrs]));
	/* Sync object for Row-level Locks */
	ConditionVariableInit(&gstore_shared_head->row_lock_cond);
	/* Hash slot for GpuStoreSharedState */
	for (i=0; i < GPUSTORE_SHARED_DESC_NSLOTS; i++)
	{
		SpinLockInit(&gstore_shared_head->gstore_sstate_lock[i]);
		dlist_init(&gstore_shared_head->gstore_sstate_slot[i]);
	}
	/* Debug counter */
	pg_atomic_init_u64(&gstore_shared_head->debug_count0, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count1, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count2, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count3, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count4, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count5, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count6, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count7, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count8, 0);
	pg_atomic_init_u64(&gstore_shared_head->debug_count9, 0);

	/* IPC to GstoreFdw background worker */
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
 * pgstrom_init_gstore_fdw
 */
void
pgstrom_init_gstore_fdw(void)
{
	static bool		gstore_fdw_auto_preload;	/* GUC */
	FdwRoutine	   *r = &pgstrom_gstore_fdw_routine;
	HASHCTL			hctl;
	BackgroundWorker worker;

	memset(r, 0, sizeof(FdwRoutine));
	NodeSetTag(r, T_FdwRoutine);
	/* SCAN support */
	r->GetForeignRelSize			= GstoreGetForeignRelSize;
	r->IsForeignScanParallelSafe	= GstoreIsForeignScanParallelSafe;
	r->GetForeignPaths				= GstoreGetForeignPaths;
	r->GetForeignPlan				= GstoreGetForeignPlan;
	r->BeginForeignScan				= GstoreBeginForeignScan;
	r->IterateForeignScan			= GstoreIterateForeignScan;
	r->ReScanForeignScan			= GstoreReScanForeignScan;
	r->EndForeignScan				= GstoreEndForeignScan;
	/* UPDATE/INSERT/DELETE */
	r->AddForeignUpdateTargets		= GstoreAddForeignUpdateTargets;
	r->PlanForeignModify			= GstorePlanForeignModify;
	r->BeginForeignModify			= GstoreBeginForeignModify;
	r->ExecForeignInsert			= GstoreExecForeignInsert;
	r->ExecForeignUpdate			= GstoreExecForeignUpdate;
	r->ExecForeignDelete			= GstoreExecForeignDelete;
	r->EndForeignModify				= GstoreEndForeignModify;
#if PG_VERSION_NUM >= 110000
	r->BeginForeignInsert			= GstoreBeginForeignInsert;
	r->EndForeignInsert				= GstoreEndForeignInsert;
#endif
	/* EXPLAIN/ANALYZE */
	r->ExplainForeignScan			= GstoreExplainForeignScan;
	r->ExplainForeignModify			= GstoreExplainForeignModify;
	r->AnalyzeForeignTable			= GstoreAnalyzeForeignTable;

	/*
	 * Local hash table for GpuStoreDesc
	 */
	memset(&hctl, 0, sizeof(HASHCTL));
	hctl.keysize	= 2 * sizeof(Oid);
	hctl.entrysize	= sizeof(GpuStoreDesc);
	hctl.hcxt		= CacheMemoryContext;
	gstore_desc_htab = hash_create("GpuStoreDesc Hash-table", 32,
								   &hctl,
								   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	/* GUC: gstore_fdw.enabled */
	DefineCustomBoolVariable("gstore_fdw.enabled",
							 "Enables the  planner's use of Gstore_Fdw",
							 NULL,
							 &gstore_fdw_enabled,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	
	/* GUC: gstore_fdw.auto_preload  */
	DefineCustomBoolVariable("gstore_fdw.auto_preload",
							 "Enables auto preload of GstoreFdw GPU buffers",
							 NULL,
							 &gstore_fdw_auto_preload,
							 false,
							 PGC_POSTMASTER,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);

	/* GUC: gstore_fdw.default_base_dir */
	DefineCustomStringVariable("gstore_fdw.default_base_dir",
							   "default directory if no 'base_file' is given",
							   NULL,
							   &gstore_fdw_default_base_dir,
							   NULL,
							   PGC_SUSET,
							   GUC_NOT_IN_SAMPLE,
							   NULL, NULL, NULL);

	/* GUC: gstore_fdw.default_redo_dir */
	DefineCustomStringVariable("gstore_fdw.default_redo_dir",
							   "default directory if no 'redo_log_file' is given",
							   NULL,
							   &gstore_fdw_default_redo_dir,
							   NULL,
							   PGC_SUSET,
							   GUC_NOT_IN_SAMPLE,
							   NULL, NULL, NULL);
	/*
	 * Background worker to load GPU store on startup
	 */
	if (gstore_fdw_auto_preload)
	{
		memset(&worker, 0, sizeof(BackgroundWorker));
		snprintf(worker.bgw_name, sizeof(worker.bgw_name),
				 "Gstore_Fdw Starup Kicker");
		worker.bgw_flags = (BGWORKER_SHMEM_ACCESS |
							BGWORKER_BACKEND_DATABASE_CONNECTION);
		worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
		worker.bgw_restart_time = 1;
		snprintf(worker.bgw_library_name, BGW_MAXLEN,
				 "$libdir/pg_strom");
		snprintf(worker.bgw_function_name, BGW_MAXLEN,
				 "GstoreFdwStartupKicker");
		worker.bgw_main_arg = 0;
		RegisterBackgroundWorker(&worker);
	}
	/* request for the static shared memory */
	RequestAddinShmemSpace(STROMALIGN(offsetof(GpuStoreSharedHead,
											   bgworkers[numDevAttrs])));
	shmem_startup_next = shmem_startup_hook;
	shmem_startup_hook = pgstrom_startup_gstore_fdw;
	/* callback for DROP FOREIGN TABLE support */
	object_access_next = object_access_hook;
	object_access_hook = pgstrom_gstore_fdw_post_deletion;
	/* transaction callbacks */
	RegisterXactCallback(gstoreFdwXactCallback, NULL);
	RegisterSubXactCallback(gstoreFdwSubXactCallback, NULL);
	/* cleanup on postmaster exit */
	before_shmem_exit(gstoreFdwOnExitCallback, 0);
}

/*
 * pgstrom.gstore_fdw_replication_base(regclass,int)
 *
 * Get base backup under ShareRowExclusiveLock; to prevent any writes.
 */
Datum
pgstrom_gstore_fdw_replication_base(PG_FUNCTION_ARGS)
{
	Oid			ftable_oid = PG_GETARG_OID(0);
	int32		index = PG_GETARG_INT32(1);
	Relation	frel;
	GpuStoreDesc *gs_desc;
	GpuStoreSharedState *gs_sstate;
	kern_data_store *kds;
	kern_data_extra *extra;
	size_t		length;
	size_t		offset;
	size_t		chunk_sz = (64UL << 20);	/* up to 64MB */
	uint64		rep_lpos;
	bytea	   *retval = NULL;

	if (pg_class_aclcheck(ftable_oid, GetUserId(),
						  ACL_SELECT) != ACLCHECK_OK)
		aclcheck_error(ACLCHECK_NO_PRIV,
					   OBJECT_FOREIGN_TABLE,
					   get_rel_name(ftable_oid));

	frel = table_open(ftable_oid, ShareRowExclusiveLock);
	if (!RelationIsGstoreFdw(frel))
		elog(ERROR, "relation '%s' is not a foreign table with gstore_fdw",
			 RelationGetRelationName(frel));
	gs_desc = gstoreFdwLookupGpuStoreDesc(frel);

	/* redo_write_pos shall not be updated under the ShareRowExclusiveLock */
	gs_sstate = gs_desc->gs_sstate;
	SpinLockAcquire(&gs_sstate->redo_pos_lock);
	rep_lpos = gs_sstate->redo_write_pos;
	SpinLockRelease(&gs_sstate->redo_pos_lock);

	/* try to fetch base chunk */
	kds = &gs_desc->base_mmap->schema;
	length = offsetof(GpuStoreBaseFileHead, schema) + kds->length;
	offset = chunk_sz * index;
	if (offset < length)
	{
		GpuStoreReplicationChunk *repl;

		if (offset + chunk_sz > length)
			chunk_sz = length - offset;
		retval = palloc(VARHDRSZ + offsetof(GpuStoreReplicationChunk,
											data) + chunk_sz);
		repl = (GpuStoreReplicationChunk *)retval->vl_dat;
		repl->rep_kind = 'b';
		repl->rep_dindex = 1234;	/* now multi-device is not supported */
		repl->rep_nitems = -1;
		repl->rep_lpos = rep_lpos;
		memcpy(repl->data, (char *)gs_desc->base_mmap + offset, chunk_sz);
		SET_VARSIZE(retval, VARHDRSZ + offsetof(GpuStoreReplicationChunk,
												data) + chunk_sz);
	}
	else if (kds->extra_hoffset)
	{
		index -= (length + chunk_sz - 1) / chunk_sz;

		extra = (kern_data_extra *)((char *)kds + kds->extra_hoffset);
		offset = chunk_sz * index;
		if (offset < extra->usage)
		{
			GpuStoreReplicationChunk *repl;

			if (offset + chunk_sz > extra->usage)
				chunk_sz = extra->usage - offset;
			retval = palloc(VARHDRSZ + offsetof(GpuStoreReplicationChunk,
												data) + chunk_sz);
			repl = (GpuStoreReplicationChunk *)retval->vl_dat;
			repl->rep_kind = 'e';
			repl->rep_dindex = 0;	/* now multi-device is not supported */
			repl->rep_nitems = -1;
			repl->rep_lpos = rep_lpos;
			memcpy(repl->data, (char *)extra + offset, chunk_sz);
			SET_VARSIZE(retval, VARHDRSZ + offsetof(GpuStoreReplicationChunk,
													data) + chunk_sz);
		}
	}
	table_close(frel, NoLock);	/* table lock must be kept */
	if (!retval)
		PG_RETURN_NULL();
	//TODO: pglz_compress() makes sense?
	PG_RETURN_BYTEA_P(retval);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_replication_base);

Datum
pgstrom_gstore_fdw_replication_redo(PG_FUNCTION_ARGS)
{
	Oid				ftable_oid = PG_GETARG_OID(0);
	uint64			base_pos = PG_GETARG_INT64(1);
	float8			duration = PG_GETARG_FLOAT8(2);
	int64			min_length = PG_GETARG_INT64(3);
	int64			max_length = PG_GETARG_INT64(4);
	Relation		frel;
	GpuStoreDesc   *gs_desc;
	GpuStoreSharedState *gs_sstate;
	GpuStoreReplicationChunk *repl;
	StringInfoData	buf;
	cl_uint			nitems = 0;
	uint64			tail_pos;
	struct timeval	tv1, tv2;

	if (base_pos != MAXALIGN(base_pos))
		elog(ERROR, "base logical position (%lu) is not aligned", base_pos);
	
	if (pg_class_aclcheck(ftable_oid, GetUserId(),
						  ACL_SELECT) != ACLCHECK_OK)
		aclcheck_error(ACLCHECK_NO_PRIV,
					   OBJECT_FOREIGN_TABLE,
					   get_rel_name(ftable_oid));

	frel = table_open(ftable_oid, AccessShareLock);
	gs_desc = gstoreFdwLookupGpuStoreDesc(frel);
	gs_sstate = gs_desc->gs_sstate;

	/* result buffer */
	initStringInfo(&buf);
	enlargeStringInfo(&buf, offsetof(GpuStoreReplicationChunk, data));
	buf.len = offsetof(GpuStoreReplicationChunk, data);

	gettimeofday(&tv1, NULL);
	for (;;)
	{
		int		slot_index;

		/* check logical position to start replication is not overwritten yet */
		SpinLockAcquire(&gs_sstate->redo_pos_lock);
		if (base_pos + gs_sstate->redo_log_limit < gs_sstate->redo_write_pos)
		{
			SpinLockRelease(&gs_sstate->redo_pos_lock);
			elog(ERROR, "gstore_fdw: REDO log of '%s' at %p is already overwritten",
				 RelationGetRelationName(frel), (void *)base_pos);
		}
		/* wait until any of redo_repl_pos slot become ready */
		for (slot_index=0; slot_index < 4; slot_index++)
		{
			if (gs_sstate->redo_repl_pos[slot_index] == ULONG_MAX)
				break;
		}
		if (slot_index >= 4)
		{
			SpinLockRelease(&gs_sstate->redo_pos_lock);
			pg_usleep(1000L);	/* 1ms */
			continue;
		}
		gs_sstate->redo_repl_pos[slot_index] = base_pos;
		tail_pos = gs_sstate->redo_write_pos;
		SpinLockRelease(&gs_sstate->redo_pos_lock);

		/* copy Insert/Delete/Commit log */
		while (base_pos < tail_pos && buf.len < max_length)
		{
			GstoreTxLogCommon  *tx_log;
			size_t		offset = base_pos % gs_sstate->redo_log_limit;

			tx_log = (GstoreTxLogCommon *)(gs_desc->redo_mmap + offset);
			if (tx_log->type == GSTORE_TX_LOG__INSERT ||
				tx_log->type == GSTORE_TX_LOG__DELETE ||
				tx_log->type == GSTORE_TX_LOG__COMMIT)
			{
				Assert(tx_log->length == MAXALIGN(tx_log->length));
				appendBinaryStringInfo(&buf, (char *)tx_log, tx_log->length);
				base_pos += tx_log->length;
				nitems++;
			}
			else if (tx_log->type == 0)
			{
				/* round to the redo buffer head */
				base_pos += (gs_sstate->redo_log_limit - offset);
			}
			else
			{
				/* redo log buffer has corruption */
				SpinLockAcquire(&gs_sstate->redo_pos_lock);
				gs_sstate->redo_repl_pos[slot_index] = ULONG_MAX;
				SpinLockRelease(&gs_sstate->redo_pos_lock);
				elog(ERROR, "gstore_fdw: Redo log buffer looks corrupted at %zu",
					 offset);
			}
		}
		/* length exceeds the minimum chunk size */
		if (buf.len >= min_length)
			break;
		gettimeofday(&tv2, NULL);
		/* even though the length is not enough, function call spent too much */
		if (TV_DIFF(tv2, tv1) >= (double)duration)
			break;
		/* wait for 50ms, then retry again */
		SpinLockAcquire(&gs_sstate->redo_pos_lock);
		gs_sstate->redo_repl_pos[slot_index] = ULONG_MAX;
		SpinLockRelease(&gs_sstate->redo_pos_lock);

		pg_usleep(50000L);
	}
	repl = (GpuStoreReplicationChunk *)buf.data;
	repl->rep_kind = 'r';
	repl->rep_dindex = 0;
	repl->rep_nitems = nitems;
	repl->rep_lpos = base_pos;
	SET_VARSIZE(repl, buf.len);

	table_close(frel, AccessShareLock);

	PG_RETURN_BYTEA_P(repl);
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_replication_redo);

Datum
pgstrom_gstore_fdw_read_debug(PG_FUNCTION_ARGS)
{
	static uint64	__debug_count0 = 0;
	static uint64	__debug_count1 = 0;
	static uint64	__debug_count2 = 0;
	static uint64	__debug_count3 = 0;
	static uint64	__debug_count4 = 0;
	static uint64	__debug_count5 = 0;
	static uint64	__debug_count6 = 0;
	static uint64	__debug_count7 = 0;
	static uint64	__debug_count8 = 0;
	static uint64	__debug_count9 = 0;
	uint64		debug_count0 = pg_atomic_read_u64(&gstore_shared_head->debug_count0);
	uint64		debug_count1 = pg_atomic_read_u64(&gstore_shared_head->debug_count1);
	uint64		debug_count2 = pg_atomic_read_u64(&gstore_shared_head->debug_count2);
	uint64		debug_count3 = pg_atomic_read_u64(&gstore_shared_head->debug_count3);
	uint64		debug_count4 = pg_atomic_read_u64(&gstore_shared_head->debug_count4);
	uint64		debug_count5 = pg_atomic_read_u64(&gstore_shared_head->debug_count5);
	uint64		debug_count6 = pg_atomic_read_u64(&gstore_shared_head->debug_count6);
	uint64		debug_count7 = pg_atomic_read_u64(&gstore_shared_head->debug_count7);
	uint64		debug_count8 = pg_atomic_read_u64(&gstore_shared_head->debug_count8);
	uint64		debug_count9 = pg_atomic_read_u64(&gstore_shared_head->debug_count9);
	char	   *s;

	s = psprintf("debug0 = %12.9f\n"
				 "debug1 = %12.9f\n"
				 "debug2 = %12.9f\n"
				 "debug3 = %12.9f\n"
				 "debug4 = %12.9f\n"
				 "debug5 = %12.9f\n"
				 "debug6 = %12.9f\n"
				 "debug7 = %12.9f\n"
				 "debug8 = %12.9f\n"
				 "debug9 = %12.9f\n",
				 (double)(debug_count0 - __debug_count0) / 1000000000.0,
				 (double)(debug_count1 - __debug_count1) / 1000000000.0,
				 (double)(debug_count2 - __debug_count2) / 1000000000.0,
				 (double)(debug_count3 - __debug_count3) / 1000000000.0,
				 (double)(debug_count4 - __debug_count4) / 1000000000.0,
				 (double)(debug_count5 - __debug_count5) / 1000000000.0,
				 (double)(debug_count6 - __debug_count6) / 1000000000.0,
				 (double)(debug_count7 - __debug_count7) / 1000000000.0,
				 (double)(debug_count8 - __debug_count8) / 1000000000.0,
				 (double)(debug_count9 - __debug_count9) / 1000000000.0);
	__debug_count0 = debug_count0;
	__debug_count1 = debug_count1;
	__debug_count2 = debug_count2;
	__debug_count3 = debug_count3;
	__debug_count4 = debug_count4;
	__debug_count5 = debug_count5;
	__debug_count6 = debug_count6;
	__debug_count7 = debug_count7;
	__debug_count8 = debug_count8;
	__debug_count9 = debug_count9;

	PG_RETURN_TEXT_P(cstring_to_text(s));
}
PG_FUNCTION_INFO_V1(pgstrom_gstore_fdw_read_debug);
