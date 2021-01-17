/*
 * gpujoin.c
 *
 * GPU accelerated relations join, based on nested-loop or hash-join
 * algorithm.
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
#include "cuda_gpuscan.h"
#include "cuda_gpujoin.h"

/*
 * GpuJoinPath
 */
typedef struct
{
	CustomPath		cpath;
	int				num_rels;
	int				optimal_gpu;
	Index			outer_relid;	/* valid, if outer scan pull-up */
	List		   *outer_quals;	/* qualifier of outer scan */
	cl_uint			outer_nrows_per_block;
	IndexOptInfo   *index_opt;		/* BRIN-index if any */
	List		   *index_conds;
	List		   *index_quals;
	cl_long			index_nblocks;
	Cost			inner_cost;		/* cost to setup inner heap/hash */
	bool			inner_parallel;	/* inner relations support parallel? */
	cl_int		   *sibling_param_id; /* only if partition-wise join child */
	struct {
		JoinType	join_type;		/* one of JOIN_* */
		double		join_nrows;		/* intermediate nrows in this depth */
		Path	   *scan_path;		/* outer scan path */
		List	   *hash_quals;		/* valid quals, if hash-join */
		List	   *join_quals;		/* all the device quals, incl hash_quals */
		IndexOptInfo *gist_index;	/* GiST index IndexOptInfo */
		AttrNumber	gist_ctid_resno;/* CTID resno on the targetlist */
		List	   *gist_clauses;	/* GiST index clause */
		Selectivity	gist_selectivity; /* GiST index selectivity */
		Size		ichunk_size;	/* expected inner chunk size */
	} inners[FLEXIBLE_ARRAY_MEMBER];
} GpuJoinPath;

/*
 * GpuJoinInfo - private state object of CustomScan(GpuJoin)
 */
typedef struct
{
	int			num_rels;
	int			optimal_gpu;
	char	   *kern_source;
	cl_uint		extra_flags;
	cl_uint		varlena_bufsz;
	List	   *used_params;
	List	   *outer_quals;
	List	   *outer_refs;
	double		outer_ratio;
	double		outer_nrows;		/* number of estimated outer nrows*/
	int			outer_width;		/* copy of @plan_width in outer path */
	Cost		outer_startup_cost;	/* copy of @startup_cost in outer path */
	Cost		outer_total_cost;	/* copy of @total_cost in outer path */
	cl_uint		outer_nrows_per_block;
	/* inner-scan parameters */
	cl_bool		inner_parallel;
	cl_int		sibling_param_id;
	/* BRIN-index support */
	Oid			index_oid;			/* OID of BRIN-index, if any */
	List	   *index_conds;		/* BRIN-index key conditions */
	List	   *index_quals;		/* original BRIN-index qualifiers */
	/* inner relations for each depth */
	List	   *inner_infos;		/* list of GpuJoinInnerInfo */
	/* supplemental information of ps_tlist */
	List	   *ps_src_depth;	/* source depth of the ps_tlist entry */
	List	   *ps_src_resno;	/* source resno of the ps_tlist entry */
	List	   *ps_src_refby;	/* mask of GPUJOIN_ATTR_REFERENCED_BY_* */
} GpuJoinInfo;

typedef struct
{
	int			depth;
	double		plan_nrows_in;
	double		plan_nrows_out;
	size_t		ichunk_size;
	JoinType	join_type;
	List	   *join_quals;
	List	   *other_quals;
	List	   *hash_inner_keys;		/* if Hash-join */
	List	   *hash_outer_keys;		/* if Hash-join */
	Oid			gist_index_reloid;		/* if GiST-index */
	AttrNumber	gist_index_ctid_resno;	/* if GiST-index */
	List	   *gist_index_clauses;		/* if GiST-index */
} GpuJoinInnerInfo;

static inline void
form_gpujoin_info(CustomScan *cscan, GpuJoinInfo *gj_info)
{
	List	   *privs = NIL;
	List	   *exprs = NIL;
	ListCell   *lc;
	int			depth = 1;

	privs = lappend(privs, makeInteger(gj_info->num_rels));
	privs = lappend(privs, makeInteger(gj_info->optimal_gpu));
	privs = lappend(privs, makeString(pstrdup(gj_info->kern_source)));
	privs = lappend(privs, makeInteger(gj_info->extra_flags));
	privs = lappend(privs, makeInteger(gj_info->varlena_bufsz));
	exprs = lappend(exprs, gj_info->used_params);
	exprs = lappend(exprs, gj_info->outer_quals);
	privs = lappend(privs, gj_info->outer_refs);
	privs = lappend(privs, pmakeFloat(gj_info->outer_ratio));
	privs = lappend(privs, pmakeFloat(gj_info->outer_nrows));
	privs = lappend(privs, makeInteger(gj_info->outer_width));
	privs = lappend(privs, pmakeFloat(gj_info->outer_startup_cost));
	privs = lappend(privs, pmakeFloat(gj_info->outer_total_cost));
	privs = lappend(privs, makeInteger(gj_info->outer_nrows_per_block));
	privs = lappend(privs, makeInteger(gj_info->inner_parallel));
	privs = lappend(privs, makeInteger(gj_info->sibling_param_id));
	privs = lappend(privs, makeInteger(gj_info->index_oid));
	privs = lappend(privs, gj_info->index_conds);
	exprs = lappend(exprs, gj_info->index_quals);
	/* for each depth */
	foreach (lc, gj_info->inner_infos)
	{
		GpuJoinInnerInfo *i_info = lfirst(lc);
		List   *p_items = NIL;
		List   *e_items = NIL;

		Assert(i_info->depth == depth);
		p_items = lappend(p_items, pmakeFloat(i_info->plan_nrows_in));
		p_items = lappend(p_items, pmakeFloat(i_info->plan_nrows_out));
		p_items = lappend(p_items, makeInteger(i_info->ichunk_size));
		p_items = lappend(p_items, makeInteger(i_info->join_type));
		e_items = lappend(e_items, i_info->join_quals);
		e_items = lappend(e_items, i_info->other_quals);
		e_items = lappend(e_items, i_info->hash_inner_keys);
		e_items = lappend(e_items, i_info->hash_outer_keys);
		p_items = lappend(p_items, makeInteger(i_info->gist_index_reloid));
		p_items = lappend(p_items, makeInteger(i_info->gist_index_ctid_resno));
		e_items = lappend(e_items, i_info->gist_index_clauses);

		privs = lappend(privs, p_items);
		exprs = lappend(exprs, e_items);
		depth++;
	}
	Assert(gj_info->num_rels == list_length(gj_info->inner_infos));
	privs = lappend(privs, gj_info->ps_src_depth);
	privs = lappend(privs, gj_info->ps_src_resno);
	privs = lappend(privs, gj_info->ps_src_refby);

	cscan->custom_private = privs;
	cscan->custom_exprs = exprs;
}

static inline GpuJoinInfo *
deform_gpujoin_info(CustomScan *cscan)
{
	GpuJoinInfo *gj_info = palloc0(sizeof(GpuJoinInfo));
	List	   *privs = cscan->custom_private;
	List	   *exprs = cscan->custom_exprs;
	int			pindex = 0;
	int			eindex = 0;
	int			depth;

	gj_info->num_rels = intVal(list_nth(privs, pindex++));
	gj_info->optimal_gpu = intVal(list_nth(privs, pindex++));
	gj_info->kern_source = strVal(list_nth(privs, pindex++));
	gj_info->extra_flags = intVal(list_nth(privs, pindex++));
	gj_info->varlena_bufsz = intVal(list_nth(privs, pindex++));
	gj_info->used_params = list_nth(exprs, eindex++);
	gj_info->outer_quals = list_nth(exprs, eindex++);
	gj_info->outer_refs = list_nth(privs, pindex++);
	gj_info->outer_ratio = floatVal(list_nth(privs, pindex++));
	gj_info->outer_nrows = floatVal(list_nth(privs, pindex++));
	gj_info->outer_width = intVal(list_nth(privs, pindex++));
	gj_info->outer_startup_cost = floatVal(list_nth(privs, pindex++));
	gj_info->outer_total_cost = floatVal(list_nth(privs, pindex++));
	gj_info->outer_nrows_per_block = intVal(list_nth(privs, pindex++));
	gj_info->inner_parallel = intVal(list_nth(privs, pindex++));
	gj_info->sibling_param_id = intVal(list_nth(privs, pindex++));
	gj_info->index_oid = intVal(list_nth(privs, pindex++));
	gj_info->index_conds = list_nth(privs, pindex++);
	gj_info->index_quals = list_nth(exprs, eindex++);
	/* for each depth */
	for (depth=1; depth <= gj_info->num_rels; depth++)
	{
		GpuJoinInnerInfo *i_info = palloc0(sizeof(GpuJoinInnerInfo));
		List   *p_items = list_nth(privs, pindex++);
		List   *e_items = list_nth(exprs, eindex++);

		i_info->depth = depth;
		i_info->plan_nrows_in = floatVal(list_nth(p_items, 0));
		i_info->plan_nrows_out = floatVal(list_nth(p_items, 1));
		i_info->ichunk_size = intVal(list_nth(p_items, 2));
		i_info->join_type = (JoinType)intVal(list_nth(p_items, 3));
		i_info->join_quals = list_nth(e_items, 0);
		i_info->other_quals = list_nth(e_items, 1);
		i_info->hash_inner_keys = list_nth(e_items, 2);
		i_info->hash_outer_keys = list_nth(e_items, 3);
		i_info->gist_index_reloid = (Oid)intVal(list_nth(p_items, 4));
		i_info->gist_index_ctid_resno = (AttrNumber)intVal(list_nth(p_items, 5));
		i_info->gist_index_clauses = list_nth(e_items, 4);

		gj_info->inner_infos = lappend(gj_info->inner_infos, i_info);
	}
	Assert(gj_info->num_rels == list_length(gj_info->inner_infos));
	gj_info->ps_src_depth = list_nth(privs, pindex++);
	gj_info->ps_src_resno = list_nth(privs, pindex++);
	gj_info->ps_src_refby = list_nth(privs, pindex++);
	Assert(pindex == list_length(privs));
	Assert(eindex == list_length(exprs));

	return gj_info;
}

/*
 * GpuJoinState - execution state object of GpuJoin
 */
typedef struct
{
	/*
	 * Execution status
	 */
	PlanState		   *state;
	ExprContext		   *econtext;

	/* Inner-preload buffer */
	size_t				preload_nitems;
	size_t				preload_usage;
	slist_head			preload_tuples;
	Bitmapset		   *preload_flatten_attrs;

	/*
	 * Join properties; common
	 */
	int					depth;
	JoinType			join_type;
	double				nrows_ratio;
	cl_uint				ichunk_size;
	ExprState		   *join_quals;
	ExprState		   *other_quals;

	/*
	 * Join properties; only hash-join
	 */
	List			   *hash_outer_keys;
	List			   *hash_inner_keys;

	/*
	 * Join properties; GiST index
	 */
	Relation			gist_irel;
	AttrNumber			gist_ctid_resno;

	/* CPU Fallback related */
	AttrNumber		   *inner_dst_resno;
	AttrNumber			inner_src_anum_min;
	AttrNumber			inner_src_anum_max;
	cl_long				fallback_inner_index;
	pg_crc32			fallback_inner_hash;
	cl_bool				fallback_inner_matched;
} innerState;

typedef struct
{
	GpuTaskState	gts;
	struct GpuJoinSharedState *gj_sstate;	/* may be on DSM, if parallel */

	/* Inner Buffers */
	struct GpuJoinSiblingState *sibling;	/* only partition-wise join */
	kern_multirels *h_kmrels;			/* mmap of host shared memory */
	CUdeviceptr		m_kmrels;			/* local map of preserved memory */
	bool			m_kmrels_owner;
	bool			inner_parallel;
	MemoryContext	preload_memcxt;		/* memory context for preloading */

	/*
	 * Expressions to be used in the CPU fallback path
	 */
	ExprState	   *outer_quals;
	double			outer_ratio;
	double			outer_nrows;
	List		   *hash_outer_keys;
	List		   *join_quals;
	/* result width per tuple for buffer length calculation */
	int				result_width;

	/*
	 * CPU Fallback
	 */
	TupleTableSlot *slot_fallback;
	ProjectionInfo *proj_fallback;		/* slot_fallback -> scan_slot */
	AttrNumber	   *outer_dst_resno;	/* destination attribute number to */
	AttrNumber		outer_src_anum_min;	/* be mapped on the slot_fallback */
	AttrNumber		outer_src_anum_max;
	cl_int			fallback_resume_depth;
	cl_long			fallback_thread_count;
	cl_long			fallback_outer_index;

	/*
	 * Properties of underlying inner relations
	 */
	int				num_rels;
	innerState		inners[FLEXIBLE_ARRAY_MEMBER];
} GpuJoinState;

/*
 * GpuJoinSharedState - shared inner hash/heap buffer
 */
#define INNER_PHASE__SCAN_RELATIONS		0
#define INNER_PHASE__SETUP_BUFFERS		1
#define INNER_PHASE__GPUJOIN_EXEC		2

struct GpuJoinSharedState
{
	dsm_handle		ss_handle;		/* DSM handle of the SharedState */
	cl_uint			ss_length;		/* Length of the SharedState */
	cl_uint			shmem_handle;	/* identifier of host inner-buffer */
	size_t			shmem_bytesize;	/* length of the host inner-buffer */
	ConditionVariable cond;			/* synchronization object */
	slock_t			mutex;			/* mutex for inner buffer */
	int				phase;			/* one of INNER_PHASE__* above */
	int				nr_workers_scanning;
	int				nr_workers_setup;
	pg_atomic_uint32 outer_scan_done;  /* non-zero, if outer is scanned */
	pg_atomic_uint32 needs_colocation; /* non-zero, if colocation is needed */
	cl_int			curr_outer_depth;
	struct {
		int			nr_workers_gpujoin;
		size_t		bytesize;		/* not zero, if allocated */
		CUipcMemHandle ipc_mhandle;	/* IPC handle of preserved memory */
	} pergpu[FLEXIBLE_ARRAY_MEMBER];
};
typedef struct GpuJoinSharedState	GpuJoinSharedState;

/*
 * GpuJoinRuntimeStat - shared runtime statistics
 */
struct GpuJoinRuntimeStat
{
	GpuTaskRuntimeStat		c;		/* common statistics */
	struct {
		pg_atomic_uint64	inner_nrooms;
		pg_atomic_uint64	inner_usage;
		pg_atomic_uint64	inner_nitems;
		pg_atomic_uint64	inner_nitems2;
		pg_atomic_uint64	right_nitems;
	} jstat[FLEXIBLE_ARRAY_MEMBER];
};
typedef struct GpuJoinRuntimeStat	GpuJoinRuntimeStat;

#define GPUJOIN_RUNTIME_STAT(gj_sstate)									\
	((GpuJoinRuntimeStat *)												\
	 ((char *)(gj_sstate) + MAXALIGN(offsetof(GpuJoinSharedState,		\
											  pergpu[numDevAttrs]))))

/*
 * GpuJoinSiblingState - shared state if GpuJoin works as partition leaf.
 *
 * In case when GpuJoin is pushed-down across Append-node that represents
 * a partition table, its inner hash/heap table is shared to all the
 * partition-leafs. So, we have to be careful to detach DSM segment of the
 * inner table, because other sibling GpuJoin may still need inner buffer
 * even if one GpuJoin exits.
 */
struct GpuJoinSiblingState
{
	GpuJoinState   *leader;
	cl_int			nr_siblings;
	cl_int			nr_processed;
	struct {
		CUdeviceptr	m_kmrels;	/* device memory of inner buffer */
	} pergpu[FLEXIBLE_ARRAY_MEMBER];
};
typedef struct GpuJoinSiblingState	GpuJoinSiblingState;

/*
 * GpuJoinTask - task object of GpuJoin
 */
typedef struct
{
	GpuTask			task;
	cl_bool			with_nvme_strom;	/* true, if NVMe-Strom */
	cl_int			outer_depth;		/* base depth, if RIGHT OUTER */
	/* DMA buffers */
	pgstrom_data_store *pds_src;	/* data store of outer relation */
	pgstrom_data_store *pds_dst;	/* data store of result buffer */
	kern_gpujoin	kern;		/* kern_gpujoin of this request */
} GpuJoinTask;

/* static variables */
static set_join_pathlist_hook_type set_join_pathlist_next;
static CustomPathMethods	gpujoin_path_methods;
static CustomScanMethods	gpujoin_plan_methods;
static CustomExecMethods	gpujoin_exec_methods;
static bool					enable_gpunestloop;				/* GUC */
static bool					enable_gpuhashjoin;				/* GUC */
static bool					enable_partitionwise_gpujoin;	/* GUC */

/* static functions */
static void gpujoin_switch_task(GpuTaskState *gts, GpuTask *gtask);
static GpuTask *gpujoin_next_task(GpuTaskState *gts);
static GpuTask *gpujoin_terminator_task(GpuTaskState *gts,
										cl_bool *task_is_ready);
static TupleTableSlot *gpujoin_next_tuple(GpuTaskState *gts);
static cl_uint get_tuple_hashvalue(innerState *istate,
								   bool is_inner_hashkeys,
								   TupleTableSlot *slot,
								   bool *p_is_null_keys);

static char *gpujoin_codegen(PlannerInfo *root,
							 CustomScan *cscan,
							 GpuJoinPath *gj_path,
							 GpuJoinInfo *gj_info,
							 List *tlist,
							 codegen_context *context);

static void createGpuJoinSharedState(GpuJoinState *gjs,
									 ParallelContext *pcxt,
									 void *coordinate);
static void cleanupGpuJoinSharedStateOnAbort(dsm_segment *segment,
											 Datum ptr);
static void gpujoinColocateOuterJoinMapsToHost(GpuJoinState *gjs);

/*
 * misc declarations
 */

/* copied from joinpath.c */
#define PATH_PARAM_BY_REL(path, rel)  \
	((path)->param_info && bms_overlap(PATH_REQ_OUTER(path), (rel)->relids))

/*
 * returns true, if pathnode is GpuJoin
 */
bool
pgstrom_path_is_gpujoin(const Path *pathnode)
{
	CustomPath *cpath = (CustomPath *) pathnode;

	if (IsA(cpath, CustomPath) &&
		cpath->methods == &gpujoin_path_methods)
		return true;
	return false;
}

/*
 * returns true, if plannode is GpuJoin
 */
bool
pgstrom_plan_is_gpujoin(const Plan *plannode)
{
	if (IsA(plannode, CustomScan) &&
		((CustomScan *) plannode)->methods == &gpujoin_plan_methods)
		return true;
	return false;
}

/*
 * returns true, if planstate node is GpuJoin
 */
bool
pgstrom_planstate_is_gpujoin(const PlanState *ps)
{
	if (IsA(ps, CustomScanState) &&
		((CustomScanState *) ps)->methods == &gpujoin_exec_methods)
		return true;
	return false;
}

/*
 * gpujoin_get_optimal_gpu
 */
cl_int
gpujoin_get_optimal_gpu(const Path *pathnode)
{
	if (pgstrom_path_is_gpujoin(pathnode))
		return ((GpuJoinPath *)pathnode)->optimal_gpu;
	return -1;
}

/*
 * pgstrom_copy_gpujoin_path
 *
 * Note that this function shall never copies individual fields recursively.
 */
Path *
pgstrom_copy_gpujoin_path(const Path *pathnode)
{
	GpuJoinPath	   *gjpath_old = (GpuJoinPath *) pathnode;
	GpuJoinPath	   *gjpath_new;
	Size			length;

	Assert(pgstrom_path_is_gpujoin(pathnode));
	length = offsetof(GpuJoinPath, inners[gjpath_old->num_rels]);
	gjpath_new = palloc0(length);
	memcpy(gjpath_new, gjpath_old, length);

	return &gjpath_new->cpath.path;
}

/*
 * dump_gpujoin_rel
 *
 * Dumps candidate GpuJoinPath for debugging
 */
static void
__dump_gpujoin_rel(StringInfo buf, PlannerInfo *root, RelOptInfo *rel)
{
	Relids		relids = rel->relids;
	List	   *range_tables = root->parse->rtable;
	int			rtindex = -1;
	bool		is_first = true;


	if (rel->reloptkind != RELOPT_BASEREL)
		appendStringInfo(buf, "(");

	while ((rtindex = bms_next_member(relids, rtindex)) >= 0)
	{
		RangeTblEntry  *rte = rt_fetch(rtindex, range_tables);
		Alias		   *eref = rte->eref;

		if (!is_first)
			appendStringInfoString(buf, ", ");
		appendStringInfo(buf, "%s", eref->aliasname);
		if (rte->rtekind == RTE_RELATION)
		{
			char   *relname = get_rel_name(rte->relid);

			if (relname && strcmp(relname, eref->aliasname) != 0)
				appendStringInfo(buf, " [%s]", relname);
			pfree(relname);
		}
		is_first = false;
	}

	if (rel->reloptkind != RELOPT_BASEREL)
		appendStringInfo(buf, ")");
}

/*
 * estimate_inner_buffersize
 */
static Size
estimate_inner_buffersize(PlannerInfo *root,
						  RelOptInfo *joinrel,
						  Path *outer_path,
						  GpuJoinPath *gpath,
						  double num_chunks)
{
	Size		inner_total_sz;
	cl_int		ncols;
	cl_int		i, num_rels = gpath->num_rels;

	/*
	 * Estimation: size of inner hash/heap buffer
	 */
	inner_total_sz = STROMALIGN(offsetof(kern_multirels,
										 chunks[num_rels]));
	for (i=0; i < num_rels; i++)
	{
		Path	   *inner_path = gpath->inners[i].scan_path;
		RelOptInfo *inner_rel = inner_path->parent;
		PathTarget *inner_reltarget = inner_rel->reltarget;
		Size		inner_nrows = (Size)inner_path->rows;
		Size		chunk_size;
		Size		htup_size;

		/*
		 * NOTE: PathTarget->width is not reliable for base relations 
		 * because this fields shows the length of attributes which
		 * are actually referenced, however, we usually load physical
		 * tuples on the KDS/KHash buffer if base relation.
		 */
		ncols = list_length(inner_reltarget->exprs);

		htup_size = MAXALIGN(offsetof(HeapTupleHeaderData,
									  t_bits[BITMAPLEN(ncols)]));
		if (inner_rel->reloptkind != RELOPT_BASEREL)
			htup_size += MAXALIGN(inner_reltarget->width);
		else
		{
			htup_size += MAXALIGN(((double)(BLCKSZ -
											SizeOfPageHeaderData)
								   * inner_rel->pages
								   / Max(inner_rel->tuples, 1.0))
								  - sizeof(ItemIdData)
								  - SizeofHeapTupleHeader);
		}

		/*
		 * estimation of the inner chunk in this depth
		 */
		if (gpath->inners[i].hash_quals != NIL)
			chunk_size = KDS_ESTIMATE_HASH_LENGTH(ncols,inner_nrows,htup_size);
		else
			chunk_size = KDS_ESTIMATE_ROW_LENGTH(ncols,inner_nrows,htup_size);
		gpath->inners[i].ichunk_size = chunk_size;
		inner_total_sz += chunk_size;
	}
	return inner_total_sz;
}

/*
 * cost_gpujoin
 *
 * estimation of GpuJoin cost
 */
static bool
cost_gpujoin(PlannerInfo *root,
			 GpuJoinPath *gpath,
			 RelOptInfo *joinrel,
			 Path *outer_path,
			 Relids required_outer,
			 int parallel_nworkers)
{
	Cost		inner_cost = 0.0;
	Cost		startup_cost = 0.0;
	Cost		run_cost = 0.0;
	Cost		startup_delay;
	Size		inner_buffer_sz = 0;
	double		gpu_ratio = pgstrom_gpu_operator_cost / cpu_operator_cost;
	double		parallel_divisor = 1.0;
	double		num_chunks;
	double		outer_ntuples = outer_path->rows;
	int			i, num_rels = gpath->num_rels;
	bool		retval = false;

	/*
	 * Cost comes from the outer-path
	 */
	if (gpath->outer_relid > 0)
	{
		double		dummy;

		pgstrom_common_relscan_cost(root,
									outer_path->parent,
									gpath->outer_quals,
									parallel_nworkers,	/* parallel scan */
									gpath->index_opt,
									gpath->index_quals,
									gpath->index_nblocks,
									&parallel_divisor,
									&dummy,
									&num_chunks,
									&gpath->outer_nrows_per_block,
									&startup_cost,
									&run_cost);
		outer_ntuples /= parallel_divisor;
	}
	else
	{
		if (pathtree_has_gpupath(outer_path))
			startup_cost = pgstrom_gpu_setup_cost / 2;
		else
			startup_cost = pgstrom_gpu_setup_cost;
		startup_cost = outer_path->startup_cost;
		run_cost = outer_path->total_cost - outer_path->startup_cost;
		num_chunks = estimate_num_chunks(outer_path);

		parallel_divisor = get_parallel_divisor(&gpath->cpath.path);
	}

	/*
	 * Estimation of inner hash/heap buffer, and number of internal loop
	 * to process in-kernel Join logic
	 */
	inner_buffer_sz = estimate_inner_buffersize(root,
												joinrel,
												outer_path,
												gpath,
												num_chunks);
	/*
	 * Cost for each depth
	 */
	for (i=0; i < num_rels; i++)
	{
		Path	   *scan_path = gpath->inners[i].scan_path;
		List	   *hash_quals = gpath->inners[i].hash_quals;
		List	   *join_quals = gpath->inners[i].join_quals;
		IndexOptInfo *gist_index = gpath->inners[i].gist_index;
		double		join_nrows = gpath->inners[i].join_nrows;
		Size		ichunk_size = gpath->inners[i].ichunk_size;
		Cost		inner_run_cost;
		QualCost	join_quals_cost;

		/*
		 * FIXME: Right now, KDS_FORMAT_ROW/HASH does not support KDS size
		 * larger than 4GB because of 32bit index from row_index[] or
		 * hash_slot[]. So, tentatively, we prohibit to construct GpuJoin
		 * path which contains large tables (expected 1.5GB, with safety
		 * margin) in the inner buffer.
		 * In the future version, up to 32GB chunk will be supported using
		 * least 3bit because row-/hash-item shall be always put on 64bit
		 * aligned location.
		 */
		if (ichunk_size >= 0x60000000UL)
		{
			if (client_min_messages <= DEBUG1 || log_min_messages <= DEBUG1)
			{
				StringInfoData buf;

				initStringInfo(&buf);
				__dump_gpujoin_rel(&buf, root, scan_path->parent);
				elog(DEBUG1, "expected inner size (%zu) on %s is too large",
					 ichunk_size, buf.data);
				pfree(buf.data);
			}
			return false;
		}

		/*
		 * cost to load all the tuples from inner-path
		 *
		 * FIXME: This is an ad-hoc workaround not to breal multi-level
		 * GpuJoin chain. PostgreSQL v11 begins to support parallel build
		 * of inner hash-table, and its cost tends to be discounted by
		 * num of parallel workers. It is exactly a rapid option to process
		 * inner side, however, cannot use combined GpuJoin+GpuPreAgg here.
		 * So, we tentatively discount the inner cost by parallel_nworkers,
		 * as if it is processed in parallel.
		 * It shall be supported on the later PG-Strom version.
		 */
		inner_run_cost = (scan_path->total_cost -
						  scan_path->startup_cost) / parallel_divisor;
		inner_cost += scan_path->startup_cost + inner_run_cost;

		/* cost for join_qual startup */
		cost_qual_eval(&join_quals_cost, join_quals, root);
		join_quals_cost.per_tuple *= gpu_ratio;
		startup_cost += join_quals_cost.startup;

		/*
		 * cost to evaluate join qualifiers according to
		 * the GpuJoin logic
		 */
		if (hash_quals != NIL)
		{
			/*
			 * GpuHashJoin - It computes hash-value of inner tuples by CPU,
			 * but outer tuples by GPU, then it evaluates join-qualifiers
			 * for each items on inner hash table by GPU.
			 */
			cl_uint		num_hashkeys = list_length(hash_quals);
			double		hash_nsteps = scan_path->rows /
				(double)__KDS_NSLOTS((Size)scan_path->rows);

			/* cost to compute inner hash value by CPU */
			inner_cost += cpu_operator_cost * num_hashkeys * scan_path->rows;

			/* cost to comput hash value by GPU */
			run_cost += (pgstrom_gpu_operator_cost *
						 num_hashkeys *
						 outer_ntuples);
			/* cost to evaluate join qualifiers */
			run_cost += (join_quals_cost.per_tuple *
						 Max(hash_nsteps, 1.0) *
						 outer_ntuples);
		}
		else if (gist_index != NULL)
		{
			List	   *gist_clauses = gpath->inners[i].gist_clauses;
			Selectivity	gist_selectivity = gpath->inners[i].gist_selectivity;
			double		inner_ntuples = scan_path->rows;
			QualCost	gist_clause_cost;

			/* cost to preload inner heap tuples by CPU */
			inner_cost += cpu_tuple_cost * inner_ntuples;

			/* cost to preload the entire index pages once */
			inner_cost += seq_page_cost * (double)gist_index->pages;

			/* cost to evaluate GiST index by GPU */
			cost_qual_eval(&gist_clause_cost, gist_clauses, root);
			run_cost += (gist_clause_cost.per_tuple * gpu_ratio * outer_ntuples);

			/* cost to evaluate join qualifiers by GPU */
			run_cost += (join_quals_cost.per_tuple * gpu_ratio *
						 outer_ntuples *
						 gist_selectivity * inner_ntuples);
		}
		else
		{
			/*
			 * GpuNestLoop - It evaluates join-qual for each pair of outer
			 * and inner tuples. So, its run_cost is usually higher than
			 * GpuHashJoin.
			 */
			double		inner_ntuples = scan_path->rows;

			/* cost to preload inner heap tuples by CPU */
			inner_cost += cpu_tuple_cost * inner_ntuples;

			/* cost to evaluate join qualifiers by GPU */
			run_cost += (join_quals_cost.per_tuple * gpu_ratio *
						 outer_ntuples *
						 inner_ntuples);
		}
		/* number of outer items on the next depth */
		outer_ntuples = join_nrows / parallel_divisor;
	}
	/* outer DMA send cost */
	run_cost += (double)num_chunks * pgstrom_gpu_dma_cost;

	/* inner DMA send cost */
	inner_cost += ((double)inner_buffer_sz /
				   (double)pgstrom_chunk_size()) * pgstrom_gpu_dma_cost;

	/* cost for GPU projection */
	startup_cost += joinrel->reltarget->cost.startup;
	run_cost += (joinrel->reltarget->cost.per_tuple +
				 cpu_tuple_cost) * gpu_ratio * gpath->cpath.path.rows;
	/* cost for DMA receive (GPU-->host) */
	run_cost += cost_for_dma_receive(joinrel, -1.0);

	/* cost to exchange tuples */
	run_cost += cpu_tuple_cost * gpath->cpath.path.rows;

	/*
	 * delay to fetch the first tuple
	 */
	startup_delay = run_cost * (1.0 / num_chunks);

	/*
	 * Put cost value on the gpath.
	 */
	gpath->cpath.path.rows /= parallel_divisor;
	gpath->cpath.path.startup_cost = startup_cost + inner_cost + startup_delay;
	gpath->cpath.path.total_cost = startup_cost + inner_cost + run_cost;
	gpath->inner_cost = inner_cost;

	/*
	 * NOTE: If very large number of rows are estimated, it may cause
	 * overflow of variables, then makes nearly negative infinite cost
	 * even though the plan is very bad.
	 * At this moment, we put assertion to detect it.
	 */
	Assert(gpath->cpath.path.startup_cost >= 0.0 &&
		   gpath->cpath.path.total_cost >= 0.0);
	retval = add_path_precheck(gpath->cpath.path.parent,
							   gpath->cpath.path.startup_cost,
							   gpath->cpath.path.total_cost,
							   NULL, required_outer);
	/* Dumps candidate GpuJoinPath for debugging */
	if (client_min_messages <= DEBUG1 || log_min_messages <= DEBUG1)
	{
		StringInfoData buf;

		initStringInfo(&buf);
		for (i=gpath->num_rels-1; i >= 0; i--)
		{
			JoinType	join_type = gpath->inners[i].join_type;
			Path	   *inner_path = gpath->inners[i].scan_path;
			bool		is_nestloop = (gpath->inners[i].hash_quals == NIL);

			__dump_gpujoin_rel(&buf, root, inner_path->parent);
			appendStringInfo(&buf, " %s%s ",
							 join_type == JOIN_FULL ? "F" :
							 join_type == JOIN_LEFT ? "L" :
							 join_type == JOIN_RIGHT ? "R" : "I",
							 is_nestloop ? "NL" : "HJ");
		}
		__dump_gpujoin_rel(&buf, root, outer_path->parent);
		elog(DEBUG1, "GpuJoin: %s Cost=%.2f..%.2f%s",
			 buf.data,
			 gpath->cpath.path.startup_cost,
			 gpath->cpath.path.total_cost,
			 !retval ? " rejected" : "");
		pfree(buf.data);
	}
	return retval;
}

typedef struct
{
	JoinType	join_type;
	Path	   *inner_path;
	List	   *join_quals;
	List	   *hash_quals;
	IndexOptInfo *gist_index;
	AttrNumber	gist_ctid_resno;
	List	   *gist_clauses;
	Selectivity	gist_selectivity;
	double		join_nrows;
} inner_path_item;

static GpuJoinPath *
create_gpujoin_path(PlannerInfo *root,
					RelOptInfo *joinrel,
					Path *outer_path,
					List *inner_path_items_list,
					ParamPathInfo *param_info,
					Relids required_outer,
					bool try_outer_parallel,
					bool try_inner_parallel)
{
	GpuJoinPath *gjpath;
	cl_int		num_rels = list_length(inner_path_items_list);
	ListCell   *lc;
	bool		parallel_safe = outer_path->parallel_safe;
	int			parallel_nworkers = outer_path->parallel_workers;
	int			i;

	/* check parallel_safe flag */
	foreach (lc, inner_path_items_list)
	{
		inner_path_item *ip_item = lfirst(lc);

		if (!ip_item->inner_path->parallel_safe)
			parallel_safe = false;
	}
	if ((try_outer_parallel | try_inner_parallel) && !parallel_safe)
		return NULL;

	gjpath = palloc0(offsetof(GpuJoinPath, inners[num_rels + 1]));
	NodeSetTag(gjpath, T_CustomPath);
	gjpath->cpath.path.pathtype = T_CustomScan;
	gjpath->cpath.path.parent = joinrel;
	gjpath->cpath.path.pathtarget = joinrel->reltarget;
	gjpath->cpath.path.param_info = param_info;	// XXXXXX
	gjpath->cpath.path.parallel_aware = try_outer_parallel;
	gjpath->cpath.path.parallel_safe = parallel_safe;
	gjpath->cpath.path.parallel_workers = parallel_nworkers;
	gjpath->cpath.path.pathkeys = NIL;
	gjpath->cpath.path.rows = joinrel->rows;
	gjpath->cpath.flags = 0;
	gjpath->cpath.methods = &gpujoin_path_methods;
	gjpath->outer_relid = 0;
	gjpath->outer_quals = NULL;
	gjpath->num_rels = num_rels;
	gjpath->inner_parallel = try_inner_parallel;

	i = 0;
	foreach (lc, inner_path_items_list)
	{
		inner_path_item *ip_item = lfirst(lc);
		List	   *hash_quals;

		if (enable_gpuhashjoin && ip_item->hash_quals != NIL)
			hash_quals = ip_item->hash_quals;
		else if (enable_gpunestloop &&
				 (ip_item->join_type == JOIN_INNER ||
				  ip_item->join_type == JOIN_LEFT))
			hash_quals = NIL;
		else
		{
			pfree(gjpath);
			return NULL;
		}
		gjpath->inners[i].join_type = ip_item->join_type;
		gjpath->inners[i].join_nrows = ip_item->join_nrows;
		gjpath->inners[i].scan_path = ip_item->inner_path;
		gjpath->inners[i].hash_quals = hash_quals;
		gjpath->inners[i].join_quals = ip_item->join_quals;
		gjpath->inners[i].gist_index = ip_item->gist_index;
		gjpath->inners[i].gist_ctid_resno = ip_item->gist_ctid_resno;
		gjpath->inners[i].gist_clauses = ip_item->gist_clauses;
		gjpath->inners[i].gist_selectivity = ip_item->gist_selectivity;
		gjpath->inners[i].ichunk_size = 0;		/* to be set later */
		i++;
	}
	Assert(i == num_rels);

	/* Try to pull up outer scan if enough simple */
	pgstrom_pullup_outer_scan(root, outer_path,
							  &gjpath->outer_relid,
							  &gjpath->outer_quals,
							  &gjpath->optimal_gpu,
							  &gjpath->index_opt,
							  &gjpath->index_conds,
							  &gjpath->index_quals,
							  &gjpath->index_nblocks);

	/*
	 * cost calculation of GpuJoin, then, add this path to the joinrel,
	 * unless its cost is not obviously huge.
	 */
	if (cost_gpujoin(root,
					 gjpath,
					 joinrel,
					 outer_path,
					 required_outer,
					 parallel_nworkers))
	{
		List   *custom_paths = list_make1(outer_path);

		/* informs planner a list of child pathnodes */
		for (i=0; i < num_rels; i++)
			custom_paths = lappend(custom_paths, gjpath->inners[i].scan_path);
		gjpath->cpath.custom_paths = custom_paths;
		return gjpath;
	}
	pfree(gjpath);
	return NULL;
}

/*
 * extract_gpuhashjoin_quals - pick up qualifiers usable for GpuHashJoin
 */
static List *
extract_gpuhashjoin_quals(PlannerInfo *root,
						  Relids outer_relids,
						  Relids inner_relids,
						  JoinType jointype,
						  List *restrict_clauses)
{
	List	   *hash_quals = NIL;
	ListCell   *lc;

	foreach (lc, restrict_clauses)
	{
		RestrictInfo   *rinfo = (RestrictInfo *) lfirst(lc);

		/*
		 * If processing an outer join, only use its own join clauses
		 * for hashing.  For inner joins we need not be so picky.
		 */
		if (IS_OUTER_JOIN(jointype) && rinfo->is_pushed_down)
			continue;

		/* Is it hash-joinable clause? */
		if (!rinfo->can_join || !OidIsValid(rinfo->hashjoinoperator))
			continue;
		Assert(is_opclause(rinfo->clause));

		/*
		 * Check if clause has the form "outer op inner" or
		 * "inner op outer". If suitable, we may be able to choose
		 * GpuHashJoin logic. See clause_sides_match_join also.
		 */
		if ((bms_is_subset(rinfo->left_relids,  outer_relids) &&
			 bms_is_subset(rinfo->right_relids, inner_relids)) ||
			(bms_is_subset(rinfo->left_relids,  inner_relids) &&
			 bms_is_subset(rinfo->right_relids, outer_relids)))
		{
			OpExpr	   *op = (OpExpr *)rinfo->clause;
			Node	   *arg1 = linitial(op->args);
			Node	   *arg2 = lsecond(op->args);
			devtype_info *dtype;

			/* hash-join key must support device hash function */
			dtype = pgstrom_devtype_lookup(exprType(arg1));
			if (!dtype || !dtype->hash_func)
				continue;
			dtype = pgstrom_devtype_lookup(exprType(arg2));
			if (!dtype || !dtype->hash_func)
				continue;

			/* OK, it is hash-joinable qualifier */
			hash_quals = lappend(hash_quals, rinfo);
		}
	}
	return hash_quals;
}

/*
 * GiST Index support
 */
static Expr *
get_index_clause_from_support(PlannerInfo *root,
							  RestrictInfo *rinfo,
							  Oid funcid,
							  int indexarg,
							  int indexcol,
							  IndexOptInfo *index)
{
#if PG_VERSION_NUM >= 120000
	/*
	 * PostgreSQL v12 added the feature of planner support function.
	 * It allows to use simplified and qualifier-specific index condition,
	 * instead of the original one.
	 * E.g) st_dwithin(geom[polygon], geom[point], 0.05) is equivalent to
	 *      geom[polygon] && st_expand(geom[point], 0.05) for index-search.
	 */
	Oid		prosupport = get_func_support(funcid);

	if (OidIsValid(prosupport))
	{
		SupportRequestIndexCondition req;
		List	   *sresult;
		
		memset(&req, 0, sizeof(SupportRequestIndexCondition));
		req.type = T_SupportRequestIndexCondition;
		req.root = root;
		req.funcid = funcid;
		req.node = (Node *) rinfo->clause;
		req.indexarg = indexarg;
		req.index = index;
		req.indexcol = indexcol;
		req.opfamily = index->opfamily[indexcol];
		req.indexcollation = index->indexcollations[indexcol];
		req.lossy = true;		/* default assumption */

		sresult = (List *)OidFunctionCall1(prosupport, PointerGetDatum(&req));
		if (list_length(sresult) == 1)
			return linitial(sresult);
		else
			return (Expr *)make_andclause(sresult);
	}
#endif
	return NULL;
}

static Expr *
match_opclause_to_indexcol(PlannerInfo *root,
						   RestrictInfo *rinfo,
						   IndexOptInfo *index,
						   int indexcol)
{
	OpExpr	   *op = (OpExpr *) rinfo->clause;
	Node	   *leftop;
	Node	   *rightop;
	Index		index_relid = index->rel->relid;
	Oid			index_collid;
	Oid			opfamily;

	/* only binary operators */
	if (list_length(op->args) != 2)
		return NULL;

	leftop = (Node *)linitial(op->args);
	rightop = (Node *)lsecond(op->args);
	opfamily = index->opfamily[indexcol];
	index_collid = index->indexcollations[indexcol];

	if (match_index_to_operand(leftop, indexcol, index) &&
		!bms_is_member(index_relid, rinfo->right_relids) &&
		!contain_volatile_functions(rightop))
	{
		if ((!OidIsValid(index_collid) || index_collid == op->inputcollid) &&
			op_in_opfamily(op->opno, opfamily))
		{
			return (Expr *)op;
		}
		set_opfuncid(op);
		return get_index_clause_from_support(root,
											 rinfo,
											 op->opfuncid,
											 0,		/* indexarg on left */
											 indexcol,
											 index);
	}

	if (match_index_to_operand(rightop, indexcol, index) &&
		!bms_is_member(index_relid, rinfo->left_relids) &&
		!contain_volatile_functions(leftop))
	{
		Oid		comm_op = get_commutator(op->opno);

		if ((!OidIsValid(index_collid) || index_collid == op->inputcollid) &&
			op_in_opfamily(comm_op, opfamily))
		{
			return make_opclause(comm_op,
								 op->opresulttype,
								 op->opretset,
								 (Expr *)rightop,
								 (Expr *)leftop,
								 op->opcollid,
								 op->inputcollid);
		}
		set_opfuncid(op);
		return get_index_clause_from_support(root,
											 rinfo,
											 op->opfuncid,
											 1,	/* indexarg on right */
											 indexcol,
											 index);
	}
	return NULL;
}

static Expr *
match_funcclause_to_indexcol(PlannerInfo *root,
							 RestrictInfo *rinfo,
							 IndexOptInfo *index,
							 int indexcol)
{
	FuncExpr   *func = (FuncExpr *) rinfo->clause;
	int			indexarg = 0;
	ListCell   *lc;

	foreach (lc, func->args)
	{
		Node   *node = lfirst(lc);

		if (match_index_to_operand(node, indexcol, index))
		{
			return get_index_clause_from_support(root,
												 rinfo,
												 func->funcid,
												 indexarg,
												 indexcol,
												 index);
		}
		indexarg++;
	}
	return NULL;
}

typedef struct
{
	PlannerInfo	   *root;
	IndexOptInfo   *index;
	AttrNumber		indexcol;
	List		   *pseudo_tlist;
	bool			build_pseudo_tlist;
	bool			is_valid;
} fixup_gist_clause_for_device_context;

/*
 * Replace the functions / operators if argument types are mismatch
 * for index references.
 * In case when GiST-index reference, index relation can have different
 * data type from the indexed column on the heap, FuncExpr / OpExpr in
 * the expression tree generates wrong device code.
 * For example, '&&' operator of geometry type also references box2df
 * type on the IndexTuple. So, we have to inject another function that
 * takes box2df and geometry arguments.
 *
 * TODO: it should be at a separated file from gpujoin.c?
 */
typedef struct altfunc_catalog_t {
	const char *func_library;	/* NULL, if internal functions */
	const char *func_signature;
	const char *altfunc_library;
	const char *altfunc_name;
	const char *altfunc_args;
} altfunc_catalog_t;

#define PGSTROM		"$libdir/pg_strom"
#define POSTGIS3	"$libdir/postgis-3"
static altfunc_catalog_t	altfunc_common_catalog[] = {
	{ POSTGIS3, "geometry_overlaps(geometry,geometry)",
	  POSTGIS3, "overlaps_2d", "(box2df,geometry)" },
	{ POSTGIS3, "geometry_overlaps(geometry,geometry)",
	  POSTGIS3, "overlaps_2d", "(box2df,geometry)" },
	{ POSTGIS3, "geometry_contains(geometry,geometry)",
	  POSTGIS3, "contains_2d", "(box2df,geometry)" },
	{ POSTGIS3, "geometry_within(geometry,geometry)",
	  POSTGIS3, "is_contained_2d", "(box2df,geometry)" },
	{ NULL, NULL, NULL },
};
#undef POSTGIS3
#undef PGSTROM

static Node *
__fixup_gist_device_funcion_if_mismatch(Oid func_oid,
										Oid func_rettype,
										List *func_args,
										Oid func_collid,
										Oid input_collid)
{
	StringInfoData	sig;
	StringInfoData	arg;
	HeapTuple		tup;
	Form_pg_proc	proc;
	const char	   *proc_lib = NULL;
	oidvector	   *alt_argtypes;
	size_t			sz;
	ListCell	   *lc;
	int				i, j;
	Node		   *retval = NULL;

	tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(func_oid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for function %u", func_oid);
	proc = (Form_pg_proc) GETSTRUCT(tup);
	Assert(proc->pronargs == proc->proargtypes.dim1);
	proc_lib = get_proc_library(tup);
	if (proc_lib == (void *)(~0UL))
		goto out;

	/*
	 * If function's argument list is fully compatible, no need to
	 * replace the function call.
	 */
	if (list_length(func_args) == proc->pronargs)
	{
		i = 0;
		foreach (lc, func_args)
		{
			Oid		__typeid = exprType(lfirst(lc));

			if (!IsBinaryCoercible(__typeid, proc->proargtypes.values[i]))
				break;
			i++;
		}
		if (!lc)
			goto out;
	}

	/*
	 * construct a function signature string based on the system catalog
	 */
	initStringInfo(&sig);
	appendStringInfo(&sig, "%s(", NameStr(proc->proname));
	for (i=0; i < proc->pronargs; i++)
	{
		appendStringInfo(&sig, "%s%s", i==0 ? "" : ",",
						 get_type_name(proc->proargtypes.values[i], false));
	}
	appendStringInfoChar(&sig, ')');

	/* Also, signature of actual data types */
	sz = offsetof(oidvector, values[list_length(func_args)]);
	alt_argtypes = alloca(sz);
	memset(alt_argtypes, 0, sz);
	alt_argtypes->ndim = 1;
	alt_argtypes->dataoffset = 0;
	alt_argtypes->elemtype = OIDOID;
	alt_argtypes->dim1 = list_length(func_args);
	alt_argtypes->lbound1 = 0;

	initStringInfo(&arg);
	appendStringInfoChar(&arg, '(');
	i = 0;
	foreach (lc, func_args)
	{
		Oid			__typeid = exprType(lfirst(lc));

		appendStringInfo(&arg, "%s%s", i==0 ? "" : ",",
						 get_type_name(__typeid, false));
		alt_argtypes->values[i++] = __typeid;
	}
	appendStringInfoChar(&arg, ')');

	/*
	 * Lookup alternative function, if any
	 */
	for (i=0; altfunc_common_catalog[i].func_signature != NULL; i++)
	{
		const char *func_lib = altfunc_common_catalog[i].func_library;
		const char *func_sig = altfunc_common_catalog[i].func_signature;
		const char *alt_lib  = altfunc_common_catalog[i].altfunc_library;
		const char *alt_name = altfunc_common_catalog[i].altfunc_name;
		const char *alt_args = altfunc_common_catalog[i].altfunc_args;

		if ((!proc_lib ? !func_lib : strcmp(proc_lib, func_lib) == 0) &&
			strcmp(func_sig, sig.data) == 0 &&
			strcmp(alt_args, arg.data) == 0)
		{
			CatCList   *catlist;

			catlist = SearchSysCacheList2(PROCNAMEARGSNSP,
										  CStringGetDatum(alt_name),
										  PointerGetDatum(alt_argtypes));
			for (j=0; j < catlist->n_members; i++)
			{
				HeapTuple	__tup = &catlist->members[j]->tuple;
				Form_pg_proc __proc = (Form_pg_proc) GETSTRUCT(__tup);
				char	   *__lib_name;

				/*
				 * note: proname and proargtypes should be already matched,
				 * so all we need to check here is library name.
				 */
				__lib_name = get_proc_library(__tup);
				if (__lib_name == (void *)(~0UL))
					continue;
				if (!alt_lib ? !__lib_name : strcmp(alt_lib, __lib_name) == 0)
				{
					/* Ok, it is the alternative function we are looking for */
					retval = (Node *)makeFuncExpr(PgProcTupleGetOid(__tup),
												  __proc->prorettype,
												  func_args,
												  func_collid,
												  input_collid,
												  COERCE_EXPLICIT_CALL);
					ReleaseSysCacheList(catlist);
					goto out;
				}
			}
			ReleaseSysCacheList(catlist);
		}
	}
out:
	ReleaseSysCache(tup);
	return retval;
}

static Node *
__fixup_gist_clause_for_device_walker(Node *node, void *__context)
{
	fixup_gist_clause_for_device_context *con = __context;
	Node	   *newnode;
	TargetEntry	*tle;

	if (!node)
		return NULL;
	if (match_index_to_operand(node, con->indexcol, con->index))
	{
		IndexOptInfo *index = con->index;
		AttrNumber	indexcol = con->indexcol;
		Oid			raw_typid;
		int32		raw_typmod;
		Oid			raw_collid;
		Var		   *ivar;

		get_atttypetypmodcoll(index->indexoid,
							  indexcol+1,
							  &raw_typid,
							  &raw_typmod,
							  &raw_collid);
		ivar = makeVar(INDEX_VAR,
					   indexcol+1,
					   raw_typid,
					   raw_typmod,
					   raw_collid, 0);
		if (con->build_pseudo_tlist)
		{
			tle = makeTargetEntry((Expr *)ivar,
								  list_length(con->pseudo_tlist) + 1,
								  NULL,
								  false);
			con->pseudo_tlist = lappend(con->pseudo_tlist, tle);
		}
		return (Node *)ivar;
	}

	if (con->build_pseudo_tlist)
	{
		RelOptInfo *rel = con->index->rel;
		Relids		varnos = pull_varnos_of_level(node, 0);

		if (!bms_overlap(varnos, rel->relids))
		{
			if (!IsA(node, Var))
			{
				List	   *subvars = pull_vars_of_level(node, 0);
				ListCell   *lc;

				foreach (lc, subvars)
				{
					Var	   *svar = lfirst(lc);

					tle = makeTargetEntry((Expr *)copyObject(svar),
										  list_length(con->pseudo_tlist) + 1,
										  NULL,
										  true);
					con->pseudo_tlist = lappend(con->pseudo_tlist, tle);
				}
			}
			tle = makeTargetEntry((Expr *)copyObject(node),
								  list_length(con->pseudo_tlist) + 1,
								  NULL,
								  false);
			con->pseudo_tlist = lappend(con->pseudo_tlist, tle);
			return (Node *)makeVar(OUTER_VAR,
								   tle->resno,
								   exprType(node),
								   exprTypmod(node),
								   exprCollation(node), 0);
		}
	}
	newnode = expression_tree_mutator(node,
									  __fixup_gist_clause_for_device_walker,
									  __context);
	if (IsA(newnode, FuncExpr))
	{
		FuncExpr   *fn = (FuncExpr *)newnode;
		Node	   *altnode;

		altnode = __fixup_gist_device_funcion_if_mismatch(fn->funcid,
														  fn->funcresulttype,
														  fn->args,
														  fn->funccollid,
														  fn->inputcollid);
		if (altnode)
			return altnode;
	}
	else if (IsA(newnode, OpExpr))
	{
		OpExpr	   *op = (OpExpr *)newnode;
		Node	   *altnode;

		set_opfuncid(op);
		altnode = __fixup_gist_device_funcion_if_mismatch(op->opfuncid,
														  op->opresulttype,
														  op->args,
														  op->opcollid,
														  op->inputcollid);
		if (altnode)
			return altnode;
	}
	return newnode;
}

static Expr *
fixup_gist_clause_for_device(PlannerInfo *root,
							 IndexOptInfo *index,
							 AttrNumber indexcol,
							 Expr *clause,
							 List **p_pseudo_tlist)
{
	fixup_gist_clause_for_device_context con;
	Node	   *result;

	if (clause)
	{
		memset(&con, 0, sizeof(con));
		con.root = root;
		con.index = index;
		con.indexcol = indexcol;
		con.pseudo_tlist = NIL;
		con.build_pseudo_tlist = (p_pseudo_tlist != NULL);
		con.is_valid = true;

		result = __fixup_gist_clause_for_device_walker((Node *)clause, &con);
		if (con.is_valid)
		{
			if (p_pseudo_tlist)
				*p_pseudo_tlist = con.pseudo_tlist;
			return (Expr *)result;
		}
	}

	if (p_pseudo_tlist)
		*p_pseudo_tlist = con.pseudo_tlist;
	return NULL;
}

static Expr *
match_clause_to_index(PlannerInfo *root,
					  IndexOptInfo *index,
					  AttrNumber indexcol,
					  List *restrict_clauses)
{
	RelOptInfo *heap_rel = index->rel;
	ListCell   *lc;
	Expr	   *clause = NULL;
	Selectivity	selectivity = 1.0;

	/* identify the restriction clauses that can match the index. */
	/* see, match_join_clauses_to_index */
	foreach(lc, restrict_clauses)
	{
		RestrictInfo *rinfo = lfirst(lc);
		Expr	   *expr = NULL;
		Expr	   *dev_expr;
		Selectivity	__selectivity;

		if (rinfo->pseudoconstant ||
			!restriction_is_securely_promotable(rinfo, heap_rel))
			continue;
		if (!rinfo->clause)
			continue;
		if (IsA(rinfo->clause, OpExpr))
			expr = match_opclause_to_indexcol(root, rinfo, index, indexcol);
		else if (IsA(rinfo->clause, FuncExpr))
			expr = match_funcclause_to_indexcol(root, rinfo, index, indexcol);

		dev_expr = fixup_gist_clause_for_device(root, index, indexcol, expr, NULL);
		if (dev_expr && pgstrom_device_expression(root, NULL, dev_expr))
		{
			__selectivity = clauselist_selectivity(root,
												   list_make1(expr),
												   heap_rel->relid,
												   JOIN_INNER,
												   NULL);
			if (!clause || selectivity > __selectivity)
			{
				clause = expr;
				selectivity = __selectivity;
			}
		}
	}
	return clause;
}

static void
extract_gpugistindex_clause(inner_path_item *ip_item,
							PlannerInfo *root,
							JoinType jointype,
							List *restrict_clauses)
{
	Path		   *inner_path = ip_item->inner_path;
	RelOptInfo	   *inner_rel = inner_path->parent;
	AttrNumber		gist_ctid_resno = SelfItemPointerAttributeNumber;
	IndexOptInfo   *gist_index = NULL;
	List		   *gist_clauses = NIL;
	Selectivity		gist_selectivity = 1.0;
	ListCell	   *lc;

	/* GPU GiST Index is used only when GpuHashJoin is not available */
	Assert(ip_item->hash_quals == NIL);

	/* FIXME: IndexOnlyScan may not contain CTID, so not supported */
	if (inner_path->pathtype == T_IndexOnlyScan)
		return;

	/* see logic in create_index_paths */
	foreach (lc, inner_rel->indexlist)
	{
		IndexOptInfo   *curr_index = (IndexOptInfo *) lfirst(lc);
		List		   *curr_clauses = NIL;
#if PG_VERSION_NUM < 110000
		int				nkeycolumns = curr_index->ncolumns;
#else
		int				nkeycolumns = curr_index->nkeycolumns;
#endif
		int				indexcol;

		Assert(curr_index->rel == inner_rel);

		/* currently, only GiST index is supported */
		if (curr_index->relam != GIST_AM_OID)
			continue;

		/* ignore partial indexes that do not match the query. */
		if (curr_index->indpred != NIL && !curr_index->predOK)
			continue;

		for (indexcol = 0; indexcol < nkeycolumns; indexcol++)
		{
			Expr   *clause = match_clause_to_index(root,
												   curr_index,
												   indexcol,
												   restrict_clauses);
			if (clause)
				curr_clauses = lappend(curr_clauses, clause);
			else
			{
				curr_clauses = NIL;
				break;
			}
		}

		if (curr_clauses)
		{
			Selectivity	curr_selectivity;

			curr_selectivity = clauselist_selectivity(root,
													  curr_clauses,
													  inner_rel->relid,
													  JOIN_INNER,
													  NULL);
			if (!gist_index || gist_selectivity > curr_selectivity)
			{
				gist_index = curr_index;
				gist_clauses = curr_clauses;
				gist_selectivity = curr_selectivity;
			}
		}
	}

	if (gist_index)
	{
		AttrNumber		resno = 1;

		foreach (lc, inner_path->pathtarget->exprs)
		{
			Var	   *var = (Var *) lfirst(lc);

			if (IsA(var, Var) &&
				var->varno == inner_rel->relid &&
				var->varattno == SelfItemPointerAttributeNumber)
			{
				Assert(var->vartype == TIDOID &&
					   var->vartypmod == -1 &&
					   var->varcollid == InvalidOid);
				gist_ctid_resno = resno;
				break;
			}
			resno++;
		}
		/*
		 * Add projection for ctid
		 */
		if (!lc)
		{
			Path	   *new_path = pgstrom_copy_pathnode(inner_path);
			PathTarget *new_target = copy_pathtarget(inner_path->pathtarget);
			Var		   *var;

			var = makeVar(inner_rel->relid,
						  SelfItemPointerAttributeNumber,
						  TIDOID, -1, InvalidOid, 0);
			new_target->exprs = lappend(new_target->exprs, var);
			gist_ctid_resno = list_length(new_target->exprs);
			new_path->pathtarget = new_target;
			ip_item->inner_path = new_path;
		}
	}
	ip_item->gist_index  = gist_index;
	ip_item->gist_ctid_resno = gist_ctid_resno;
	ip_item->gist_clauses = gist_clauses;
	ip_item->gist_selectivity = gist_selectivity;
}

#if PG_VERSION_NUM >= 110000
/*
 * Partition support for GPU-aware custom-plans (GpuJoin, GpuPreAgg)
 *
 * In case when GPU-aware custom-plans try to pick up input path which
 * already scanned and unified the partitioned child tables, it may be
 * valuable to push down GpuJoin/GpuPreAgg before the Append.
 * Unlike CPU-only tasks, GPU-aware custom-plans need to send/receive
 * data to/from the device, so ping-pong between CPU and GPU are usually
 * inefficient.
 *
 * For example, we may have the expected query execution plan below:
 *   Final-Aggregate
 *    + GpuPreAgg
 *       + GpuJoin
 *       |  + Append
 *       |     + Scan on t_1
 *       |     + Scan on t_2
 *       |     + Scan on t_3
 *       + Scan on t_x
 *
 * In this case, all the records in t_1/t_2/t_3 must be loaded to RAM
 * once, then moved to GPU.
 *
 * What we want to run is below:
 *
 *   Final-Aggregation
 *    + Append
 *       + GpuPreAgg
 *       |  + GpuJoin on t_1
 *       |     + Scan on t_x
 *       + GpuPreAgg
 *       |  + GpuJoin on t_2
 *       |     + Scan on t_x
 *       + GpuPreAgg
 *          + GpuJoin on t_3
 *             + Scan on t_x
 *
 * The above form delivers much smaller data to Append, because most of
 * the data stream is preliminary aggregated on GpuPreAgg stage.
 */
#if PG_VERSION_NUM < 120000
/*
 * adjust_child_relids is static function in PG11
 */
static Relids
adjust_child_relids(Relids relids, int nappinfos, AppendRelInfo **appinfos)
{
	Bitmapset  *result = NULL;
	int			cnt;

	for (cnt = 0; cnt < nappinfos; cnt++)
	{
		AppendRelInfo *appinfo = appinfos[cnt];

		/* Remove parent, add child */
		if (bms_is_member(appinfo->parent_relid, relids))
		{
			/* Make a copy if we are changing the set. */
			if (!result)
				result = bms_copy(relids);

			result = bms_del_member(result, appinfo->parent_relid);
			result = bms_add_member(result, appinfo->child_relid);
		}
	}

	/* If we made any changes, return the modified copy. */
	if (result)
		return result;

	/* Otherwise, return the original set without modification. */
	return relids;
}
#endif

/*
 * buildPartitionLeafJoinRel
 */
static RelOptInfo *
buildPartitionLeafJoinRel(PlannerInfo *root,
						  RelOptInfo *parent_joinrel,
						  Relids outer_relids,
						  Relids inner_relids,
						  AppendRelInfo **appinfos,
						  int nappinfos,
						  double join_nrows)
{
	RelOptInfo *joinrel = makeNode(RelOptInfo);
	PathTarget *reltarget = create_empty_pathtarget();
	PathTarget *parent_reltarget = parent_joinrel->reltarget;

	/* see build_child_join_rel */
	joinrel->reloptkind = RELOPT_OTHER_JOINREL;
	joinrel->relids = bms_union(outer_relids,
								inner_relids);
	joinrel->consider_startup = (root->tuple_fraction > 0);
	joinrel->consider_param_startup = false;
	joinrel->consider_parallel = false;
	joinrel->reltarget = reltarget;
	joinrel->rtekind = RTE_JOIN;

	joinrel->top_parent_relids = bms_union(parent_joinrel->relids,
										   inner_relids);
	/*
	 * NOTE: This joinrel is built for only GpuJoinPath, shall never
	 * have ForeignPath. So, we can ignore initialization of foreign
	 * relation's properties.
	 *
	 * set_foreign_rel_properties(joinrel, outer_rel, inner_rel);
	 */

	/* See logic in build_child_join_reltarget() */
	reltarget->exprs = (List *)
		adjust_appendrel_attrs(root, (Node *)parent_reltarget->exprs,
							   nappinfos, appinfos);
	reltarget->cost.startup = parent_joinrel->reltarget->cost.startup;
	reltarget->cost.per_tuple = parent_joinrel->reltarget->cost.per_tuple;
	reltarget->width = parent_joinrel->reltarget->width;

	/* Child joinrel is parallel safe if parent is parallel safe. */
	joinrel->consider_parallel = parent_joinrel->consider_parallel;

	/* Assign # of rows */
	joinrel->rows = join_nrows;

	return joinrel;
}

/*
 * buildInnerPathItems
 */
static List *
buildInnerPathItems(PlannerInfo *root,
					AppendPath *append_path,
					List *inner_rels_list,  /* RelOptInfo */
					List *join_types_list,  /* JoinType */
					List *join_quals_list,  /* RestrictInfo */
					List *join_nrows_list,  /* Value(T_Float) */
					bool try_outer_parallel,
					bool try_inner_parallel,
					Relids *p_inner_relids,
					double *p_join_nrows)
{
	RelOptInfo *append_rel = append_path->path.parent;
	ListCell   *lc1, *lc2, *lc3, *lc4;
	Relids		outer_relids = bms_copy(append_rel->relids);
	Relids		inner_relids = NULL;
	List	   *results = NIL;
	double		join_nrows_curr = 0.0;

	forfour (lc1, inner_rels_list,
			 lc2, join_types_list,
			 lc3, join_quals_list,
			 lc4, join_nrows_list)
	{
		RelOptInfo *inner_rel = lfirst(lc1);
		JoinType	join_type = lfirst_int(lc2);
		List	   *join_quals = lfirst(lc3);
		double		join_nrows = floatVal(lfirst(lc4));
		Path	   *inner_path = NULL;
		ListCell   *cell;
		inner_path_item *ip_item;

		if (!try_inner_parallel)
		{
			foreach (cell, inner_rel->pathlist)
			{
				Path   *temp_path = lfirst(cell);

				if (try_outer_parallel && !temp_path->parallel_safe)
					continue;
				if (!bms_overlap(PATH_REQ_OUTER(temp_path), outer_relids))
				{
					inner_path = temp_path;
					break;
				}
			}
		}
		else
		{
			foreach (cell, inner_rel->partial_pathlist)
			{
				Path   *temp_path = lfirst(cell);

				Assert(temp_path->parallel_safe);
				if (!bms_overlap(PATH_REQ_OUTER(temp_path), outer_relids))
				{
					inner_path = temp_path;
					break;
				}
			}
		}
		if (!inner_path)
			return NIL;

		ip_item = palloc0(sizeof(inner_path_item));
		ip_item->join_type = join_type;
		ip_item->inner_path = inner_path;
		ip_item->join_quals = join_quals;
		ip_item->hash_quals = extract_gpuhashjoin_quals(root,
														outer_relids,
														inner_rel->relids,
														join_type,
														join_quals);
		if (ip_item->hash_quals == NIL)
			extract_gpugistindex_clause(ip_item,
										root,
										join_type,
										join_quals);
		ip_item->join_nrows = join_nrows_curr = join_nrows;
		results = lappend(results, ip_item);

		inner_relids = bms_add_members(inner_relids, inner_rel->relids);
		outer_relids = bms_add_members(outer_relids, inner_rel->relids);
	}
	*p_inner_relids = inner_relids;
	*p_join_nrows = join_nrows_curr;

	return results;
}

static List *
adjustInnerPathItems(List *inner_items_base,
					 PlannerInfo *root,
					 RelOptInfo *append_rel,
					 RelOptInfo *leaf_rel,
					 AppendRelInfo **appinfos,
					 int nappinfos,
					 double nrows_ratio)
{
	List	   *results = NIL;
	ListCell   *lc;

	foreach (lc, inner_items_base)
	{
		inner_path_item *ip_item_src = lfirst(lc);
		inner_path_item *ip_item_dst = palloc0(sizeof(inner_path_item));
		Path	   *inner_path;

		ip_item_dst->join_type = ip_item_src->join_type;

		inner_path = ip_item_src->inner_path;
		if (inner_path->param_info)
		{
			ParamPathInfo  *param_src = inner_path->param_info;
			ParamPathInfo  *param_dst = makeNode(ParamPathInfo);

			param_dst->ppi_req_outer =
				adjust_child_relids(param_src->ppi_req_outer,
									nappinfos, appinfos);
			param_dst->ppi_rows = param_src->ppi_rows;
			param_dst->ppi_clauses = (List *)
				adjust_appendrel_attrs(root, (Node *)param_src->ppi_clauses,
									   nappinfos, appinfos);
			inner_path = pgstrom_copy_pathnode(inner_path);
			inner_path->param_info = param_dst;
		}
		ip_item_dst->inner_path = inner_path;
		ip_item_dst->join_quals = (List *)
			adjust_appendrel_attrs(root, (Node *)ip_item_src->join_quals,
								   nappinfos, appinfos);
		ip_item_dst->hash_quals = (List *)
			adjust_appendrel_attrs(root, (Node *)ip_item_src->hash_quals,
								   nappinfos, appinfos);
		ip_item_dst->gist_index = ip_item_src->gist_index;
		ip_item_dst->gist_ctid_resno = ip_item_src->gist_ctid_resno;
		ip_item_dst->gist_clauses = (List *)
			adjust_appendrel_attrs(root, (Node *)ip_item_src->gist_clauses,
								   nappinfos, appinfos);
		ip_item_dst->gist_selectivity = ip_item_src->gist_selectivity;
		ip_item_dst->join_nrows = ip_item_src->join_nrows * nrows_ratio;

		results = lappend(results, ip_item_dst);
	}
	return results;
}

/*
 * buildPartitionedGpuJoinPaths
 */
static List *
buildPartitionedGpuJoinPaths(PlannerInfo *root,
							 RelOptInfo *parent_joinrel,
							 AppendPath *append_path,
							 List *inner_rels_list,  /* RelOptInfo */
							 List *join_types_list,  /* JoinType */
							 List *join_quals_list,  /* RestrictInfo */
							 List *join_nrows_list,  /* Value(T_Float) */
							 Relids required_outer,
							 ParamPathInfo *param_info,
							 bool try_outer_parallel,
							 bool try_inner_parallel,
							 bool try_extract_gpujoin,
							 AppendPath **p_append_path,
							 int *p_parallel_nworkers,
							 Cost *p_discount_cost)
{
	RelOptInfo *append_rel = append_path->path.parent;
	Cost		discount_cost = 0.0;
	List	   *results = NIL;
	ListCell   *lc;
	List	   *inner_items_base;
	List	   *inner_items_leaf;
	Relids		inner_relids = NULL;
	double		join_nrows = 0.0;
	GpuJoinPath *gjpath_leader = NULL;
	bool		assign_sibling_param_id = true;
	int			parallel_nworkers = 0;

	inner_items_base = buildInnerPathItems(root,
										   append_path,
										   inner_rels_list,
										   join_types_list,
										   join_quals_list,
										   join_nrows_list,
										   try_outer_parallel,
										   try_inner_parallel,
										   &inner_relids,
										   &join_nrows);
	if (inner_items_base == NIL)
		return NIL;

	foreach (lc, append_path->subpaths)
	{
		Path	   *leaf_path = lfirst(lc);
		RelOptInfo *leaf_rel = leaf_path->parent;
		RelOptInfo *leaf_joinrel;
		AppendRelInfo **appinfos;
		int			nappinfos;
		GpuJoinPath *gjpath;
		double		nrows_ratio
			= (join_nrows > 0.0 ? leaf_rel->rows / join_nrows : 0.0);

		/* adjust inner_path_item for this leaf */
		appinfos = find_appinfos_by_relids_nofail(root, leaf_rel->relids,
												  &nappinfos);
		inner_items_leaf = adjustInnerPathItems(inner_items_base,
												root,
												append_rel,
												leaf_rel,
												appinfos,
												nappinfos,
												nrows_ratio);
		/*
		 * extract GpuJoin for better outer leafs
		 */
		if (try_extract_gpujoin)
		{
			const Path *pathnode;

			pathnode = gpu_path_find_cheapest(root,
											  leaf_rel,
											  try_outer_parallel,
											  try_inner_parallel);
			if (pathnode && pgstrom_path_is_gpujoin(pathnode))
			{
				const GpuJoinPath *gjtemp = (const GpuJoinPath *)pathnode;
				inner_path_item	*ip_temp;
				int		i;

				for (i=gjtemp->num_rels-1; i>=0; i--)
				{
					ip_temp = palloc0(sizeof(inner_path_item));
					ip_temp->join_type  = gjtemp->inners[i].join_type;
					ip_temp->inner_path = gjtemp->inners[i].scan_path;
					ip_temp->join_quals = gjtemp->inners[i].join_quals;
					ip_temp->hash_quals = gjtemp->inners[i].hash_quals;
					ip_temp->gist_index = gjtemp->inners[i].gist_index;
					ip_temp->gist_ctid_resno = gjtemp->inners[i].gist_ctid_resno;
					ip_temp->gist_clauses = gjtemp->inners[i].gist_clauses;
					ip_temp->gist_selectivity = gjtemp->inners[i].gist_selectivity;
					ip_temp->join_nrows = gjtemp->inners[i].join_nrows;

					inner_items_leaf = lcons(ip_temp, inner_items_leaf);
				}
				leaf_path = linitial(gjtemp->cpath.custom_paths);
				leaf_rel  = leaf_path->parent;
			}
		}

		/*
		 * make a pseudo join-relation with inners + leaf
		 */
		leaf_joinrel = buildPartitionLeafJoinRel(root,
												 parent_joinrel,
												 leaf_rel->relids,
												 inner_relids,
												 appinfos,
												 nappinfos,
												 join_nrows * nrows_ratio);
		pfree(appinfos);

		gjpath = create_gpujoin_path(root,
									 leaf_joinrel,
									 leaf_path,
									 inner_items_leaf,
									 param_info,
									 required_outer,
									 try_outer_parallel,
									 try_inner_parallel);
		if (!gjpath)
			return NIL;
		if (!gjpath_leader)
			gjpath_leader = gjpath;
		else
		{
			if (gjpath_leader->num_rels != gjpath->num_rels)
				assign_sibling_param_id = false;
			else
			{
				int		i;

				for (i=0; i < gjpath->num_rels; i++)
				{
					Path   *ipath_l = gjpath_leader->inners[i].scan_path;
					Path   *ipath_c = gjpath->inners[i].scan_path;

					if (!bms_equal(ipath_l->parent->relids,
								   ipath_c->parent->relids))
					{
						assign_sibling_param_id = false;
						break;
					}
				}
			}
		}
		parallel_nworkers = Max(parallel_nworkers,
								gjpath->cpath.path.parallel_workers);
		results = lappend(results, gjpath);
	}
	/* assign sibling_param_id, if any */
	if (assign_sibling_param_id && list_length(results) > 1)
	{
		int	   *sibling_param_id = palloc(sizeof(int));

		*sibling_param_id = -1;
		foreach (lc, results)
		{
			GpuJoinPath *gjpath = lfirst(lc);
			gjpath->sibling_param_id = sibling_param_id;
			if (lc != list_head(append_path->subpaths))
				discount_cost += gjpath->inner_cost;
		}
	}
	/* see add_paths_to_append_rel() */
	parallel_nworkers = Max3(parallel_nworkers,
							 fls(list_length(append_path->subpaths)),
							 max_parallel_workers_per_gather);

	*p_append_path       = append_path;
	*p_parallel_nworkers = parallel_nworkers;
	*p_discount_cost     = discount_cost;

	return results;
}

/*
 * extract_partitionwise_pathlist
 */
static List *
__extract_partitionwise_pathlist(PlannerInfo *root,
								 RelOptInfo *parent_joinrel,
								 Path *outer_path,
								 List *inner_rels_list, /* RelOptInfo */
								 List *join_types_list, /* JoinType */
								 List *join_quals_list, /* RestrictInfo */
								 List *join_nrows_list, /* Value(T_Float) */
								 Relids required_outer,
								 ParamPathInfo *param_info,
								 bool try_outer_parallel,
								 bool try_inner_parallel,
								 bool try_extract_gpujoin,
								 AppendPath **p_append_path,
								 int *p_parallel_nworkers,
								 Cost *p_discount_cost)
{
	List	   *result = NIL;
	ListCell   *lc;

	Assert(list_length(inner_rels_list) == list_length(join_types_list) &&
		   list_length(inner_rels_list) == list_length(join_quals_list) &&
		   list_length(inner_rels_list) == list_length(join_nrows_list));
	if (IsA(outer_path, AppendPath))
	{
		AppendPath *append_path = (AppendPath *) outer_path;

		if (append_path->partitioned_rels == NIL)
			return NIL;		/* not a partition, give up */
		/*
		 * In case when we have no tables to join, just extract AppendPath
		 */
		if (!parent_joinrel)
		{
			int		nworkers = 0;

			foreach (lc, append_path->subpaths)
			{
				Path   *path = lfirst(lc);

				nworkers = Max(nworkers, path->parallel_workers);
			}
			nworkers = Max3(nworkers,
							fls(list_length(append_path->subpaths)),
							max_parallel_workers_per_gather);

			*p_append_path = append_path;
			*p_parallel_nworkers = nworkers;
			*p_discount_cost = 0.0;

			return append_path->subpaths;
		}
		if (!enable_partitionwise_gpujoin)
			return NIL;

		result = buildPartitionedGpuJoinPaths(root,
											  parent_joinrel,
											  append_path,
											  inner_rels_list,
											  join_types_list,
											  join_quals_list,
											  join_nrows_list,
											  required_outer,
											  param_info,
											  try_outer_parallel,
											  try_inner_parallel,
											  try_extract_gpujoin,
											  p_append_path,
											  p_parallel_nworkers,
											  p_discount_cost);
	}
	else if (IsA(outer_path, NestPath) ||
			 IsA(outer_path, MergePath) ||
			 IsA(outer_path, HashPath))
	{
		JoinPath   *join_path = (JoinPath *) outer_path;
		double		join_nrows = join_path->path.parent->rows;
		Path	   *inner_path = join_path->innerjoinpath;

		if (join_path->jointype != JOIN_INNER &&
			join_path->jointype != JOIN_LEFT)
			return NIL;		/* not a supported join type */
		if (!parent_joinrel)
			parent_joinrel = outer_path->parent;

		inner_rels_list = lcons(inner_path->parent, inner_rels_list);
		join_types_list = lcons_int(join_path->jointype, join_types_list);
		join_quals_list = lcons(join_path->joinrestrictinfo, join_quals_list);
		join_nrows_list = lcons(makeFloat(psprintf("%e", join_nrows)),
								join_nrows_list);
		result = __extract_partitionwise_pathlist(root,
												  parent_joinrel,
												  join_path->outerjoinpath,
												  inner_rels_list,
												  join_types_list,
												  join_quals_list,
												  join_nrows_list,
												  required_outer,
												  param_info,
												  try_outer_parallel,
												  try_inner_parallel,
												  try_extract_gpujoin,
												  p_append_path,
												  p_parallel_nworkers,
												  p_discount_cost);
	}
	else if (pgstrom_path_is_gpujoin(outer_path))
	{
		GpuJoinPath *gjpath = (GpuJoinPath *) outer_path;
		Path   *gjouter_path = linitial(gjpath->cpath.custom_paths);
		int		i;

		if (!parent_joinrel)
			parent_joinrel = outer_path->parent;

		for (i=gjpath->num_rels-1; i >= 0; i--)
		{
			Path   *inner_path = gjpath->inners[i].scan_path;
			char   *join_nrows = psprintf("%e", gjpath->inners[i].join_nrows);

			if (gjpath->inners[i].join_type != JOIN_INNER &&
				gjpath->inners[i].join_type != JOIN_LEFT)
				return NIL;	/* not a supported join type */
			inner_rels_list = lcons(inner_path->parent,
									inner_rels_list);
			join_types_list = lcons_int(gjpath->inners[i].join_type,
										join_types_list);
			join_quals_list = lcons(gjpath->inners[i].join_quals,
									join_quals_list);
			join_nrows_list = lcons(makeFloat(join_nrows),
									join_nrows_list);
		}
		result = __extract_partitionwise_pathlist(root,
												  parent_joinrel,
												  gjouter_path,
												  inner_rels_list,
												  join_types_list,
												  join_quals_list,
												  join_nrows_list,
												  required_outer,
												  param_info,
												  try_outer_parallel,
												  try_inner_parallel,
												  try_extract_gpujoin,
												  p_append_path,
												  p_parallel_nworkers,
												  p_discount_cost);
	}
	else if (IsA(outer_path, ProjectionPath))
	{
		ProjectionPath *projection_path = (ProjectionPath *)outer_path;
		List	   *temp;
		ListCell   *lc;

		temp = __extract_partitionwise_pathlist(root,
												parent_joinrel,
												projection_path->subpath,
												inner_rels_list,
												join_types_list,
												join_quals_list,
												join_nrows_list,
												required_outer,
												param_info,
												try_outer_parallel,
												try_inner_parallel,
												try_extract_gpujoin,
												p_append_path,
												p_parallel_nworkers,
												p_discount_cost);
		foreach (lc, temp)
		{
			Path		   *subpath = lfirst(lc);
			RelOptInfo	   *subrel = subpath->parent;
			PathTarget	   *newtarget;
			ProjectionPath *newpath;
			AppendRelInfo **appinfos;
			int				nappinfos;

			appinfos = find_appinfos_by_relids_nofail(root, subrel->relids,
													  &nappinfos);
			newtarget = copy_pathtarget(projection_path->path.pathtarget);
			newtarget->exprs = (List *)
				adjust_appendrel_attrs(root, (Node *)newtarget->exprs,
									   nappinfos, appinfos);
			newpath = create_projection_path(root,
											 subpath->parent,
											 subpath,
											 newtarget);
			result = lappend(result, newpath);

			pfree(appinfos);
		}
	}
	else if (IsA(outer_path, GatherPath))
	{
		Path	   *subpath = NULL;

		if (try_outer_parallel)
			subpath = ((GatherPath *) outer_path)->subpath;
		else
		{
			/*
			 * NOTE: sub-paths under GatherPath have 'parallel_aware' attribute
			 * but it is not suitable for non-parallel path construction. Thus,
			 * we try to fetch the second best path except for GatherPath.
			 */
			RelOptInfo *outer_rel = outer_path->parent;

			foreach (lc, outer_rel->pathlist)
			{
				Path   *__path = lfirst(lc);

				if (!IsA(__path, GatherPath))
				{
					subpath = __path;
					break;
				}
			}
			if (!subpath)
				return NIL;
		}
		result = __extract_partitionwise_pathlist(root,
												  parent_joinrel,
												  subpath,
												  inner_rels_list,
												  join_types_list,
												  join_quals_list,
												  join_nrows_list,
												  required_outer,
												  param_info,
												  try_outer_parallel,
												  try_inner_parallel,
												  try_extract_gpujoin,
												  p_append_path,
												  p_parallel_nworkers,
												  p_discount_cost);
	}
	return result;
}

List *
extract_partitionwise_pathlist(PlannerInfo *root,
							   Path *outer_path,
							   bool try_outer_parallel,
							   bool try_inner_parallel,
							   AppendPath **p_append_path,
							   int *p_parallel_nworkers,
							   Cost *p_discount_cost)
{
	return __extract_partitionwise_pathlist(root,
											NULL,
											outer_path,
											NIL,	/* inner RelOptInfos */
											NIL,	/* inner JoinTypes */
											NIL,	/* inner JoinQuals */
											NIL,	/* inner JoinNRows */
											NULL,	/* required_outer */
											NULL,	/* param_info */
											try_outer_parallel,
											try_inner_parallel,
											true,
											p_append_path,
											p_parallel_nworkers,
											p_discount_cost);
}
#endif		/* >=PG11; partition-wise join support */

/*
 * try_add_gpujoin_append_paths
 */
static void
try_add_gpujoin_append_paths(PlannerInfo *root,
							 RelOptInfo *joinrel,
							 Path *outer_path,
							 Path *inner_path,
							 JoinType join_type,
							 JoinPathExtraData *extra,
							 Relids required_outer,
							 ParamPathInfo *param_info,
							 bool try_outer_parallel,
							 bool try_inner_parallel)
{
#if PG_VERSION_NUM >= 110000
	Value	   *join_nrows = makeFloat(psprintf("%e", joinrel->rows));
	List	   *subpaths_list = NIL;
	List	   *partitioned_rels;
	AppendPath *append_path;
	int			parallel_nworkers;
	Cost		discount_cost;

	if (join_type != JOIN_INNER &&
		join_type != JOIN_LEFT)
		return;
	if (required_outer != NULL)
		return;
	Assert(extra != NULL);
	subpaths_list =
		__extract_partitionwise_pathlist(root,
										 joinrel,
										 outer_path,
										 list_make1(inner_path->parent),
										 list_make1_int(join_type),
										 list_make1(extra->restrictlist),
										 list_make1(join_nrows),
										 required_outer,
										 param_info,
										 try_outer_parallel,
										 try_inner_parallel,
										 true,
										 &append_path,
										 &parallel_nworkers,
										 &discount_cost);
	if (subpaths_list == NIL)
		return;
	/*
	 * Now inner_path X outer_path is distributed to all the leaf-pathnodes.
	 * Then, create a new AppendPath.
	 */
	partitioned_rels = copyObject(append_path->partitioned_rels);
	if (try_outer_parallel)
	{
		append_path = create_append_path(root, joinrel,
										 NIL, subpaths_list,
										 NIL, required_outer,
										 parallel_nworkers, true,
										 partitioned_rels, -1.0);
		append_path->path.total_cost -= discount_cost;
		if (gpu_path_remember(root, joinrel,
							  true, false,
							  &append_path->path))
			add_partial_path(joinrel, (Path *) append_path);
	}
	else
	{
		append_path = create_append_path(root, joinrel,
										 subpaths_list, NIL,
										 NIL, required_outer,
										 0, false,
										 partitioned_rels, -1.0);
		append_path->path.total_cost -= discount_cost;
		if (gpu_path_remember(root, joinrel,
							  false, false,
							  &append_path->path))
			add_path(joinrel, (Path *) append_path);
	}
#endif
}

/*
 * try_add_gpujoin_paths
 */
static void
try_add_gpujoin_paths(PlannerInfo *root,
					  RelOptInfo *joinrel,
					  Path *outer_path,
					  Path *inner_path,
					  JoinType join_type,
					  JoinPathExtraData *extra,
					  bool try_outer_parallel,
					  bool try_inner_parallel)
{
	Relids			required_outer;
	ParamPathInfo  *param_info;
	GpuJoinPath	   *gjpath;
	const Path	   *pathnode;
	inner_path_item *ip_item;
	List		   *ip_items_list;
	List		   *restrict_clauses = extra->restrictlist;
	ListCell	   *lc;

	/* Sanity checks */
	Assert(try_outer_parallel || !try_inner_parallel);

	/* Quick exit if unsupported join type */
	if (join_type != JOIN_INNER &&
		join_type != JOIN_FULL &&
		join_type != JOIN_RIGHT &&
		join_type != JOIN_LEFT)
		return;

	/*
	 * GpuJoin does not support JOIN in case when either side is parameterized
	 * by the other side.
	 */
	if (bms_overlap(PATH_REQ_OUTER(outer_path), inner_path->parent->relids) ||
		bms_overlap(PATH_REQ_OUTER(inner_path), outer_path->parent->relids))
		return;

	/*
	 * Check to see if proposed path is still parameterized, and reject
	 * if the parameterization wouldn't be sensible.
	 * Note that GpuNestLoop does not support parameterized nest-loop,
	 * only cross-join or non-symmetric join are supported, therefore,
	 * calc_non_nestloop_required_outer() is sufficient.
	 */
	required_outer = calc_non_nestloop_required_outer(outer_path,
													  inner_path);
	if (required_outer &&
		!bms_overlap(required_outer, extra->param_source_rels))
	{
		bms_free(required_outer);
		return;
	}

	/*
	 * Get param info
	 */
	param_info = get_joinrel_parampathinfo(root,
										   joinrel,
										   outer_path,
										   inner_path,
										   extra->sjinfo,
										   required_outer,
										   &restrict_clauses);
	/*
	 * It makes no sense to run cross join on GPU devices
	 */
	if (!restrict_clauses)
		return;

	/*
	 * All the join-clauses must be executable on GPU device.
	 * Even though older version supports HostQuals to be
	 * applied post device join, it leads undesirable (often
	 * unacceptable) growth of the result rows in device join.
	 * So, we simply reject any join that contains host-only
	 * qualifiers.
	 */
	foreach (lc, restrict_clauses)
	{
		RestrictInfo   *rinfo = lfirst(lc);

		if (!pgstrom_device_expression(root, joinrel, rinfo->clause))
			return;
	}

	/*
	 * setup inner_path_item
	 */
	ip_item = palloc0(sizeof(inner_path_item));
	ip_item->join_type = join_type;
	ip_item->inner_path = inner_path;
	ip_item->join_quals = restrict_clauses;
	ip_item->hash_quals =
		extract_gpuhashjoin_quals(root,
								  outer_path->parent->relids,
								  inner_path->parent->relids,
								  join_type,
								  restrict_clauses);
	if (ip_item->hash_quals == NIL)
		extract_gpugistindex_clause(ip_item,
									root,
									join_type,
									restrict_clauses);
	ip_item->join_nrows = joinrel->rows;
	ip_items_list = list_make1(ip_item);

	for (;;)
	{
		gjpath = create_gpujoin_path(root,
									 joinrel,
									 outer_path,
									 ip_items_list,
									 param_info,
									 required_outer,
									 try_outer_parallel,
									 try_inner_parallel);
		if (gjpath && gpu_path_remember(root, joinrel,
										try_outer_parallel,
										try_inner_parallel,
										(Path *)gjpath))
		{
			if (try_outer_parallel)
				add_partial_path(joinrel, (Path *)gjpath);
			else
				add_path(joinrel, (Path *)gjpath);
		}

		/* try to pull-up outer GpuJoin, if any */
		pathnode = gpu_path_find_cheapest(root,
										  outer_path->parent,
										  try_outer_parallel,
										  try_inner_parallel);
		if (pathnode && pgstrom_path_is_gpujoin(pathnode))
		{
			const GpuJoinPath *gjtemp = (const GpuJoinPath *)pathnode;
			int		i;

			for (i=gjtemp->num_rels-1; i>=0; i--)
			{
				inner_path_item *ip_temp = palloc0(sizeof(inner_path_item));

				ip_temp->join_type  = gjtemp->inners[i].join_type;
				ip_temp->inner_path = gjtemp->inners[i].scan_path;
				ip_temp->join_quals = gjtemp->inners[i].join_quals;
				ip_temp->hash_quals = gjtemp->inners[i].hash_quals;
				ip_temp->gist_index = gjtemp->inners[i].gist_index;
				ip_temp->gist_ctid_resno = gjtemp->inners[i].gist_ctid_resno;
				ip_temp->gist_clauses = gjtemp->inners[i].gist_clauses;
				ip_temp->gist_selectivity = gjtemp->inners[i].gist_selectivity;
				ip_temp->join_nrows = gjtemp->inners[i].join_nrows;

				ip_items_list = lcons(ip_temp, ip_items_list);
			}
			outer_path = linitial(gjtemp->cpath.custom_paths);
		}
		else
		{
			break;
		}
	}

	/* Add partition-wise GpuJoin path */
	if (enable_partitionwise_gpujoin)
		try_add_gpujoin_append_paths(root,
									 joinrel,
									 outer_path,
									 inner_path,
									 join_type,
									 extra,
									 required_outer,
									 param_info,
									 try_outer_parallel,
									 try_inner_parallel);
}

/*
 * gpujoin_add_join_path
 *
 * entrypoint of the GpuJoin logic
 */
static void
gpujoin_add_join_path(PlannerInfo *root,
					  RelOptInfo *joinrel,
					  RelOptInfo *outerrel,
					  RelOptInfo *innerrel,
					  JoinType jointype,
					  JoinPathExtraData *extra)
{
	Path	   *outer_path;
	Path	   *inner_path;
	ListCell   *lc1, *lc2;
	bool		half_parallel_done = false;
	bool		full_parallel_done = false;

	/* calls secondary module if exists */
	if (set_join_pathlist_next)
		set_join_pathlist_next(root,
							   joinrel,
							   outerrel,
							   innerrel,
							   jointype,
							   extra);

	/* nothing to do, if PG-Strom is not enabled */
	if (!pgstrom_enabled || (!enable_gpunestloop && !enable_gpuhashjoin))
		return;

	/*
	 * make a none-parallel GpuJoin path
	 */
	foreach (lc1, outerrel->pathlist)
	{
		outer_path = lfirst(lc1);

		if (bms_overlap(PATH_REQ_OUTER(outer_path),
						innerrel->relids))
			continue;
		foreach (lc2, innerrel->pathlist)
		{
			inner_path = lfirst(lc2);

			if (bms_overlap(PATH_REQ_OUTER(inner_path),
							outerrel->relids))
				continue;

			try_add_gpujoin_paths(root,
								  joinrel,
								  outer_path,
								  inner_path,
								  jointype,
								  extra,
								  false,
								  false);
			break;
		}
		break;
	}
	if (!joinrel->consider_parallel)
		return;

	/*
	 * Consider parallel GpuJoin path
	 */
	foreach (lc1, outerrel->partial_pathlist)
	{
		outer_path = lfirst(lc1);

		Assert(outer_path->parallel_safe);
		if (bms_overlap(PATH_REQ_OUTER(outer_path),
						innerrel->relids) ||
			outer_path->parallel_workers == 0)
			continue;

		if (!half_parallel_done)
		{
			foreach (lc2, innerrel->pathlist)
			{
				inner_path = lfirst(lc2);

				if (!inner_path->parallel_safe ||
					bms_overlap(PATH_REQ_OUTER(inner_path),
								outerrel->relids))
					continue;
				try_add_gpujoin_paths(root,
									  joinrel,
									  outer_path,
									  inner_path,
									  jointype,
									  extra,
									  true,
									  false);
				half_parallel_done = true;
				break;
			}
		}

		if (!full_parallel_done)
		{
			foreach (lc2, innerrel->partial_pathlist)
			{
				inner_path = lfirst(lc2);

				if (!inner_path->parallel_safe ||
					bms_overlap(PATH_REQ_OUTER(inner_path),
								outerrel->relids))
					continue;
				try_add_gpujoin_paths(root,
									  joinrel,
									  outer_path,
									  inner_path,
									  jointype,
									  extra,
									  true,
									  true);
				full_parallel_done = true;
				break;
			}
		}
		if (half_parallel_done && full_parallel_done)
			return;
	}
}

/*
 * build_device_targetlist
 *
 * It constructs a tentative custom_scan_tlist, according to
 * the expression to be evaluated, returned or shown in EXPLAIN.
 * Usually, all we need to pay attention is columns referenced by host-
 * qualifiers and target-list. However, we may need to execute entire
 * JOIN operations on CPU if GPU raised CpuReCheck error. So, we also
 * adds columns which are also referenced by device qualifiers.
 * (EXPLAIN command has to solve the name, so we have to have these
 * Var nodes in the custom_scan_tlist.)
 *
 * pgstrom_post_planner_gpujoin() may update the custom_scan_tlist
 * to push-down CPU projection. In this case, custom_scan_tlist will
 * have complicated expression not only simple Var-nodes, to simplify
 * targetlist of the CustomScan to reduce cost for CPU projection as
 * small as possible we can.
 */
typedef struct
{
	PlannerInfo	   *root;
	List		   *ps_tlist;
	List		   *ps_depth;
	List		   *ps_resno;
	List		   *ps_refby;
	GpuJoinPath	   *gpath;
	List		   *custom_plans;
	Index			outer_scanrelid;
	int				att_refby;
} build_device_tlist_context;

#define GPUJOIN_ATTR_REFERENCE_BY__PROJECTION			0x0001
#define GPUJOIN_ATTR_REFERENCE_BY__PROJECTION_ELEMS	0x0002
#define GPUJOIN_ATTR_REFERENCE_BY__OUTER_QUALS			0x0004
#define GPUJOIN_ATTR_REFERENCE_BY__JOIN_QUALS			0x0008
#define GPUJOIN_ATTR_REFERENCE_BY__OTHER_QUALS			0x0010
#define GPUJOIN_ATTR_REFERENCE_BY__HASH_INNER_KEY		0x0020
#define GPUJOIN_ATTR_REFERENCE_BY__HASH_OUTER_KEY		0x0040

static void
build_device_tlist_walker(Node *node, build_device_tlist_context *context)
{
	GpuJoinPath	   *gpath = context->gpath;
	RelOptInfo	   *gjrel = gpath->cpath.path.parent;
	RelOptInfo	   *rel;
	ListCell	   *cell;
	ListCell	   *lc1, *lc2;
	bool			resjunk;
	int				i;

	if (!node)
		return;
	resjunk = (context->att_refby != GPUJOIN_ATTR_REFERENCE_BY__PROJECTION);
	if (IsA(node, List))
	{
		List   *temp = (List *)node;

		foreach (cell, temp)
			build_device_tlist_walker(lfirst(cell), context);
	}
	else if (IsA(node, TargetEntry))
	{
		TargetEntry *tle = (TargetEntry *)node;

		build_device_tlist_walker((Node *)tle->expr, context);
	}
	else if (IsA(node, Var))
	{
		Var	   *varnode = (Var *) node;
		Var	   *ps_node;

		forboth (lc1, context->ps_tlist,
				 lc2, context->ps_refby)
		{
			TargetEntry	   *tle = lfirst(lc1);

			if (!IsA(tle->expr, Var))
				continue;

			ps_node = (Var *) tle->expr;
			if (ps_node->varno == varnode->varno &&
				ps_node->varattno == varnode->varattno &&
				ps_node->varlevelsup == varnode->varlevelsup)
			{
				Assert(ps_node->vartype == varnode->vartype &&
					   ps_node->vartypmod == varnode->vartypmod &&
					   ps_node->varcollid == varnode->varcollid);
				lfirst_int(lc2) |= context->att_refby;
				return;
			}
		}

		/*
		 * Not in the pseudo-scan targetlist, so append this one
		 */
		for (i=0; i <= gpath->num_rels; i++)
		{
			if (i == 0)
			{
				Path   *outer_path = linitial(gpath->cpath.custom_paths);

				rel = outer_path->parent;
				/* special case if outer scan was pulled up */
				if (varnode->varno == context->outer_scanrelid)
				{
					TargetEntry	   *ps_tle =
						makeTargetEntry((Expr *) copyObject(varnode),
										list_length(context->ps_tlist) + 1,
										NULL,
										resjunk);
					context->ps_tlist = lappend(context->ps_tlist, ps_tle);
					context->ps_depth = lappend_int(context->ps_depth, i);
					context->ps_resno = lappend_int(context->ps_resno,
													varnode->varattno);
					context->ps_refby = lappend_int(context->ps_refby,
													context->att_refby);
					Assert(bms_is_member(varnode->varno, rel->relids));
					Assert(varnode->varno == rel->relid);
					return;
				}
			}
			else
				rel = gpath->inners[i-1].scan_path->parent;

			if (bms_is_member(varnode->varno, rel->relids))
			{
				Plan   *plan = list_nth(context->custom_plans, i);

				foreach (cell, plan->targetlist)
				{
					TargetEntry *tle = lfirst(cell);

					if (equal(varnode, tle->expr))
					{
						TargetEntry	   *ps_tle =
							makeTargetEntry((Expr *) copyObject(varnode),
											list_length(context->ps_tlist) + 1,
											NULL,
											resjunk);
						context->ps_tlist = lappend(context->ps_tlist, ps_tle);
						context->ps_depth = lappend_int(context->ps_depth, i);
						context->ps_resno = lappend_int(context->ps_resno,
														tle->resno);
						context->ps_refby = lappend_int(context->ps_refby,
														context->att_refby);
						return;
					}
				}
				break;
			}
		}
		elog(ERROR, "Bug? uncertain origin of Var-node: %s",
			 nodeToString(varnode));
	}
	else if (IsA(node, PlaceHolderVar))
	{
		PlaceHolderVar *phvnode = (PlaceHolderVar *) node;

		foreach (cell, context->ps_tlist)
		{
			TargetEntry	   *tle = lfirst(cell);

			if (equal(phvnode, tle->expr))
				return;
		}

		/* Not in the pseudo-scan target-list, so append a new one */
		for (i=0; i <= gpath->num_rels; i++)
		{
			if (i == 0)
			{
				/*
				 * NOTE: We don't assume PlaceHolderVar that references the
				 * outer-path which was pulled-up, because only simple scan
				 * paths (SeqScan or GpuScan with no host-only qualifiers)
				 * can be pulled-up, thus, no chance for SubQuery paths.
				 */
				Index	outer_scanrelid = context->outer_scanrelid;
				Path   *outer_path = linitial(gpath->cpath.custom_paths);

				if (outer_scanrelid != 0 &&
					bms_is_member(outer_scanrelid, phvnode->phrels))
					elog(ERROR, "Bug? PlaceHolderVar referenced simple scan outer-path, not expected: %s", nodeToString(phvnode));

				rel = outer_path->parent;
			}
			else
				rel = gpath->inners[i-1].scan_path->parent;

			if (bms_is_subset(phvnode->phrels, rel->relids))
			{
				Plan   *plan = list_nth(context->custom_plans, i);

				foreach (cell, plan->targetlist)
				{
					TargetEntry	   *tle = lfirst(cell);
					TargetEntry	   *ps_tle;
					AttrNumber		ps_resno;

					if (!equal(phvnode, tle->expr))
						continue;

					ps_resno = list_length(context->ps_tlist) + 1;
					ps_tle = makeTargetEntry((Expr *) copyObject(phvnode),
											 ps_resno,
											 NULL,
											 resjunk);
					context->ps_tlist = lappend(context->ps_tlist, ps_tle);
					context->ps_depth = lappend_int(context->ps_depth, i);
					context->ps_resno = lappend_int(context->ps_resno,
													tle->resno);
					context->ps_refby = lappend_int(context->ps_refby,
													context->att_refby);
					return;
				}
			}
		}
		elog(ERROR, "Bug? uncertain origin of PlaceHolderVar-node: %s",
			 nodeToString(phvnode));
	}
	else
	{
		List   *vars_items;
		int		att_refby_saved = context->att_refby;

		if (!resjunk && pgstrom_device_expression(context->root,
												  gjrel, (Expr *)node))
		{
			TargetEntry	   *ps_tle;

			context->att_refby |= GPUJOIN_ATTR_REFERENCE_BY__PROJECTION_ELEMS;
			foreach (cell, context->ps_tlist)
			{
				TargetEntry	   *tle = lfirst(cell);

				if (equal(node, tle->expr))
					goto skip;
			}
			ps_tle = makeTargetEntry((Expr *) copyObject(node),
									 list_length(context->ps_tlist) + 1,
									 NULL,
									 resjunk);
			context->ps_tlist = lappend(context->ps_tlist, ps_tle);
			context->ps_depth = lappend_int(context->ps_depth, -1);	/* dummy */
			context->ps_resno = lappend_int(context->ps_resno, -1);	/* dummy */
			context->ps_refby = lappend_int(context->ps_refby, 0);	/* dummy */
		}
	skip:
		vars_items = pull_var_clause(node, PVC_RECURSE_PLACEHOLDERS);
		foreach (cell, vars_items)
			build_device_tlist_walker(lfirst(cell), context);
		/* restore the context */
		context->att_refby = att_refby_saved;
	}
}

static void
build_device_targetlist(PlannerInfo *root,
						GpuJoinPath *gpath,
						CustomScan *cscan,
						GpuJoinInfo *gj_info,
						List *targetlist,
						List *custom_plans)
{
	build_device_tlist_context context;
	ListCell   *lc;

	Assert(outerPlan(cscan)
		   ? cscan->scan.scanrelid == 0
		   : cscan->scan.scanrelid != 0);

	memset(&context, 0, sizeof(build_device_tlist_context));
	context.root = root;
	context.gpath = gpath;
	context.custom_plans = custom_plans;
	context.outer_scanrelid = cscan->scan.scanrelid;
	context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__PROJECTION;
	if (targetlist != NIL)
		build_device_tlist_walker((Node *)targetlist, &context);
	else
	{
		/*
		 * MEMO: If GpuJoinPath is located under ProjectionPath,
		 * create_plan_recurse delivers invalid tlist (=NIL).
		 * So, we picks up referenced Var nodes from the PathTarget,
		 * instead of the tlist.
		 */
		PathTarget *path_target = gpath->cpath.path.pathtarget;

		foreach (lc, path_target->exprs)
			build_device_tlist_walker((Node *)lfirst(lc), &context);
	}

	/*
	 * Above are host referenced columns. On the other hands, the columns
	 * newly added below are device-only columns, so it will never
	 * referenced by the host-side. We mark it resjunk=true.
	 *
	 * Also note that any Var nodes in the device executable expression
	 * must be added with resjunk=true to solve the variable name.
	 */
	context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__OUTER_QUALS;
	build_device_tlist_walker((Node *)gj_info->outer_quals, &context);

	foreach (lc, gj_info->inner_infos)
	{
		GpuJoinInnerInfo *i_info = lfirst(lc);

		context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__JOIN_QUALS;
		build_device_tlist_walker((Node *)i_info->join_quals, &context);

		context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__OTHER_QUALS;
		build_device_tlist_walker((Node *)i_info->other_quals, &context);

		context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__HASH_INNER_KEY;
		build_device_tlist_walker((Node *)i_info->hash_inner_keys, &context);

		context.att_refby = GPUJOIN_ATTR_REFERENCE_BY__HASH_OUTER_KEY;
		build_device_tlist_walker((Node *)i_info->hash_outer_keys, &context);
	}
	Assert(list_length(context.ps_tlist) == list_length(context.ps_depth) &&
		   list_length(context.ps_tlist) == list_length(context.ps_resno) &&
		   list_length(context.ps_tlist) == list_length(context.ps_refby));

	gj_info->ps_src_depth = context.ps_depth;
	gj_info->ps_src_resno = context.ps_resno;
	gj_info->ps_src_refby = context.ps_refby;
	cscan->custom_scan_tlist = context.ps_tlist;
}

/*
 * PlanGpuJoinPath
 *
 * Entrypoint to create CustomScan(GpuJoin) node
 */
static Plan *
PlanGpuJoinPath(PlannerInfo *root,
				RelOptInfo *rel,
				CustomPath *best_path,
				List *tlist,
				List *clauses,
				List *custom_plans)
{
	GpuJoinPath	   *gjpath = (GpuJoinPath *) best_path;
	RelOptInfo	   *joinrel = gjpath->cpath.path.parent;
	Index			outer_relid = gjpath->outer_relid;
	GpuJoinInfo		gj_info;
	CustomScan	   *cscan;
	codegen_context	context;
	Plan		   *outer_plan;
	ListCell	   *lc;
	double			outer_nrows;
	int				i, k;

	Assert(gjpath->num_rels + 1 == list_length(custom_plans));
	outer_plan = linitial(custom_plans);

	cscan = makeNode(CustomScan);
	cscan->scan.plan.targetlist = tlist;
	cscan->scan.plan.qual = NIL;
	cscan->scan.scanrelid = outer_relid;
	cscan->flags = best_path->flags;
	cscan->methods = &gpujoin_plan_methods;
	cscan->custom_plans = list_copy_tail(custom_plans, 1);
	Assert(list_length(cscan->custom_plans) == gjpath->num_rels);

	memset(&gj_info, 0, sizeof(GpuJoinInfo));
	gj_info.outer_ratio = 1.0;
	gj_info.outer_nrows = outer_plan->plan_rows;
	gj_info.outer_width = outer_plan->plan_width;
	gj_info.outer_startup_cost = outer_plan->startup_cost;
	gj_info.outer_total_cost = outer_plan->total_cost;
	gj_info.num_rels = gjpath->num_rels;

	if (!gjpath->sibling_param_id)
		gj_info.sibling_param_id = -1;
	else
	{
		cl_int	param_id = *gjpath->sibling_param_id;

		if (param_id < 0)
		{
			PlannerGlobal  *glob = root->glob;
#if PG_VERSION_NUM < 110000
			param_id = glob->nParamExec++;
#else
			param_id = list_length(glob->paramExecTypes);
			glob->paramExecTypes = lappend_oid(glob->paramExecTypes,
											   INTERNALOID);
#endif
			*gjpath->sibling_param_id = param_id;
		}
		gj_info.sibling_param_id = param_id;
	}
	gj_info.inner_parallel = gjpath->inner_parallel;

	outer_nrows = outer_plan->plan_rows;
	for (i=0; i < gjpath->num_rels; i++)
	{
		GpuJoinInnerInfo *i_info = palloc0(sizeof(GpuJoinInnerInfo));
		List	   *hash_inner_keys = NIL;
		List	   *hash_outer_keys = NIL;
		List	   *join_quals = NIL;
		List	   *other_quals = NIL;

		/* misc properties */
		i_info->depth = i+1;
		i_info->plan_nrows_in = outer_nrows;
		i_info->plan_nrows_out = gjpath->inners[i].join_nrows;
		i_info->ichunk_size = gjpath->inners[i].ichunk_size;
		i_info->join_type = gjpath->inners[i].join_type;

		/* GpuHashJoin properties */
		foreach (lc, gjpath->inners[i].hash_quals)
		{
			Path		   *scan_path = gjpath->inners[i].scan_path;
			RelOptInfo	   *scan_rel = scan_path->parent;
			RestrictInfo   *rinfo = lfirst(lc);
			OpExpr		   *op_clause = (OpExpr *) rinfo->clause;
			Node		   *arg1 = (Node *)linitial(op_clause->args);
			Node		   *arg2 = (Node *)lsecond(op_clause->args);
			Relids			relids1 = pull_varnos(arg1);
			Relids			relids2 = pull_varnos(arg2);

			/*
			 * NOTE: Both sides of hash-join operator may have different
			 * types if cross-type operators, like int48eq(x,y), are used.
			 * Hash functions are designed to generate same hash-value
			 * regardless of the data types, so we can run hash-join
			 * without implicit type casts.
			 */
			if (bms_is_subset(relids1, scan_rel->relids) &&
				!bms_is_subset(relids2, scan_rel->relids))
			{
				hash_inner_keys = lappend(hash_inner_keys, arg1);
				hash_outer_keys = lappend(hash_outer_keys, arg2);
			}
			else if (bms_is_subset(relids2, scan_rel->relids) &&
					 !bms_is_subset(relids1, scan_rel->relids))
			{
				hash_inner_keys = lappend(hash_inner_keys, arg2);
				hash_outer_keys = lappend(hash_outer_keys, arg1);
			}
			else
				elog(ERROR, "Bug? hash-clause reference bogus varnos");
		}
		/* OUTER JOIN handling */
		if (IS_OUTER_JOIN(i_info->join_type))
		{
			extract_actual_join_clauses(gjpath->inners[i].join_quals,
										best_path->path.parent->relids,
										&join_quals, &other_quals);
		}
		else
		{
			join_quals = extract_actual_clauses(gjpath->inners[i].join_quals,
												false);
			other_quals = NIL;
		}
		i_info->join_quals = join_quals;
		i_info->other_quals = other_quals;
		i_info->hash_inner_keys = hash_inner_keys;
		i_info->hash_outer_keys = hash_outer_keys;

		/* GpuGistIndex properties */
		if (gjpath->inners[i].gist_index != NULL)
		{
			IndexOptInfo   *gist_index = gjpath->inners[i].gist_index;

			i_info->gist_index_reloid = gist_index->indexoid;
			i_info->gist_index_ctid_resno = gjpath->inners[i].gist_ctid_resno;
			i_info->gist_index_clauses = gjpath->inners[i].gist_clauses;
		}
		gj_info.inner_infos = lappend(gj_info.inner_infos, i_info);

		outer_nrows = i_info->plan_nrows_out;
	}

	/*
	 * If outer-plan node is simple relation scan; SeqScan or GpuScan with
	 * device executable qualifiers, GpuJoin can handle the relation scan
	 * for better i/o performance. Elsewhere, call the child outer node.
	 */
	if (outer_relid)
	{
		RelOptInfo *baserel = root->simple_rel_array[outer_relid];
		Bitmapset  *referenced = NULL;
		List	   *outer_quals = gjpath->outer_quals;
		List	   *outer_refs = NULL;

		/* pick up outer referenced columns */
		pull_varattnos((Node *)outer_quals, outer_relid, &referenced);
		referenced = pgstrom_pullup_outer_refs(root, baserel, referenced);
		for (k = bms_next_member(referenced, -1);
			 k >= 0;
			 k = bms_next_member(referenced, k))
		{
			i = k + FirstLowInvalidHeapAttributeNumber;
			if (i >= 0)
				outer_refs = lappend_int(outer_refs, i);
		}

		/* BRIN-index stuff */
		if (gjpath->index_opt)
		{
			gj_info.index_oid = gjpath->index_opt->indexoid;
			gj_info.index_conds = gjpath->index_conds;
			gj_info.index_quals
				= extract_actual_clauses(gjpath->index_quals, false);
		}
		gj_info.outer_quals = outer_quals;
		gj_info.outer_refs = outer_refs;
	}
	else
	{
		outerPlan(cscan) = outer_plan;
		Assert(gjpath->outer_quals == NIL);
		Assert(gjpath->index_opt == NULL);
	}
	gj_info.outer_nrows_per_block = gjpath->outer_nrows_per_block;

	/*
	 * Build a tentative pseudo-scan targetlist. At this point, we cannot
	 * know which expression shall be applied on the final results, thus,
	 * all we can construct is a pseudo-scan targetlist that is consists
	 * of Var-nodes only.
	 */
	build_device_targetlist(root, gjpath, cscan, &gj_info,
							tlist, custom_plans);

	/*
	 * construct kernel code
	 */
	pgstrom_init_codegen_context(&context, root, joinrel);
	gj_info.optimal_gpu = gjpath->optimal_gpu;
	gj_info.kern_source = gpujoin_codegen(root,
										  cscan,
										  gjpath,
										  &gj_info,
										  tlist,
										  &context);
	gj_info.extra_flags = context.extra_flags | DEVKERNEL_NEEDS_GPUJOIN;
	gj_info.used_params = context.used_params;

	form_gpujoin_info(cscan, &gj_info);

	return &cscan->scan.plan;
}

typedef struct
{
	int		depth;
	List   *ps_src_depth;
	List   *ps_src_resno;
} fixup_varnode_to_origin_context;

static Node *
fixup_varnode_to_origin_mutator(Node *node,
								fixup_varnode_to_origin_context *context)
{
	if (!node)
		return NULL;
	if (IsA(node, Var))
	{
		Var	   *varnode = (Var *) node;
		int		varattno = varnode->varattno;
		int		src_depth;

		Assert(varnode->varno == INDEX_VAR);
		src_depth = list_nth_int(context->ps_src_depth,
								 varnode->varattno - 1);
		if (src_depth == context->depth)
		{
			Var	   *newnode = copyObject(varnode);

			newnode->varno = INNER_VAR;
			newnode->varattno = list_nth_int(context->ps_src_resno,
											 varattno - 1);
			return (Node *) newnode;
		}
		else if (src_depth > context->depth)
			elog(ERROR, "Expression reference deeper than current depth");
	}
	return expression_tree_mutator(node, fixup_varnode_to_origin_mutator,
								   (void *) context);
}

static List *
fixup_varnode_to_origin(int depth,
						List *ps_src_depth,
						List *ps_src_resno,
						List *expr_list)
{
	fixup_varnode_to_origin_context	context;

	Assert(IsA(expr_list, List));
	memset(&context, 0 , sizeof(fixup_varnode_to_origin_context));
	context.depth = depth;
	context.ps_src_depth = ps_src_depth;
	context.ps_src_resno = ps_src_resno;

	return (List *) fixup_varnode_to_origin_mutator((Node *)expr_list,
													&context);
}

/*
 * assign_gpujoin_session_info
 *
 * Gives some definitions to the static portion of GpuJoin implementation
 */
void
assign_gpujoin_session_info(StringInfo buf, GpuTaskState *gts)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;

	Assert(gts->css.methods == &gpujoin_exec_methods);
	appendStringInfo(
		buf,
		"#define GPUJOIN_MAX_DEPTH %u\n",
		gjs->num_rels);
}

static Node *
gpujoin_create_scan_state(CustomScan *node)
{
	GpuJoinState   *gjs;
	cl_int			num_rels = list_length(node->custom_plans);

	gjs = MemoryContextAllocZero(CurTransactionContext,
								 offsetof(GpuJoinState,
										  inners[num_rels]));
	NodeSetTag(gjs, T_CustomScanState);
	gjs->gts.css.flags = node->flags;
	gjs->gts.css.methods = &gpujoin_exec_methods;

	return (Node *) gjs;
}

static void
ExecInitGpuJoin(CustomScanState *node, EState *estate, int eflags)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;
	ScanState	   *ss = &gjs->gts.css.ss;
	CustomScan	   *cscan = (CustomScan *) node->ss.ps.plan;
	GpuJoinInfo	   *gj_info = deform_gpujoin_info(cscan);
	TupleDesc		result_tupdesc = planStateResultTupleDesc(&ss->ps);
	TupleDesc		scan_tupdesc;
	TupleDesc		junk_tupdesc;
	List		   *tlist_fallback = NIL;
	bool			fallback_needs_projection = false;
	bool			fallback_meets_resjunk = false;
	bool			explain_only = ((eflags & EXEC_FLAG_EXPLAIN_ONLY) != 0);
	ListCell	   *lc1, *lc2, *lc3;
	cl_int			i, j, nattrs;
	StringInfoData	kern_define;
	ProgramId		program_id;

	/* activate a GpuContext for CUDA kernel execution */
	gjs->gts.gcontext = AllocGpuContext(gj_info->optimal_gpu, false, false);

	/*
	 * Re-initialization of scan tuple-descriptor and projection-info,
	 * because commit 1a8a4e5cde2b7755e11bde2ea7897bd650622d3e of
	 * PostgreSQL makes to assign result of ExecTypeFromTL() instead
	 * of ExecCleanTypeFromTL; that leads unnecessary projection.
	 * So, we try to remove junk attributes from the scan-descriptor.
	 *
	 * Also note that the supplied TupleDesc that contains junk attributes
	 * are still useful to run CPU fallback code. So, we keep this tuple-
	 * descriptor to initialize the related stuff.
	 */
	junk_tupdesc = gjs->gts.css.ss.ss_ScanTupleSlot->tts_tupleDescriptor;
	scan_tupdesc = ExecCleanTypeFromTL(cscan->custom_scan_tlist);
	ExecInitScanTupleSlot(estate, &gjs->gts.css.ss, scan_tupdesc,
						  &TTSOpsVirtual);
	ExecAssignScanProjectionInfoWithVarno(&gjs->gts.css.ss, INDEX_VAR);

	/* Setup common GpuTaskState fields */
	pgstromInitGpuTaskState(&gjs->gts,
							gjs->gts.gcontext,
							GpuTaskKind_GpuJoin,
							gj_info->outer_refs,
							gj_info->used_params,
							gj_info->optimal_gpu,
							gj_info->outer_nrows_per_block,
							eflags);
	gjs->gts.cb_next_tuple		= gpujoin_next_tuple;
	gjs->gts.cb_next_task		= gpujoin_next_task;
	gjs->gts.cb_terminator_task	= gpujoin_terminator_task;
	gjs->gts.cb_switch_task		= gpujoin_switch_task;
	gjs->gts.cb_process_task	= gpujoin_process_task;
	gjs->gts.cb_release_task	= gpujoin_release_task;

	/* DSM & GPU memory of inner buffer */
	gjs->h_kmrels = NULL;
	gjs->m_kmrels = 0UL;
	gjs->m_kmrels_owner = false;
	gjs->inner_parallel = gj_info->inner_parallel;
	gjs->preload_memcxt = AllocSetContextCreate(estate->es_query_cxt,
												"Inner GPU Buffer Preloading",
												ALLOCSET_DEFAULT_SIZES);
	if (gj_info->sibling_param_id >= 0)
	{
		ParamExecData  *param
			= &(estate->es_param_exec_vals[gj_info->sibling_param_id]);
		if (param->value == 0UL)
		{
			GpuJoinSiblingState *sibling
				= palloc0(offsetof(GpuJoinSiblingState,
								   pergpu[numDevAttrs]));
			sibling->leader = gjs;
			param->isnull = false;
			param->value = PointerGetDatum(sibling);
		}
		gjs->sibling = (GpuJoinSiblingState *)DatumGetPointer(param->value);
		gjs->sibling->nr_siblings++;
	}

	/*
	 * NOTE: outer_quals, hash_outer_keys and join_quals are intended
	 * to use fallback routine if GPU kernel required host-side to
	 * retry a series of hash-join/nest-loop operation. So, we need to
	 * pay attention which slot is actually referenced.
	 * Right now, ExecEvalScalarVar can reference only three slots
	 * simultaneously (scan, inner and outer). So, varno of varnodes
	 * has to be initialized according to depth of the expression.
	 *
	 * TODO: we have to initialize above expressions carefully for
	 * CPU fallback implementation.
	 */
	gjs->num_rels = gj_info->num_rels;
	if (gj_info->outer_quals)
		gjs->outer_quals = ExecInitQual(gj_info->outer_quals, &ss->ps);
	gjs->outer_ratio = gj_info->outer_ratio;
	gjs->outer_nrows = gj_info->outer_nrows;
	Assert(!cscan->scan.plan.qual);

	/*
	 * Init OUTER child node
	 */
	if (gjs->gts.css.ss.ss_currentRelation)
	{
		Relation	scan_rel = gjs->gts.css.ss.ss_currentRelation;

		pgstromExecInitBrinIndexMap(&gjs->gts,
									gj_info->index_oid,
									gj_info->index_conds,
									gj_info->index_quals);
		nattrs = RelationGetNumberOfAttributes(scan_rel);
	}
	else
	{
		TupleDesc	outer_desc;

		outerPlanState(gjs) = ExecInitNode(outerPlan(cscan), estate, eflags);
		outer_desc = planStateResultTupleDesc(outerPlanState(gjs));
		nattrs = outer_desc->natts;
		Assert(!OidIsValid(gj_info->index_oid));
	}

	/*
	 * Init CPU fallback stuff
	 */
	foreach (lc1, cscan->custom_scan_tlist)
	{
		TargetEntry	   *tle = lfirst(lc1);
		Var			   *var;

		/*
		 * NOTE: Var node inside of general expression shall reference
		 * the custom_scan_tlist recursively. Thus, we don't need to
		 * care about varno/varattno fixup here.
		 */
		Assert(IsA(tle, TargetEntry));

		/*
		 * Because ss_ScanTupleSlot does not contain junk attribute,
		 * we have to remove junk attribute by projection, if any of
		 * target-entry in custom_scan_tlist (that is tuple format to
		 * be constructed by CPU fallback) are junk.
		 */
		if (tle->resjunk)
		{
			fallback_needs_projection = true;
			fallback_meets_resjunk = true;
		}
		else
		{
			/* no valid attribute after junk attribute */
			if (fallback_meets_resjunk)
				elog(ERROR, "Bug? a valid attribute appear after junk ones");

			Assert(!fallback_meets_resjunk);

			if (IsA(tle->expr, Var))
			{
				tle = copyObject(tle);
				var = (Var *) tle->expr;
				var->varnosyn	= var->varno;
				var->varattnosyn = var->varattno;
				var->varno		= INDEX_VAR;
				var->varattno	= tle->resno;
			}
			else
			{
				/* also, non-simple Var node needs projection */
				fallback_needs_projection = true;
			}
			tlist_fallback = lappend(tlist_fallback, tle);
		}
	}

	if (fallback_needs_projection)
	{
		gjs->slot_fallback = MakeSingleTupleTableSlot(junk_tupdesc,
													  &TTSOpsVirtual);
		gjs->proj_fallback = ExecBuildProjectionInfo(tlist_fallback,
													 ss->ps.ps_ExprContext,
													 ss->ss_ScanTupleSlot,
													 &ss->ps,
													 junk_tupdesc);
	}
	else
	{
		gjs->slot_fallback = ss->ss_ScanTupleSlot;
		gjs->proj_fallback = NULL;
	}
	ExecStoreAllNullTuple(gjs->slot_fallback);

	gjs->outer_src_anum_min = nattrs;
	gjs->outer_src_anum_max = FirstLowInvalidHeapAttributeNumber;
	nattrs -= FirstLowInvalidHeapAttributeNumber;
	gjs->outer_dst_resno = palloc0(sizeof(AttrNumber) * nattrs);
	j = 1;
	forboth (lc1, gj_info->ps_src_depth,
			 lc2, gj_info->ps_src_resno)
	{
		int		depth = lfirst_int(lc1);
		int		resno = lfirst_int(lc2);

		if (depth == 0)
		{
			if (gjs->outer_src_anum_min > resno)
				gjs->outer_src_anum_min = resno;
			if (gjs->outer_src_anum_max < resno)
				gjs->outer_src_anum_max = resno;
			resno -= FirstLowInvalidHeapAttributeNumber;
			Assert(resno > 0 && resno <= nattrs);
			gjs->outer_dst_resno[resno - 1] = j;
		}
		j++;
	}
	gjs->fallback_outer_index = -1;

	/*
	 * Init INNER child nodes for each depth
	 */
	for (i=0; i < gj_info->num_rels; i++)
	{
		innerState *istate = &gjs->inners[i];
		GpuJoinInnerInfo *i_info = list_nth(gj_info->inner_infos, i);
		Plan	   *inner_plan = list_nth(cscan->custom_plans, i);
		List	   *hash_inner_keys = i_info->hash_inner_keys;
		List	   *hash_outer_keys = i_info->hash_outer_keys;
		TupleDesc	inner_tupdesc;

		istate->state = ExecInitNode(inner_plan, estate, eflags);
		istate->econtext = CreateExprContext(estate);
		istate->preload_nitems = 0;
		istate->preload_usage = 0;
		slist_init(&istate->preload_tuples);
		
		istate->depth = i + 1;
		istate->nrows_ratio = i_info->plan_nrows_out / Max(i_info->plan_nrows_in, 1.0);
		istate->ichunk_size = i_info->ichunk_size;
		istate->join_type = i_info->join_type;

		/*
		 * NOTE: We need to deal with Var-node references carefully,
		 * because varno/varattno pair depends on the context when
		 * ExecQual() is called.
		 * - join_quals and hash_outer_keys are only called for
		 * fallback process when CpuReCheck error was returned.
		 * So, we can expect values are stored in ecxt_scantuple
		 * according to the pseudo-scan-tlist.
		 *- hash_inner_keys are only called to construct hash-table
		 * prior to GPU execution, so, we can expect input values
		 * are deployed according to the result of child plans.
		 */
		if (i_info->join_quals)
		{
			Assert(IsA(i_info->join_quals, List));
			istate->join_quals = ExecInitQual(i_info->join_quals, &ss->ps);
		}

		if (i_info->other_quals)
		{
			Assert(IsA(i_info->other_quals, List));
			istate->other_quals = ExecInitQual(i_info->other_quals, &ss->ps);
		}

		Assert(list_length(hash_inner_keys) == list_length(hash_outer_keys));
		if (hash_inner_keys != NIL && hash_outer_keys != NIL)
		{
			hash_inner_keys = fixup_varnode_to_origin(istate->depth,
													  gj_info->ps_src_depth,
													  gj_info->ps_src_resno,
													  hash_inner_keys);
			forboth (lc1, hash_inner_keys,
					 lc2, hash_outer_keys)
			{
				Expr	   *i_expr = lfirst(lc1);
				Expr	   *o_expr = lfirst(lc2);
				ExprState  *i_expr_state = ExecInitExpr(i_expr, &ss->ps);
				ExprState  *o_expr_state = ExecInitExpr(o_expr, &ss->ps);

				istate->hash_inner_keys =
					lappend(istate->hash_inner_keys, i_expr_state);
				istate->hash_outer_keys =
					lappend(istate->hash_outer_keys, o_expr_state);
			}
		}

		if (OidIsValid(i_info->gist_index_reloid))
		{
			TargetEntry	*tle;
			Var		   *var;

			istate->gist_irel = index_open(i_info->gist_index_reloid,
										   AccessShareLock);
			if (i_info->gist_index_ctid_resno < 1 ||
				i_info->gist_index_ctid_resno > list_length(inner_plan->targetlist))
				elog(ERROR, "GPU-GiST: inner ctid is out of range");
			tle = list_nth(inner_plan->targetlist,
						   i_info->gist_index_ctid_resno - 1);
			var = (Var *)tle->expr;
			if (!IsA(tle->expr, Var) || var->vartype != TIDOID)
				elog(ERROR, "GPU-GiST: wrong Var-definition for inner ctid");
			istate->gist_ctid_resno = i_info->gist_index_ctid_resno;
		}

		/*
		 * CPU fallback setup for INNER reference
		 */
		inner_tupdesc = planStateResultTupleDesc(istate->state);
		nattrs = inner_tupdesc->natts;
		istate->inner_src_anum_min = nattrs;
		istate->inner_src_anum_max = FirstLowInvalidHeapAttributeNumber;
		nattrs -= FirstLowInvalidHeapAttributeNumber;
		istate->inner_dst_resno = palloc0(sizeof(AttrNumber) * nattrs);

		j = 1;
		forthree (lc1, gj_info->ps_src_depth,
				  lc2, gj_info->ps_src_resno,
				  lc3, gj_info->ps_src_refby)
		{
			int		depth = lfirst_int(lc1);
			int		resno = lfirst_int(lc2);
			int		refby = lfirst_int(lc3);

			if (depth == istate->depth)
			{
				const FormData_pg_attribute *attr;

				if (resno > 0)
					attr = tupleDescAttr(inner_tupdesc, resno-1);
				else
					attr = SystemAttributeDefinition(resno);
				
				if (istate->inner_src_anum_min > resno)
					istate->inner_src_anum_min = resno;
				if (istate->inner_src_anum_max < resno)
					istate->inner_src_anum_max = resno;
				resno -= FirstLowInvalidHeapAttributeNumber;
				Assert(resno > 0 && resno <= nattrs);
				istate->inner_dst_resno[resno - 1] = j;

				if (attr->attlen  == -1 &&
					(refby & (GPUJOIN_ATTR_REFERENCE_BY__PROJECTION_ELEMS |
							  GPUJOIN_ATTR_REFERENCE_BY__OUTER_QUALS |
							  GPUJOIN_ATTR_REFERENCE_BY__JOIN_QUALS |
							  GPUJOIN_ATTR_REFERENCE_BY__OTHER_QUALS |
							  GPUJOIN_ATTR_REFERENCE_BY__HASH_INNER_KEY)) != 0)
					istate->preload_flatten_attrs =
						bms_add_member(istate->preload_flatten_attrs, resno);
			}
			j++;
		}
		/* add inner state as children of this custom-scan */
		gjs->gts.css.custom_ps = lappend(gjs->gts.css.custom_ps,
										 istate->state);
	}
	initStringInfo(&kern_define);
	pgstrom_build_session_info(&kern_define,
							   &gjs->gts,
							   gj_info->extra_flags);
	program_id = pgstrom_create_cuda_program(gjs->gts.gcontext,
											 gj_info->extra_flags,
											 gj_info->varlena_bufsz,
											 gj_info->kern_source,
											 kern_define.data,
											 false,
											 explain_only);
	gjs->gts.program_id = program_id;
	pfree(kern_define.data);

	/* expected kresults buffer expand rate */
	gjs->result_width =
		MAXALIGN(offsetof(HeapTupleHeaderData,
						  t_bits[BITMAPLEN(result_tupdesc->natts)]) +
				 (tupleDescHasOid(result_tupdesc) ? sizeof(Oid) : 0)) +
		MAXALIGN(cscan->scan.plan.plan_width);	/* average width */
}

/*
 * ExecReCheckGpuJoin
 *
 * Routine of EPQ recheck on GpuJoin. Join condition shall be checked on
 * the EPQ tuples.
 */
static bool
ExecReCheckGpuJoin(CustomScanState *node, TupleTableSlot *slot)
{
	/*
	 * TODO: Extract EPQ tuples on CPU fallback slot, then check
	 * join condition by CPU
	 */
	return true;
}

/*
 * ExecGpuJoin
 */
static TupleTableSlot *
ExecGpuJoin(CustomScanState *node)
{
	GpuJoinState *gjs = (GpuJoinState *) node;

	ActivateGpuContext(gjs->gts.gcontext);
	if (!GpuJoinInnerPreload(&gjs->gts, NULL))
		return NULL;
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) pgstromExecGpuTaskState,
					(ExecScanRecheckMtd) ExecReCheckGpuJoin);
}

static void
ExecEndGpuJoin(CustomScanState *node)
{
	GpuJoinState *gjs = (GpuJoinState *) node;
	int		i;

	/* wait for completion of any asynchronous GpuTask */
	SynchronizeGpuContext(gjs->gts.gcontext);
	/* close index related stuff if any */
	pgstromExecEndBrinIndexMap(&gjs->gts);
	/* shutdown inner/outer subtree */
	ExecEndNode(outerPlanState(node));
	for (i=0; i < gjs->num_rels; i++)
	{
		innerState	   *istate = &gjs->inners[i];

		if (istate->gist_irel)
			index_close(istate->gist_irel, NoLock);
		ExecEndNode(istate->state);
	}
	/* then other private resources */
	GpuJoinInnerUnload(&gjs->gts, false);
	/* shutdown the common portion */
	pgstromReleaseGpuTaskState(&gjs->gts, NULL);
}

static void
ExecReScanGpuJoin(CustomScanState *node)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;
	cl_int			i;

	/* wait for completion of any asynchronous GpuTask */
	SynchronizeGpuContext(gjs->gts.gcontext);
	/* rescan the outer sub-plan */
	if (outerPlanState(gjs))
		ExecReScan(outerPlanState(gjs));
	gjs->gts.scan_overflow = NULL;

	/*
	 * NOTE: ExecReScan() does not pay attention on the PlanState within
	 * custom_ps, so we need to assign its chgParam by ourself.
	 */
	if (gjs->gts.css.ss.ps.chgParam != NULL)
	{
		for (i=0; i < gjs->num_rels; i++)
		{
			innerState *istate = &gjs->inners[i];

			UpdateChangedParamSet(gjs->inners[i].state,
								  gjs->gts.css.ss.ps.chgParam);
			if (istate->state->chgParam != NULL)
				ExecReScan(istate->state);
		}
		/* rewind the inner hash/heap buffer */
		GpuJoinInnerUnload(&gjs->gts, true);
	}
	/* common rescan handling */
	pgstromRescanGpuTaskState(&gjs->gts);
}

static void
ExplainGpuJoin(CustomScanState *node, List *ancestors, ExplainState *es)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;
	CustomScan	   *cscan = (CustomScan *) node->ss.ps.plan;
	GpuJoinInfo	   *gj_info = deform_gpujoin_info(cscan);
	GpuJoinRuntimeStat *gj_rtstat = NULL;
	List		   *dcontext;
	ListCell	   *lc1;
	char		   *temp;
	char			qlabel[128];
	int				depth;
	StringInfoData	str;

	initStringInfo(&str);

	if (gjs->gj_sstate)
		gj_rtstat = GPUJOIN_RUNTIME_STAT(gjs->gj_sstate);
	if (gj_rtstat)
		mergeGpuTaskRuntimeStat(&gjs->gts, &gj_rtstat->c);
	if (gjs->gts.css.ss.ps.instrument)
		memcpy(&gjs->gts.css.ss.ps.instrument->bufusage,
			   &gjs->gts.outer_instrument.bufusage,
			   sizeof(BufferUsage));

	/* deparse context */
	dcontext =  set_deparse_context_planstate(es->deparse_cxt,
											  (Node *) node,
											  ancestors);
	/* Device projection (verbose only) */
	if (es->verbose)
	{
		resetStringInfo(&str);
		foreach (lc1, cscan->custom_scan_tlist)
		{
			TargetEntry	   *tle = lfirst(lc1);

			if (tle->resjunk)
				continue;

			if (lc1 != list_head(cscan->custom_scan_tlist))
				appendStringInfo(&str, ", ");
			if (tle->resjunk)
				appendStringInfoChar(&str, '[');
			temp = deparse_expression((Node *)tle->expr,
									  dcontext, true, false);
			appendStringInfo(&str, "%s", temp);
			if (es->verbose)
			{
				temp = format_type_with_typemod(exprType((Node *)tle->expr),
												exprTypmod((Node *)tle->expr));
				appendStringInfo(&str, "::%s", temp);
			}
			if (tle->resjunk)
				appendStringInfoChar(&str, ']');
		}
		ExplainPropertyText("GPU Projection", str.data, es);
	}

	/* statistics for outer scan, if any */
	pgstromExplainOuterScan(&gjs->gts, dcontext, ancestors, es,
							gj_info->outer_quals,
                            gj_info->outer_startup_cost,
                            gj_info->outer_total_cost,
                            gj_info->outer_nrows,
                            gj_info->outer_width);
	/* siblings-identifier for asymmetric partition-wise join */
	if (gj_info->sibling_param_id >= 0)
	{
		ExplainPropertyInteger("Inner sibling-id", NULL,
							   gj_info->sibling_param_id, es);
	}

	/* join-qualifiers */
	depth = 1;
	foreach (lc1, gj_info->inner_infos)
	{
		innerState *istate = &gjs->inners[depth-1];
		GpuJoinInnerInfo *i_info = lfirst(lc1);
		JoinType	join_type = i_info->join_type;
		List	   *join_quals = i_info->join_quals;
		List	   *other_quals = i_info->other_quals;
		List	   *hash_outer_keys = i_info->hash_outer_keys;
		Oid			gist_index_reloid = i_info->gist_index_reloid;
		List	   *gist_index_clauses = i_info->gist_index_clauses;
		kern_data_store *kds_in = NULL;
		kern_data_store *kds_gist = NULL;
		int			indent_width;
		double		exec_nrows_in = 0.0;
		double		exec_nrows_out1 = 0.0;	/* by INNER JOIN */
		double		exec_nrows_out2 = 0.0;	/* by OUTER JOIN */
		uint64		exec_nrows_gist = 0.0;	/* by GiST Index */

		if (gjs->h_kmrels)
		{
			kds_in = KERN_MULTIRELS_INNER_KDS(gjs->h_kmrels, depth);
			kds_gist = KERN_MULTIRELS_GIST_INDEX(gjs->h_kmrels, depth);
		}

		/* fetch number of rows */
		if (gj_rtstat)
		{
			exec_nrows_in = (double)
				(pg_atomic_read_u64(&gj_rtstat->jstat[depth-1].inner_nitems) +
				 pg_atomic_read_u64(&gj_rtstat->jstat[depth-1].right_nitems));
			exec_nrows_out1 = (double)
				pg_atomic_read_u64(&gj_rtstat->jstat[depth].inner_nitems);
			exec_nrows_out2 = (double)
				pg_atomic_read_u64(&gj_rtstat->jstat[depth].right_nitems);
			exec_nrows_gist = pg_atomic_read_u64(&gj_rtstat->jstat[depth].inner_nitems2);
		}

		resetStringInfo(&str);
		if (hash_outer_keys != NULL)
		{
			appendStringInfo(&str, "GpuHash%sJoin",
							 join_type == JOIN_FULL ? "Full" :
							 join_type == JOIN_LEFT ? "Left" :
							 join_type == JOIN_RIGHT ? "Right" : "");
		}
		else if (i_info->gist_index_clauses != NULL)
		{
			appendStringInfo(&str, "GpuGiST%sJoin",
							 join_type == JOIN_FULL ? "Full" :
							 join_type == JOIN_LEFT ? "Left" :
							 join_type == JOIN_RIGHT ? "Right" : "");
		}
		else
		{
			appendStringInfo(&str, "GpuNestLoop%s",
							 join_type == JOIN_FULL ? "Full" :
							 join_type == JOIN_LEFT ? "Left" :
							 join_type == JOIN_RIGHT ? "Right" : "");
		}
		snprintf(qlabel, sizeof(qlabel), "Depth%2d", depth);
		indent_width = es->indent * 2 + strlen(qlabel) + 2;

		if (es->format == EXPLAIN_FORMAT_TEXT)
		{
			if (es->costs)
			{
				if (!gj_rtstat)
					appendStringInfo(&str, "(nrows %.0f...%.0f)",
									 i_info->plan_nrows_in,
									 i_info->plan_nrows_out);
				else if (exec_nrows_out2 > 0.0)
					appendStringInfo(&str, "(plan nrows: %.0f...%.0f,"
									 " actual nrows: %.0f...%.0f+%.0f)",
									 i_info->plan_nrows_in,
									 i_info->plan_nrows_out,
									 exec_nrows_in,
									 exec_nrows_out1,
									 exec_nrows_out2);
				else
					appendStringInfo(&str, "(plan nrows: %.0f...%.0f,"
									 " actual nrows: %.0f...%.0f)",
									 i_info->plan_nrows_in,
									 i_info->plan_nrows_out,
									 exec_nrows_in,
									 exec_nrows_out1);
			}
			ExplainPropertyText(qlabel, str.data, es);

			appendStringInfoSpaces(es->str, indent_width);
			if (!kds_in)
			{
				appendStringInfo(es->str, "%sSize: %s",
								 hash_outer_keys ? "Hash" : "Heap",
								 format_bytesz(istate->ichunk_size));
			}
			else
			{
				appendStringInfo(es->str, "%sSize: %s (estimated: %s)",
								 hash_outer_keys ? "Hash" : "Heap",
								 format_bytesz(kds_in->length),
								 format_bytesz(istate->ichunk_size));
			}
			if (kds_gist)
			{
				appendStringInfo(es->str, ", IndexSize: %s",
								 format_bytesz(kds_gist->length));
			}
			appendStringInfoChar(es->str, '\n');
		}
		else
		{
			ExplainPropertyText(qlabel, str.data, es);

			if (es->costs)
			{
				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d Plan Rows-in", depth);
				ExplainPropertyFloat(qlabel, NULL, i_info->plan_nrows_in, 0, es);

				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d Plan Rows-out", depth);
				ExplainPropertyFloat(qlabel, NULL, i_info->plan_nrows_out, 0, es);

				if (gj_rtstat)
				{
					snprintf(qlabel, sizeof(qlabel),
							 "Depth% 2d Actual Rows-in", depth);
					ExplainPropertyFloat(qlabel, NULL, exec_nrows_in, 0, es);

					snprintf(qlabel, sizeof(qlabel),
							 "Depth% 2d Actual Rows-out by inner join", depth);
					ExplainPropertyFloat(qlabel, NULL, exec_nrows_out1, 0, es);

					snprintf(qlabel, sizeof(qlabel),
							 "Depth% 2d Actual Rows-out by outer join", depth);
					ExplainPropertyFloat(qlabel, NULL, exec_nrows_out2, 0, es);
				}
			}

			snprintf(qlabel, sizeof(qlabel), "Depth % 2d KDS Plan Size", depth);
			ExplainPropertyInteger(qlabel, NULL, istate->ichunk_size, es);
			if (kds_in)
			{
				snprintf(qlabel, sizeof(qlabel), "Depth % 2d KDS Exec Size", depth);
				ExplainPropertyInteger(qlabel, NULL, kds_in->length, es);
			}
			if (kds_gist)
			{
				snprintf(qlabel, sizeof(qlabel), "Depth% 2d Index Size", depth);
				ExplainPropertyInteger(qlabel, NULL, kds_gist->length, es);
			}			
		}

		/*
		 * HashJoinKeys, if any
		 */
		if (hash_outer_keys)
		{
			temp = deparse_expression((Node *)hash_outer_keys,
                                      dcontext, true, false);
			if (es->format == EXPLAIN_FORMAT_TEXT)
			{
				appendStringInfoSpaces(es->str, indent_width);
				appendStringInfo(es->str, "HashKeys: %s\n", temp);
			}
			else
			{
				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d HashKeys", depth);
				ExplainPropertyText(qlabel, temp, es);
			}
		}
		/*
		 * GiST Index, if any
		 */
		if (OidIsValid(gist_index_reloid) && gist_index_clauses != NIL)
		{
			const char *iname;
			Node	   *clause;

			if (list_length(gist_index_clauses) > 1)
				clause = (Node *)gist_index_clauses;
			else
				clause = linitial(gist_index_clauses);

			temp = deparse_expression(clause, dcontext, true, false);
			iname = get_rel_name(gist_index_reloid);
			if (es->format == EXPLAIN_FORMAT_TEXT)
			{
				appendStringInfoSpaces(es->str, indent_width);
				appendStringInfo(es->str, "IndexFilter: %s on %s\n",
								 temp, iname);
			}
			else
			{
				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d GiST Index", depth);
				ExplainPropertyText(qlabel, iname, es);
				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d GiST Filter", depth);
				ExplainPropertyText(qlabel, temp, es);
			}

			if (es->analyze)
			{
				if (es->format == EXPLAIN_FORMAT_TEXT)
				{
					appendStringInfoSpaces(es->str, indent_width);
					appendStringInfo(es->str, "Rows Fetched by Index: %lu\n",
									 exec_nrows_gist);
				}
				else
				{
					ExplainPropertyInteger("Rows Fetched by Index", NULL,
										   exec_nrows_gist, es);
				}
			}
		}
		/*
		 * JoinQuals, if any
		 */
		if (join_quals)
		{
			temp = deparse_expression((Node *)join_quals, dcontext,
									  true, false);
			if (es->format == EXPLAIN_FORMAT_TEXT)
			{
				appendStringInfoSpaces(es->str, indent_width);
				appendStringInfo(es->str, "JoinQuals: %s\n", temp);
			}
			else
			{
				snprintf(qlabel, sizeof(qlabel),
						 "Depth% 2d JoinQuals", depth);
				ExplainPropertyText(qlabel, temp, es);
			}
		}

		/*
		 * OtherQuals, if any
		 */
		if (other_quals)
		{
			temp = deparse_expression((Node *)other_quals, dcontext,
									  es->verbose, false);
			if (es->format == EXPLAIN_FORMAT_TEXT)
			{
				appendStringInfoSpaces(es->str, indent_width);
				appendStringInfo(es->str, "JoinFilter: %s\n", temp);
			}
			else
			{
				snprintf(qlabel, sizeof(qlabel), "Depth %02d-Filter", depth);
				ExplainPropertyText(qlabel, str.data, es);
			}
		}
		depth++;
	}
	/* other common field */
	pgstromExplainGpuTaskState(&gjs->gts, es);
}

/*
 * ExecGpuJoinEstimateDSM
 */
static Size
ExecGpuJoinEstimateDSM(CustomScanState *node,
					   ParallelContext *pcxt)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;

	return (MAXALIGN(offsetof(GpuJoinSharedState,
							  pergpu[numDevAttrs])) +
			MAXALIGN(offsetof(GpuJoinRuntimeStat,
							  jstat[gjs->num_rels + 1])) +
			pgstromSizeOfBrinIndexMap((GpuTaskState *) node) +
			pgstromEstimateDSMGpuTaskState((GpuTaskState *)node, pcxt));
}

/*
 * ExecGpuJoinInitDSM
 */
static void
ExecGpuJoinInitDSM(CustomScanState *node,
				   ParallelContext *pcxt,
				   void *coordinate)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;

	/* save the ParallelContext */
	gjs->gts.pcxt = pcxt;
	/* setup shared-state and runtime-statistics */
	createGpuJoinSharedState(gjs, pcxt, coordinate);
	on_dsm_detach(pcxt->seg,
				  cleanupGpuJoinSharedStateOnAbort,
				  PointerGetDatum(gjs->gj_sstate));
	on_dsm_detach(pcxt->seg,
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gjs->gts.gcontext));
	/* allocation of an empty multirel buffer */
	coordinate = (char *)coordinate + gjs->gj_sstate->ss_length;
	if (gjs->gts.outer_index_state)
	{
		gjs->gts.outer_index_map = (Bitmapset *)coordinate;
		gjs->gts.outer_index_map->nwords = -1;		/* uninitialized */
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gjs->gts));
	}
	pgstromInitDSMGpuTaskState(&gjs->gts, pcxt, coordinate);
}

/*
 * ExecGpuJoinInitWorker
 */
static void
ExecGpuJoinInitWorker(CustomScanState *node,
					  shm_toc *toc,
					  void *coordinate)
{
	GpuJoinState	   *gjs = (GpuJoinState *) node;
	GpuJoinSharedState *gj_sstate = (GpuJoinSharedState *) coordinate;

	gjs->gj_sstate = gj_sstate;
	/* ensure to stop workers prior to detach DSM */
	on_dsm_detach(dsm_find_mapping(gj_sstate->ss_handle),
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gjs->gts.gcontext));
	coordinate = (char *)coordinate + gj_sstate->ss_length;
	if (gjs->gts.outer_index_state)
	{
		gjs->gts.outer_index_map = (Bitmapset *)coordinate;
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gjs->gts));
	}
	pgstromInitWorkerGpuTaskState(&gjs->gts, coordinate);
}

/*
 * ExecGpuJoinReInitializeDSM
 */
static void
ExecGpuJoinReInitializeDSM(CustomScanState *node,
						   ParallelContext *pcxt, void *coordinate)
{
	pgstromReInitializeDSMGpuTaskState((GpuTaskState *) node);
}

/*
 * ExecShutdownGpuJoin
 *
 * DSM shall be released prior to Explain callback, so we have to save the
 * run-time statistics on the shutdown timing.
 */
static void
ExecShutdownGpuJoin(CustomScanState *node)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;
	GpuJoinSharedState *gj_sstate_old = gjs->gj_sstate;
	GpuJoinSharedState *gj_sstate_new;
	size_t			i, length;

	/*
	 * If this GpuJoin node is located under the inner side of another
	 * GpuJoin, it should not be called under the background worker
	 * context, however, ExecShutdown walks down the node.
	 */
	if (!gj_sstate_old)
		return;

	/* parallel worker put runtime-stat on ExecEnd handler */
	if (IsParallelWorker())
	{
		GpuJoinRuntimeStat *gj_rtstat = GPUJOIN_RUNTIME_STAT(gjs->gj_sstate);
		
		mergeGpuTaskRuntimeStatParallelWorker(&gjs->gts, &gj_rtstat->c);
	}
	else
	{
		EState	   *estate = gjs->gts.css.ss.ps.state;

		length = (MAXALIGN(offsetof(GpuJoinSharedState,
									pergpu[numDevAttrs])) +
				  MAXALIGN(offsetof(GpuJoinRuntimeStat,
									jstat[gjs->num_rels + 1])));
		gj_sstate_new = MemoryContextAlloc(estate->es_query_cxt, length);
		memcpy(gj_sstate_new, gj_sstate_old, length);
		/*
		 * Clear the ipc_mhandle and shmem_handle, not to release same
		 * resource twice or mode. If inner-side has siblings, shared-
		 * state shall be copied to local memory for each!
		 */
		gj_sstate_old->shmem_handle = UINT_MAX;
		for (i=0; i < numDevAttrs; i++)
		{
			gj_sstate_old->pergpu[i].bytesize = 0;
			memset(&gj_sstate_old->pergpu[i].ipc_mhandle,
				   0, sizeof(CUipcMemHandle));
		}
		gjs->gj_sstate = gj_sstate_new;
	}
}

/*
 * pgstrom_codegen_var_declarations
 *
 * declaration of the variables
 */
static void
pgstrom_codegen_var_declarations(StringInfo source,
								 int curr_depth,
								 List *kvars_list)								 
{
	StringInfoData	   *inners = alloca(sizeof(StringInfoData) * curr_depth);
	StringInfoData		base;
	StringInfoData		row;
	StringInfoData		arrow;
	StringInfoData		column;
	ListCell		   *lc;
	int					i;

	/* init */
	initStringInfo(&base);
	initStringInfo(&row);
	initStringInfo(&arrow);
	initStringInfo(&column);
	for (i=0; i < curr_depth; i++)
		initStringInfo(&inners[i]);

	/* code to init variables */
	foreach (lc, kvars_list)
	{
		Var		   *kvar = lfirst(lc);
		int			depth = kvar->varno;
		devtype_info *dtype;

		dtype = pgstrom_devtype_lookup(kvar->vartype);
		if (!dtype)
			elog(ERROR, "device type \"%s\" not found",
				 format_type_be(kvar->vartype));
		if (depth == 0)
		{
			/* RIGHT OUTER may have kds==NULL */
			if (base.len == 0)
				appendStringInfoString(
					&base,
					"  /* variable load in depth-0 (outer KDS) */\n"
					"  offset = (!o_buffer ? 0 : o_buffer[0]);\n"
					"  if (!kds)\n"
					"  {\n");
			appendStringInfo(
				&base,
				"    pg_datum_ref(kcxt,KVAR_%u,NULL); //pg_%s_t\n",
				kvar->varattnosyn,
				dtype->type_name);

			/* KDS_FORMAT_ARROW only if depth == 0 */
			if (arrow.len == 0)
				appendStringInfoString(
					&arrow,
					"  else if (kds->format == KDS_FORMAT_ARROW)\n"
					"  {\n");
			appendStringInfo(
				&arrow,
				"    if (offset > 0)\n"
				"      pg_datum_ref_arrow(kcxt,KVAR_%u,kds,%u,offset-1);\n"
				"    else\n"
				"      pg_datum_ref(kcxt,KVAR_%u,NULL);\n",
				kvar->varattnosyn,
				kvar->varattno - 1,
				kvar->varattnosyn);

			/* KDS_FORMAT_COLUMN only if depth == 0 */
			if (column.len == 0)
				appendStringInfoString(
					&column,
					"  else if (kds->format == KDS_FORMAT_COLUMN)\n"
					"  {\n");
			appendStringInfo(
				&column,
				"    if (offset == 0)\n"
				"      pg_datum_ref(kcxt,KVAR_%u,NULL);\n"
				"    else\n"
				"    {\n"
				"      datum = kern_get_datum_column(kds,extra,%u,offset-1);\n"
				"      pg_datum_ref(kcxt,KVAR_%u,datum);\n"
				"    }\n",
				kvar->varattnosyn,
				kvar->varattno-1, kvar->varattnosyn);

			/* KDS_FORMAT_ROW or KDS_FORMAT_BLOCK */
			if (row.len == 0)
				appendStringInfoString(
					&row,
					"  else\n"
					"  {\n"
					"    /* KDS_FORMAT_ROW or KDS_FORMAT_BLOCK */\n"
					"    if (offset == 0)\n"
					"      htup = NULL;\n"
					"    else if (kds->format == KDS_FORMAT_ROW)\n"
					"      htup = KDS_ROW_REF_HTUP(kds,offset,NULL,NULL);\n"
					"    else if (kds->format == KDS_FORMAT_BLOCK)\n"
					"      htup = KDS_BLOCK_REF_HTUP(kds,offset,NULL,NULL);\n"
					"    else\n"
					"      htup = NULL; /* bug */\n");
			appendStringInfo(
				&row,
				"    datum = GPUJOIN_REF_DATUM(kds->colmeta,htup,%u);\n"
				"    pg_datum_ref(kcxt,KVAR_%u,datum); //pg_%s_t\n",
				kvar->varattno-1,
				kvar->varattnosyn, dtype->type_name);
		}
		else if (depth < curr_depth)
		{
			StringInfo	decl = &inners[depth-1];

			if (decl->len == 0)
			{
				appendStringInfo(
					decl,
					"  /* variable load in depth-%u (inner KDS) */\n"
					"  {\n"
					"    kds_in = KERN_MULTIRELS_INNER_KDS(kmrels, %u);\n"
					"    if (!o_buffer)\n"
					"      htup = NULL;\n"
					"    else\n"
					"      htup = KDS_ROW_REF_HTUP(kds_in,o_buffer[%d],\n"
					"                              NULL, NULL);\n",
					depth,
					depth,
					depth);
			}
			appendStringInfo(
				decl,
				"    datum = GPUJOIN_REF_DATUM(kds_in->colmeta,htup,%u);\n"
				"    pg_datum_ref(kcxt,KVAR_%u,datum); //pg_%s_t\n",
				kvar->varattno - 1,
				kvar->varattnosyn,
				dtype->type_name);
		}
		else if (depth == curr_depth)
		{
			StringInfo	decl = &inners[depth-1];

			if (decl->len == 0)
			{
				appendStringInfo(
					decl,
					"  /* variable load in depth-%u (inner KDS) */\n"
					"  {\n"
					"    kds_in = KERN_MULTIRELS_INNER_KDS(kmrels, %u);\n",
					depth,
					depth);
			}
			appendStringInfo(
				decl,
				"    datum = GPUJOIN_REF_DATUM(kds_in->colmeta,i_htup,%u);\n"
				"    pg_datum_ref(kcxt,KVAR_%u,datum); //pg_%s_t\n",
				kvar->varattno - 1,
				kvar->varattnosyn,
				dtype->type_name);
		}
		else
		{
			elog(ERROR, "Bug? kernel Var-node is out of range: %s",
				 nodeToString(kvar));
		}
	}

	/* close the block */
	if (base.len > 0)
		appendStringInfo(source, "%s  }\n", base.data);
	if (arrow.len > 0)
		appendStringInfo(source, "%s  }\n", arrow.data);
	if (column.len > 0)
		appendStringInfo(source, "%s  }\n", column.data);
	if (row.len > 0)
		appendStringInfo(source, "%s  }\n", row.data);
	for (i=0; i < curr_depth; i++)
	{
		StringInfo	decl = &inners[i];
		if (decl->len > 0)
			appendStringInfo(source, "%s  }\n", decl->data);
		pfree(decl->data);
	}
	pfree(base.data);
	pfree(row.data);
	pfree(arrow.data);
	pfree(column.data);

	appendStringInfoChar(source, '\n');
}

/*
 * gpujoin_codegen_var_decl
 *
 * declaration of the variables in 'used_var' list
 */
static void
gpujoin_codegen_var_param_decl(StringInfo source,
							   GpuJoinInfo *gj_info,
							   int cur_depth,
							   codegen_context *context)
{
	List		   *kern_vars = NIL;
	ListCell	   *cell;
	devtype_info   *dtype;

	/*
	 * Pick up variables in-use and append its properties in the order
	 * corresponding to depth/resno.
	 */
	Assert(cur_depth > 0 && cur_depth <= gj_info->num_rels);
	foreach (cell, context->used_vars)
	{
		Var		   *varnode = lfirst(cell);
		Var		   *kernode = NULL;
		ListCell   *lc1;
		ListCell   *lc2;
		ListCell   *lc3;

		Assert(IsA(varnode, Var));
		/* GiST-index references shall be handled by the caller */
		if (varnode->varno == INDEX_VAR)
			continue;

		forthree (lc1, context->pseudo_tlist,
				  lc2, gj_info->ps_src_depth,
				  lc3, gj_info->ps_src_resno)
		{
			TargetEntry	*tle = lfirst(lc1);
			int		src_depth = lfirst_int(lc2);
			int		src_resno = lfirst_int(lc3);

			if (equal(tle->expr, varnode))
			{
				kernode = copyObject(varnode);
				kernode->varno = src_depth;			/* save the source depth */
				kernode->varattno = src_resno;		/* save the source resno */
				kernode->varattnosyn = tle->resno;	/* resno on the ps_tlist */
				if (src_depth < 0 || src_depth > cur_depth)
					elog(ERROR, "Bug? device varnode out of range");
				break;
			}
		}
		if (!kernode)
			elog(ERROR, "Bug? device varnode was not on the ps_tlist: %s",
				 nodeToString(varnode));
		kern_vars = lappend(kern_vars, kernode);
	}

	/*
	 * parameter declaration
	 */
	pgstrom_codegen_param_declarations(source, context);

	/*
	 * variable declarations
	 */
	appendStringInfoString(
		source,
		"  HeapTupleHeaderData *htup  __attribute__((unused));\n"
		"  kern_data_store *kds_in    __attribute__((unused));\n"
		"  void *datum                __attribute__((unused));\n"
		"  cl_uint offset             __attribute__((unused));\n");

	foreach (cell, kern_vars)
	{
		Var	   *kvar = lfirst(cell);

		dtype = pgstrom_devtype_lookup(kvar->vartype);
		if (!dtype)
			elog(ERROR, "device type \"%s\" not found",
				 format_type_be(kvar->vartype));
		appendStringInfo(
			source,
			"  pg_%s_t KVAR_%u;\n",
			dtype->type_name,
			kvar->varattnosyn);
	}
	appendStringInfoChar(source, '\n');
	pgstrom_codegen_var_declarations(source, cur_depth, kern_vars);
}

/*
 * codegen for:
 * STATIC_FUNCTION(cl_bool)
 * gpujoin_join_quals_depth%u(kern_context *kcxt,
 *                            kern_data_store *kds,
 *                            kern_data_extra *extra,
 *                            kern_multirels *kmrels,
 *                            cl_int *o_buffer,
 *                            HeapTupleHeaderData *i_htup,
 *                            cl_bool *joinquals_matched)
 */
static void
gpujoin_codegen_join_quals(StringInfo source,
						   GpuJoinInfo *gj_info,
						   GpuJoinInnerInfo *i_info,
						   codegen_context *context)
{
	List	   *join_quals = i_info->join_quals;
	List	   *other_quals = i_info->other_quals;
	char	   *join_quals_code = NULL;
	char	   *other_quals_code = NULL;

	Assert(i_info->depth > 0 && i_info->depth <= gj_info->num_rels);
	/*
	 * make a text representation of join_qual
	 */
	context->used_vars = NIL;
	context->param_refs = NULL;
	resetStringInfo(&context->decl_temp);
	if (join_quals != NIL)
		join_quals_code = pgstrom_codegen_expression((Node *)join_quals,
													 context);
	if (other_quals != NIL)
		other_quals_code = pgstrom_codegen_expression((Node *)other_quals,
													  context);
	/*
	 * function declaration
	 */
	appendStringInfo(
		source,
		"DEVICE_FUNCTION(cl_bool)\n"
		"gpujoin_join_quals_depth%d(kern_context *kcxt,\n"
		"                          kern_data_store *kds,\n"
		"                          kern_data_extra *extra,\n"
        "                          kern_multirels *kmrels,\n"
		"                          cl_uint *o_buffer,\n"
		"                          HeapTupleHeaderData *i_htup,\n"
		"                          cl_bool *joinquals_matched)\n"
		"{\n%s",
		i_info->depth, context->decl_temp.data);

	/*
	 * variable/params declaration & initialization
	 */
	gpujoin_codegen_var_param_decl(source, gj_info,
								   i_info->depth, context);

	/*
	 * evaluation of other-quals and join-quals
	 */
	if (join_quals_code != NULL)
	{
		appendStringInfo(
			source,
			"  if (i_htup && o_buffer && !EVAL(%s))\n"
			"  {\n"
			"    if (joinquals_matched)\n"
			"      *joinquals_matched = false;\n"
			"    return false;\n"
			"  }\n",
			join_quals_code);
	}
	appendStringInfo(
		source,
		"  if (joinquals_matched)\n"
		"    *joinquals_matched = true;\n");
	if (other_quals_code != NULL)
	{
		appendStringInfo(
			source,
			"  if (!EVAL(%s))\n"
			"    return false;\n",
			other_quals_code);
	}
	appendStringInfo(
		source,
		"  return true;\n"
		"}\n"
		"\n");
}

/*
 * codegen for:
 * STATIC_FUNCTION(cl_uint)
 * gpujoin_hash_value_depth%u(kern_context *kcxt,
 *                            kern_data_store *kds,
 *                            kern_data_extra *extra,
 *                            kern_multirels *kmrels,
 *                            cl_int *o_buffer,
 *                            cl_bool *is_null_keys)
 */
static void
gpujoin_codegen_hash_value(StringInfo source,
						   GpuJoinInfo *gj_info,
						   GpuJoinInnerInfo *i_info,
						   codegen_context *context)
{
	List		   *hash_outer_keys = i_info->hash_outer_keys;
	List		   *type_oid_list = NIL;
	ListCell	   *lc;
	StringInfoData	decl;
	StringInfoData	body;


	Assert(hash_outer_keys != NIL);
	initStringInfo(&decl);
	initStringInfo(&body);

	appendStringInfo(
		&decl,
		"  cl_uint hash = 0xffffffffU;\n"
		"  cl_bool is_null_keys = true;\n");

	context->used_vars = NIL;
	context->param_refs = NULL;
	resetStringInfo(&context->decl_temp);
	foreach (lc, hash_outer_keys)
	{
		Node	   *key_expr = lfirst(lc);
		Oid			key_type = exprType(key_expr);
		devtype_info *dtype;

		dtype = pgstrom_devtype_lookup(key_type);
		if (!dtype)
			elog(ERROR, "Bug? device type \"%s\" not found",
                 format_type_be(key_type));
		appendStringInfo(
			&body,
			"  temp.%s_v = %s;\n"
			"  if (!temp.%s_v.isnull)\n"
			"    is_null_keys = false;\n"
			"  hash ^= pg_comp_hash(kcxt, temp.%s_v);\n",
			dtype->type_name,
			pgstrom_codegen_expression(key_expr, context),
			dtype->type_name,
			dtype->type_name);
		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
	}

	/*
	 * variable/params declaration & initialization
	 */
	pgstrom_union_type_declarations(&decl, "temp", type_oid_list);
	gpujoin_codegen_var_param_decl(&decl, gj_info,
								   i_info->depth, context);
	appendStringInfo(
		source,
		"STATIC_FUNCTION(cl_uint)\n"
		"gpujoin_hash_value_depth%u(kern_context *kcxt,\n"
		"                          kern_data_store *kds,\n"
		"                          kern_data_extra *extra,\n"
		"                          kern_multirels *kmrels,\n"
		"                          cl_uint *o_buffer,\n"
		"                          cl_bool *p_is_null_keys)\n"
		"{\n"
		"%s%s%s"
		"  *p_is_null_keys = is_null_keys;\n"
		"  hash ^= 0xffffffff;\n"
		"  return hash;\n"
		"}\n"
		"\n",
		i_info->depth,
		decl.data,
		context->decl_temp.data,
		body.data);
	pfree(decl.data);
	pfree(body.data);
}

/*
 * gpujoin_codegen_gist_index_quals
 */
static void
gpujoin_codegen_gist_index_quals(StringInfo source,
								 PlannerInfo *root,
								 GpuJoinInfo *gj_info,
								 GpuJoinPath *gj_path,
								 int depth,
								 codegen_context *context)
{
	IndexOptInfo   *gist_index = gj_path->inners[depth-1].gist_index;
	List		   *gist_clauses = gj_path->inners[depth-1].gist_clauses;
	List		   *pseudo_tlist_saved = context->pseudo_tlist;
	List		   *pseudo_tlist = NIL;
	List		   *device_clauses;
	List		   *kvars_list = NIL;
	AttrNumber		indexcol = 0;
	devtype_info   *dtype;
	StringInfoData	body;
	StringInfoData	decl;
	StringInfoData	temp;
	StringInfoData	alias;
	StringInfoData	unalias;
	ListCell	   *cell;

	initStringInfo(&body);
	initStringInfo(&decl);
	initStringInfo(&temp);
	initStringInfo(&alias);
	initStringInfo(&unalias);

	device_clauses = (List *)
		fixup_gist_clause_for_device(root,
									 gist_index,
									 indexcol,
									 (Expr *)gist_clauses,
									 &pseudo_tlist);
	context->pseudo_tlist = pseudo_tlist;

	/*
	 * Build up the GpuJoinGiSTKeysDepth%u structure, and
	 * GiST key variables to be loaded.
	 */
	appendStringInfo(
		source,
		"/* ------------------------------------------------\n"
		" *\n"
		" * GiST-Index support routines (depth=%u)\n"
		" *\n"
		" * ------------------------------------------------ */\n"
		"typedef struct GpuJoinGiSTKeysDepth%u_s {\n",
		depth, depth);
	foreach (cell, pseudo_tlist)
	{
		TargetEntry *tle = lfirst(cell);
		Oid			type_oid;

		if (IsA(tle->expr, Var) && ((Var *)tle->expr)->varno == INDEX_VAR)
			continue;		/* skip references to index tuple */

		type_oid = exprType((Node *)tle->expr);
		dtype = pgstrom_devtype_lookup(type_oid);
		if (!dtype)
			elog(ERROR, "device type \"%s\" not found",
				 format_type_be(type_oid));
		if (!tle->resjunk)
		{
			appendStringInfo(
				source,
				"  pg_%s_t  __KVAR_%u;\n",
				dtype->type_name, tle->resno);
			appendStringInfo(
				&alias,
				"#define KVAR_%u ((keys)->__KVAR_%u)\n", tle->resno, tle->resno);
			appendStringInfo(
				&unalias,
				"#undef  KVAR_%u\n", tle->resno);

			context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
		}
		else
		{
			/* temporary variable for expression calculation */
			Assert(IsA(tle->expr, Var));
			appendStringInfo(
				&decl,
				"  pg_%s_t  KVAR_%u;\n",
				dtype->type_name, tle->resno);
		}

		if (IsA(tle->expr, Var))
		{
			Var		   *kvar = (Var *)tle->expr;
			Var		   *keynode = NULL;
			ListCell   *lc1, *lc2, *lc3;

			forthree (lc1, pseudo_tlist_saved,
					  lc2, gj_info->ps_src_depth,
					  lc3, gj_info->ps_src_resno)
			{
				TargetEntry *__tle = lfirst(lc1);
				int			src_depth = lfirst_int(lc2);
				int			src_resno = lfirst_int(lc3);

				if (equal(__tle->expr, kvar))
				{
					keynode = copyObject(kvar);
					keynode->varno = src_depth;
					keynode->varattno = src_resno;
					keynode->varattnosyn = tle->resno;
					if (src_depth < 0 || src_depth >= depth)
						elog(ERROR, "Bug? device varnode out of range");
					kvars_list = list_append_unique(kvars_list, keynode);
					break;
				}
			}
			if (!keynode)
				elog(ERROR, "Bug? device varnode was not on the ps_tlist: %s",
					 nodeToString(kvar));
		}
	}
	appendStringInfo(
		source,
		"} GpuJoinGiSTKeysDepth%u_t;\n"
		"%s\n",
		depth, alias.data);

	/*
	 * Function to load GiST key variables
	 */
	context->used_vars = NIL;
	context->param_refs = NULL;
	resetStringInfo(&context->decl_temp);

	pgstrom_codegen_var_declarations(&body, depth, kvars_list);
	/* expressions if any */
	foreach (cell, pseudo_tlist)
	{
		TargetEntry	*tle = lfirst(cell);
		char	   *code;

		if (tle->resjunk)
			continue;
		if (IsA(tle->expr, Var))
			continue;
		code = pgstrom_codegen_expression((Node *)tle->expr, context);
		appendStringInfo(
			&body,
			"  KVAR_%u = %s;\n",
			tle->resno, code);
	}
	pgstrom_codegen_param_declarations(&decl, context);

	appendStringInfo(
		source,
		"STATIC_FUNCTION(cl_bool)\n"
        "gpujoin_gist_load_keys_depth%d(kern_context *kcxt,\n"
        "                              kern_multirels *kmrels,\n"
        "                              kern_data_store *kds,\n"
        "                              kern_data_extra *extra,\n"
        "                              cl_uint *o_buffer,\n"
		"                              void *__keys)\n"
        "{\n"
		"  GpuJoinGiSTKeysDepth%u_t *keys = (GpuJoinGiSTKeysDepth%u_t *)__keys;\n"
        "  HeapTupleHeaderData *htup  __attribute__((unused));\n"
        "  kern_data_store *kds_in    __attribute__((unused));\n"
        "  void *datum                __attribute__((unused));\n"
        "  cl_uint offset             __attribute__((unused));\n"
		"%s\n%s"
		"  return (kcxt->errcode == ERRCODE_STROM_SUCCESS);\n"
		"}\n\n",
		depth,
		depth, depth,
		decl.data,
		body.data);

	/*
	 * Function to check GiST index quals
	 */
	resetStringInfo(&decl);
	resetStringInfo(&body);
	context->used_vars = NIL;
    context->param_refs = NULL;
    resetStringInfo(&context->decl_temp);

	foreach (cell, pseudo_tlist)
	{
		TargetEntry *tle = lfirst(cell);
		Var			*ivar = (Var *)tle->expr;

		if (tle->resjunk || !IsA(ivar, Var) || ivar->varno != INDEX_VAR)
			continue;
		dtype = pgstrom_devtype_lookup(ivar->vartype);
		if (!dtype)
			elog(ERROR, "device type \"%s\" not found",
				 format_type_be(ivar->vartype));
		appendStringInfo(
			&decl,
			"  pg_%s_t KVAR_%u;\n",
			dtype->type_name, tle->resno);
	}

	appendStringInfoString(
		&body,
		"  EXTRACT_INDEX_TUPLE_BEGIN(addr, kds_gist, itup);\n");
	for (indexcol=0; indexcol < gist_index->ncolumns; indexcol++)
	{
		foreach (cell, pseudo_tlist)
		{
			TargetEntry *tle = lfirst(cell);
			Var			*ivar = (Var *)tle->expr;

			if (!tle->resjunk &&
				IsA(ivar, Var) &&
				ivar->varno == INDEX_VAR &&
				ivar->varattno == indexcol+1)
			{
				appendStringInfo(
					&body,
					"%s"
					"  pg_datum_ref(kcxt,KVAR_%u,addr);\n",
					temp.data,
					tle->resno);
				resetStringInfo(&temp);
				break;
			}
		}
		appendStringInfoString(
			&temp,
			"  EXTRACT_INDEX_TUPLE_NEXT(addr, kds_gist);\n");
	}
	appendStringInfoString(
		&body,
		"  EXTRACT_INDEX_TUPLE_END();\n\n");

	/* fixup pseudo_tlist for expression */
	context->pseudo_tlist = NIL;
	foreach (cell, pseudo_tlist)
	{
		TargetEntry *tle = lfirst(cell);
		Var			*pvar = (Var *)tle->expr;

		if (!tle->resjunk &&
			(!IsA(pvar, Var) || pvar->varno != INDEX_VAR))
		{
			Var	   *var = makeVar(OUTER_VAR,
								  tle->resno,
								  exprType((Node *)tle->expr),
								  exprTypmod((Node *)tle->expr),
								  exprCollation((Node *)tle->expr), 0);
			tle = makeTargetEntry((Expr *)var, tle->resno, NULL, false);
		}
		context->pseudo_tlist = lappend(context->pseudo_tlist, tle);
	}

	foreach (cell, device_clauses)
	{
		Expr   *clause = lfirst(cell);

		appendStringInfo(
			&body,
			"  if (!EVAL(%s))\n"
			"    return false;\n",
			pgstrom_codegen_expression((Node *)clause, context));
	}
	pgstrom_codegen_param_declarations(&decl, context);
	
	appendStringInfo(
		source,
		"STATIC_FUNCTION(cl_bool)\n"
		"gpujoin_gist_index_quals_depth%u(kern_context *kcxt,\n"
		"                                kern_data_store *kds_gist,\n"
		"                                IndexTupleData *itup,\n"
		"                                void *__keys)\n"
		"{\n"
		"  GpuJoinGiSTKeysDepth%u_t *keys = (GpuJoinGiSTKeysDepth%u_t *)__keys;\n"
		"  char *addr;\n"
		"%s\n"
		"%s\n"
		"  return true;\n"
		"}\n",
		depth,
		depth, depth,
		decl.data,
		body.data);
	appendStringInfo(source, "%s\n", unalias.data);

	/* cleanup */
	pfree(decl.data);
	pfree(body.data);
	pfree(temp.data);
	pfree(alias.data);
	pfree(unalias.data);
	context->pseudo_tlist = pseudo_tlist_saved;
}

/*
 * gpujoin_codegen_projection
 *
 * It makes a device function for device projection.
 */
static void
gpujoin_codegen_projection(StringInfo source,
						   CustomScan *cscan,
						   GpuJoinInfo *gj_info,
						   codegen_context *context)
{
	List		   *tlist_dev = cscan->custom_scan_tlist;
	List		   *ps_src_depth = gj_info->ps_src_depth;
	List		   *ps_src_resno = gj_info->ps_src_resno;
	ListCell	   *lc1;
	ListCell	   *lc2;
	ListCell	   *lc3;
	AttrNumber	   *varattmaps;
	Bitmapset	   *refs_by_vars = NULL;
	Bitmapset	   *refs_by_expr = NULL;
	List		   *type_oid_list = NIL;
	devtype_info   *dtype;
	StringInfoData	decl;
	StringInfoData	body;
	StringInfoData	temp;
	StringInfoData	row;
	StringInfoData	arrow;
	StringInfoData	column;
	StringInfoData	outer;
	cl_int			nfields = list_length(tlist_dev);
	cl_int			depth;
	cl_bool			is_first;

	varattmaps = palloc(sizeof(AttrNumber) * list_length(tlist_dev));
	initStringInfo(&decl);
	initStringInfo(&body);
	initStringInfo(&temp);
	initStringInfo(&row);
	initStringInfo(&arrow);
	initStringInfo(&column);
	initStringInfo(&outer);

	context->used_vars = NIL;
	context->param_refs = NULL;
	resetStringInfo(&context->decl_temp);

	/* expand varlena_bufsz for tup_dclass/values/extra array */
	context->varlena_bufsz += (MAXALIGN(sizeof(cl_char) * nfields) +
							   MAXALIGN(sizeof(Datum)   * nfields) +
							   MAXALIGN(sizeof(cl_uint) * nfields));

	/*
	 * Pick up all the var-node referenced directly or indirectly by
	 * device expressions; which are resjunk==false.
	 */
	forthree (lc1, tlist_dev,
			  lc2, ps_src_depth,
			  lc3, ps_src_resno)
	{
		TargetEntry	*tle = lfirst(lc1);
		cl_int		src_depth = lfirst_int(lc2);

		if (tle->resjunk)
			continue;
		if (src_depth >= 0)
		{
			refs_by_vars = bms_add_member(refs_by_vars, tle->resno -
										  FirstLowInvalidHeapAttributeNumber);
		}
		else
		{
			List	   *expr_vars = pull_vars_of_level((Node *)tle->expr, 0);
			ListCell   *cell;

			foreach (cell, expr_vars)
			{
				TargetEntry	   *__tle = tlist_member(lfirst(cell), tlist_dev);

				if (!__tle)
					elog(ERROR, "Bug? no indirectly referenced Var-node exists in custom_scan_tlist");
				refs_by_expr = bms_add_member(refs_by_expr, __tle->resno -
										FirstLowInvalidHeapAttributeNumber);
			}
			list_free(expr_vars);
		}
	}

	appendStringInfoString(
		&body,
		"  if (tup_extras)\n"
		"    memset(tup_extras, 0, sizeof(cl_uint) * kds_dst->ncols);\n");

	for (depth=0; depth <= gj_info->num_rels; depth++)
	{
		List	   *kvars_srcnum = NIL;
		List	   *kvars_dstnum = NIL;
		const char *kds_label;
		cl_int		i, nattrs = -1;
		bool		sysattr_refs = false;

		resetStringInfo(&row);
		resetStringInfo(&arrow);
		resetStringInfo(&outer);

		/* collect information in this depth */
		memset(varattmaps, 0, sizeof(AttrNumber) * list_length(tlist_dev));

		forthree (lc1, tlist_dev,
				  lc2, ps_src_depth,
				  lc3, ps_src_resno)
		{
			TargetEntry *tle = lfirst(lc1);
			cl_int		src_depth = lfirst_int(lc2);
			cl_int		src_resno = lfirst_int(lc3);
			cl_int		k = tle->resno - FirstLowInvalidHeapAttributeNumber;

			if (depth != src_depth)
				continue;
			if (src_resno < 0)
			{
				if (depth != 0)
					elog(ERROR, "Bug? sysattr reference at inner table");
				sysattr_refs = true;
			}
			if (bms_is_member(k, refs_by_vars))
				varattmaps[tle->resno - 1] = src_resno;
			if (bms_is_member(k, refs_by_expr))
			{
				kvars_srcnum = lappend_int(kvars_srcnum, src_resno);
				kvars_dstnum = lappend_int(kvars_dstnum, tle->resno);
			}
			if (bms_is_member(k, refs_by_vars) ||
				bms_is_member(k, refs_by_expr))
				nattrs = Max(nattrs, src_resno);
		}

		/* no need to extract inner/outer tuple in this depth */
		if (nattrs < 1 && !sysattr_refs)
			continue;

		if (depth == 0)
			kds_label = "kds_src";
		else
			kds_label = "kds_in";

		/* System column reference if any */
		foreach (lc1, tlist_dev)
		{
			TargetEntry		   *tle = lfirst(lc1);
			const FormData_pg_attribute *attr;

			if (varattmaps[tle->resno-1] >= 0)
				continue;
			attr = SystemAttributeDefinition(varattmaps[tle->resno-1]);
			/* row or block */
			appendStringInfo(
				&row,
				"  sz = pg_sysattr_%s_store(kcxt,%s,htup,&t_self,\n"
				"                           tup_dclass[%d],\n"
				"                           tup_values[%d]);\n"
				"  if (tup_extras)\n"
				"    tup_extras[%d] = sz;\n",
				NameStr(attr->attname),
				kds_label,
				tle->resno - 1,
				tle->resno - 1,
				tle->resno - 1);
			/* arrow */
			appendStringInfo(
				&arrow,
				"    sz = pg_sysattr_%s_fetch_arrow(kcxt,(offset==0 ? NULL : %s),\n"
				"                                   offset-1,\n"
				"                                   tup_dclass[%d],\n"
				"                                   tup_values[%d]);\n"
				"    if (tup_extras)\n"
				"      tup_extras[%d] = sz;\n",
				NameStr(attr->attname),
				kds_label,
				tle->resno - 1,
				tle->resno - 1,
				tle->resno - 1);
			/* column */
			appendStringInfo(
				&column,
				"    sz = pg_sysattr_%s_fetch_column(kcxt,(offset==0 ? NULL : %s),\n"
				"                                    offset-1,\n"
				"                                    tup_dclass[%d],\n"
				"                                    tup_values[%d]);\n"
				"    if (tup_extras)\n"
				"      tup_extras[%d] = sz;\n",
				NameStr(attr->attname),
				kds_label,
				tle->resno - 1,
				tle->resno - 1,
				tle->resno - 1);
			/* NULL-initialization for LEFT OUTER JOIN */
			appendStringInfo(
				&outer,
				"  tup_dclass[%d] = DATUM_CLASS__NULL;\n",
				tle->resno - 1);
		}
		/* begin to walk on the tuple */
		if (nattrs > 0)
			appendStringInfo(
				&row,
				"    EXTRACT_HEAP_TUPLE_BEGIN(addr,%s,htup);\n",
				kds_label);
		resetStringInfo(&temp);
		for (i=1; i <= nattrs; i++)
		{
			TargetEntry	   *tle;
			Oid				type_oid;
			int16			typelen;
			bool			typebyval;
			cl_bool			referenced = false;

			foreach (lc1, tlist_dev)
			{
				tle = lfirst(lc1);

				if (varattmaps[tle->resno - 1] != i)
					continue;
				/*
				 * attributes can be directly copied regardless of device-
				 * type support (if row format).
				 */
				type_oid = exprType((Node *)tle->expr);
				get_typlenbyval(type_oid, &typelen, &typebyval);
				dtype = pgstrom_devtype_lookup_and_track(type_oid, context);
				if (dtype)
					type_oid_list = list_append_unique_oid(type_oid_list,
														   dtype->type_oid);
				/* row */
				appendStringInfo(
					&temp,
					"  EXTRACT_HEAP_%s(addr,tup_dclass[%d],tup_values[%d]);\n",
					(!typebyval   ? "READ_POINTER" :
					 typelen == 1 ? "READ_8BIT"    :
					 typelen == 2 ? "READ_16BIT"   :
					 typelen == 4 ? "READ_32BIT"   :
					 typelen == 8 ? "READ_64BIT"   : "__invalid_typlen__"),
					tle->resno - 1,
					tle->resno - 1);
				/* arrow */
				if (!dtype)
				{
					appendStringInfo(
						&arrow,
						"    tup_dclass[%d] = DATUM_CLASS__NULL;\n",
						tle->resno - 1);
				}
				else
				{
					if (!referenced)
						appendStringInfo(
							&arrow,
							"    if (r_idx == 0)\n"
							"      pg_datum_ref(kcxt,temp.%s_v,NULL);\n"
							"    else\n"
							"      pg_datum_ref_arrow(kcxt,temp.%s_v,%s,%d,r_idx-1);\n",
							dtype->type_name,
							dtype->type_name, kds_label, i-1);
					appendStringInfo(
						&arrow,
						"    sz = pg_datum_store(kcxt, temp.%s_v,\n"
						"                        tup_dclass[%d],\n"
						"                        tup_values[%d]);\n"
						"    if (tup_extras)\n"
						"      tup_extras[%d] = sz;\n"
						"    extra_sum += MAXALIGN(sz);\n",
						dtype->type_name,
						tle->resno - 1,
						tle->resno - 1,
						tle->resno - 1);
					context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
					type_oid_list = list_append_unique_oid(type_oid_list,
														   dtype->type_oid);
				}
				/* column */
				if (!referenced)
					appendStringInfo(
						&column,
						"    if (r_idx == 0)\n"
						"      addr = NULL;\n"
						"    else\n"
						"      addr = kern_get_datum_column(%s,kds_extra,%d,r_idx-1);\n",
						kds_label, i-1);
				appendStringInfo(
					&column,
					"    if (!addr)\n"
					"      tup_dclass[%d] = DATUM_CLASS__NULL;\n"
					"    else\n"
					"    {\n"
					"      tup_dclass[%d] = DATUM_CLASS__NORMAL;\n"
					"      tup_values[%d] = %s(addr);\n"
					"    }\n",
					tle->resno-1,
					tle->resno-1,
					tle->resno-1,
					(!typebyval ? "PointerGetDatum" :
					 typelen == 1 ? "READ_INT8_PTR"  :
					 typelen == 2 ? "READ_INT16_PTR" :
					 typelen == 4 ? "READ_INT32_PTR" :
					 typelen == 8 ? "READ_INT64_PTR" : "__invalid_typlen__"));
				/* NULL-initialization for LEFT OUTER JOIN */
				appendStringInfo(
					&outer,
					"    tup_dclass[%d] = DATUM_CLASS__NULL;\n",
					tle->resno - 1);

				referenced = true;
			}

			forboth (lc1, kvars_srcnum,
					 lc2, kvars_dstnum)
			{
				devtype_info   *dtype;
				cl_int			src_num = lfirst_int(lc1);
				cl_int			dst_num = lfirst_int(lc2);
				Oid				type_oid;

				if (src_num != i)
					continue;
				/* add KVAR_%u declarations */
				tle = list_nth(tlist_dev, dst_num - 1);
				type_oid = exprType((Node *)tle->expr);
				dtype = pgstrom_devtype_lookup(type_oid);
				if (!dtype)
					elog(ERROR, "cache lookup failed for device type: %s",
						 format_type_be(type_oid));
				type_oid_list = list_append_unique_oid(type_oid_list, type_oid);

				/* row */
				appendStringInfo(
					&decl,
					"  pg_%s_t KVAR_%u;\n",
					dtype->type_name,
					dst_num);
				appendStringInfo(
					&temp,
					"    pg_datum_ref(kcxt, KVAR_%u, addr);\n", dst_num);
				/* arrow */
				if (!referenced)
					appendStringInfo(
						&arrow,
						"    if (r_idx == 0)\n"
						"      pg_datum_ref(kcxt,temp.%s_v,NULL);\n"
						"    else\n"
						"      pg_datum_ref_arrow(kcxt,temp.%s_v,%s,%d,r_idx-1);\n",
						dtype->type_name,
						dtype->type_name, kds_label, i-1);
				appendStringInfo(
					&arrow,
					"    KVAR_%u = temp.%s_v;\n",
					dst_num, dtype->type_name);
				/* column */
				if (!referenced)
					appendStringInfo(
						&column,
						"    if (r_idx == 0)\n"
						"      addr = NULL;\n"
						"    else\n"
						"      addr = kern_get_datum_column(%s,kds_extra,%d,r_idx-1);\n",
						kds_label, i-1);
				appendStringInfo(
					&column,
					"    pg_datum_ref(kcxt, KVAR_%u, addr);\n", dst_num);

				referenced = true;
			}

			/* flush to the main buffer */
			if (referenced)
			{
				appendStringInfoString(&row, temp.data);
				resetStringInfo(&temp);
			}
			appendStringInfo(
				&temp,
				"    EXTRACT_HEAP_TUPLE_NEXT(addr,%s);\n", kds_label);
		}
		if (nattrs > 0)
			appendStringInfoString(
				&row,
				"    EXTRACT_HEAP_TUPLE_END();\n");

		if (depth == 0)
		{
			appendStringInfo(
				&body,
				"  /* ------ extract outer relation ------ */\n"
				"  if (!kds_src)\n"
				"  {\n"
				"%s"
				"  }\n"
				"  else if (kds_src->format == KDS_FORMAT_ROW ||\n"
				"           kds_src->format == KDS_FORMAT_BLOCK)\n"
				"  {\n"
				"    offset = r_buffer[0];\n"
				"    if (offset == 0)\n"
				"      htup = NULL;\n"
				"    else if (kds_src->format == KDS_FORMAT_ROW)\n"
				"      htup = KDS_ROW_REF_HTUP(kds_src,offset,&t_self,NULL);\n"
				"    else\n"
				"      htup = KDS_BLOCK_REF_HTUP(kds_src,offset,&t_self,NULL);\n"
				"%s"
				"  }\n"
				"  else if (kds_src->format == KDS_FORMAT_ARROW)\n\n"
				"  {\n"
				"    cl_uint r_idx = r_buffer[0];\n"
				"%s"
				"  }\n"
				"  else if (kds_src->format == KDS_FORMAT_COLUMN)\n"
				"  {\n"
				"    cl_uint r_idx = r_buffer[0];\n"
				"%s"
				"  }\n",
				outer.data,
				row.data,
				arrow.data,
				column.data);
		}
		else
		{
			appendStringInfo(
				&body,
				"  /* ---- extract inner relation (depth=%d) */\n"
				"  kds_in = KERN_MULTIRELS_INNER_KDS(kmrels, %d);\n"
				"  assert(kds_in->format == KDS_FORMAT_ROW ||\n"
				"         kds_in->format == KDS_FORMAT_HASH);\n"
				"  offset = r_buffer[%d];\n"
				"  if (offset == 0)\n"
				"  {\n"
				"%s"
				"  }\n"
				"  else\n"
				"  {\n"
				"    htup = KDS_ROW_REF_HTUP(kds_in,offset,&t_self,NULL);\n"
				"%s"
				"  }\n",
				depth, depth, depth,
				outer.data,
				row.data);
		}
	}

	/*
	 * Execution of the expression
	 */
	is_first = true;
	forboth (lc1, tlist_dev,
			 lc2, ps_src_depth)
	{
		TargetEntry	   *tle = lfirst(lc1);
		cl_int			src_depth = lfirst_int(lc2);
		devtype_info   *dtype;

		if (tle->resjunk || src_depth >= 0)
			continue;

		if (is_first)
		{
			appendStringInfoString(
				&body,
				"\n"
				"  /* calculation of expressions */\n");
			is_first = false;
		}

		dtype = pgstrom_devtype_lookup(exprType((Node *) tle->expr));
		if (!dtype)
			elog(ERROR, "cache lookup failed for device type: %s",
				 format_type_be(exprType((Node *) tle->expr)));
		appendStringInfo(
			&body,
			"  temp.%s_v = %s;\n"
			"  sz = pg_datum_store(kcxt, temp.%s_v,\n"
			"                      tup_dclass[%d],\n"
			"                      tup_values[%d]);\n"
			"  if (tup_extras)\n"
			"    tup_extras[%d] = sz;\n"
			"  extra_sum += MAXALIGN(sz);\n\n",
			dtype->type_name,
			pgstrom_codegen_expression((Node *)tle->expr, context),
			dtype->type_name,
			tle->resno - 1,
			tle->resno - 1,
			tle->resno - 1);
		context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
	}
	/* add const/param and temporary declarations */
	pgstrom_codegen_param_declarations(&decl, context);
	pgstrom_union_type_declarations(&decl, "temp", type_oid_list);
	/* merge declarations and function body */
	appendStringInfo(
		source,
		"DEVICE_FUNCTION(cl_uint)\n"
		"gpujoin_projection(kern_context *kcxt,\n"
		"                   kern_data_store *kds_src,\n"
		"                   kern_data_extra *kds_extra,\n"
		"                   kern_multirels *kmrels,\n"
		"                   cl_uint *r_buffer,\n"
		"                   kern_data_store *kds_dst,\n"
		"                   cl_char *tup_dclass,\n"
		"                   Datum   *tup_values,\n"
		"                   cl_uint *tup_extras)\n"
		"{\n"
		"  HeapTupleHeaderData *htup    __attribute__((unused));\n"
		"  kern_data_store *kds_in      __attribute__((unused));\n"
		"  ItemPointerData  t_self      __attribute__((unused));\n"
		"  cl_uint          offset      __attribute__((unused));\n"
		"  cl_uint          sz          __attribute__((unused));\n"
		"  cl_uint          extra_sum = 0;\n"
		"  void            *addr        __attribute__((unused)) = NULL;\n"
		"%s%s\n%s"
		"  return extra_sum;\n"
		"}\n",
		decl.data, context->decl_temp.data,
		body.data);

	pfree(decl.data);
	pfree(body.data);
	pfree(temp.data);
	pfree(row.data);
	pfree(arrow.data);
}

static char *
gpujoin_codegen(PlannerInfo *root,
				CustomScan *cscan,
				GpuJoinPath *gj_path,
				GpuJoinInfo *gj_info,
				List *tlist,
				codegen_context *context)
{
	StringInfoData source;
	StringInfoData temp;
	int			depth;
	size_t		sz, off;
	size_t		varlena_bufsz;
	ListCell   *cell;
	gpujoinPseudoStack *pstack;

	initStringInfo(&source);
	initStringInfo(&temp);

	/*
	 * System constants of GpuJoin
	 * KPARAM_0 is gpujoinPseudoStack, to indicate pseudo-stack offset
	 * for each depth, per SM.
	 */
	sz = offsetof(gpujoinPseudoStack,
				  ps_offset[gj_path->num_rels + 1]);
	pstack = palloc0(sz);
	SET_VARSIZE(pstack, sz);
	for (depth=0, off=0; depth <= gj_path->num_rels; depth++)
	{
		sz = sizeof(cl_uint) * (depth+1) * GPUJOIN_PSEUDO_STACK_NROOMS;
		pstack->ps_offset[depth] = off;
		off += sz;
		/* GiST-index support needs extra pseudo-stack */
		if (depth > 0 && gj_path->inners[depth-1].gist_clauses)
			off += sz;
	}
	pstack->ps_unitsz = off;

	context->used_params = list_make1(makeConst(BYTEAOID,
												-1,
												InvalidOid,
												-1,
												PointerGetDatum(pstack),
												false,
												false));
	/*
	 * gpuscan_quals_eval
	 */
	codegen_gpuscan_quals(&source,
						  context,
						  "gpujoin",
						  cscan->scan.scanrelid,
						  gj_info->outer_quals);
	varlena_bufsz = context->varlena_bufsz;

	/*
	 * gpujoin_join_quals
	 */
	context->pseudo_tlist = cscan->custom_scan_tlist;
	foreach (cell, gj_info->inner_infos)
	{
		GpuJoinInnerInfo *i_info = lfirst(cell);

		context->varlena_bufsz = 0;
		gpujoin_codegen_join_quals(&source, gj_info, i_info, context);
		varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);
	}

	appendStringInfo(
		&source,
		"DEVICE_FUNCTION(cl_bool)\n"
		"gpujoin_join_quals(kern_context *kcxt,\n"
		"                   kern_data_store *kds,\n"
		"                   kern_data_extra *extra,\n"
		"                   kern_multirels *kmrels,\n"
		"                   int depth,\n"
		"                   cl_uint *o_buffer,\n"
		"                   HeapTupleHeaderData *i_htup,\n"
		"                   cl_bool *needs_outer_row)\n"
		"{\n"
		"  switch (depth)\n"
		"  {\n");

	for (depth=1; depth <= gj_info->num_rels; depth++)
	{
		appendStringInfo(
			&source,
			"  case %d:\n"
			"    return gpujoin_join_quals_depth%d(kcxt, kds, extra, kmrels,\n"
			"                                     o_buffer, i_htup,\n"
			"                                     needs_outer_row);\n",
			depth, depth);
	}
	appendStringInfo(
		&source,
		"  default:\n"
		"    STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,\n"
		"                  \"GpuJoin: wrong code generation\");\n"
		"    break;\n"
		"  }\n"
		"  return false;\n"
		"}\n\n");

	/*
	 * gpujoin_hash_value
	 */
	foreach (cell, gj_info->inner_infos)
	{
		GpuJoinInnerInfo *i_info = lfirst(cell);

		if (i_info->hash_outer_keys)
		{
			context->varlena_bufsz = 0;
			gpujoin_codegen_hash_value(&source, gj_info, i_info, context);
			varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);
		}
	}

	appendStringInfo(
		&source,
		"DEVICE_FUNCTION(cl_uint)\n"
		"gpujoin_hash_value(kern_context *kcxt,\n"
		"                   kern_data_store *kds,\n"
		"                   kern_data_extra *extra,\n"
		"                   kern_multirels *kmrels,\n"
		"                   cl_int depth,\n"
		"                   cl_uint *o_buffer,\n"
		"                   cl_bool *is_null_keys)\n"
		"{\n"
		"  switch (depth)\n"
		"  {\n");

	foreach (cell, gj_info->inner_infos)
	{
		GpuJoinInnerInfo *i_info = lfirst(cell);

		if (i_info->hash_outer_keys)
		{
			appendStringInfo(
				&source,
				"  case %u:\n"
				"    return gpujoin_hash_value_depth%u(kcxt,kds,extra,kmrels,\n"
				"                                      o_buffer,is_null_keys);\n",
				i_info->depth,
				i_info->depth);
		}
	}
	appendStringInfo(
		&source,
		"  default:\n"
		"    STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,\n"
		"                  \"GpuJoin: wrong code generation\");\n"
		"    break;\n"
		"  }\n"
		"  return (cl_uint)(-1);\n"
		"}\n"
		"\n");

	/*
	 * gpujoin_gist_load_keys / gpujoin_gist_check_quals
	 */
	for (depth=0; depth < gj_path->num_rels; depth++)
	{
		if (!gj_path->inners[depth].gist_index)
			continue;
		context->varlena_bufsz = 0;
		gpujoin_codegen_gist_index_quals(&source,
										 root,
										 gj_info,
										 gj_path,
										 depth+1,
										 context);
		varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);
	}

	appendStringInfoString(
		 &source,
		 "DEVICE_FUNCTION(void *)\n"
		 "gpujoin_gist_load_keys(kern_context *kcxt,\n"
		 "                       kern_multirels *kmrels,\n"
		 "                       kern_data_store *kds,\n"
		 "                       kern_data_extra *extra,\n"
		 "                       cl_int depth,\n"
		 "                       cl_uint *o_buffer)\n"
		 "{\n");
	for (depth=0; depth < gj_path->num_rels; depth++)
	{
		if (!gj_path->inners[depth].gist_index)
			continue;
		appendStringInfo(
			&source,
			"  if (depth == %u)\n"
			"  {\n"
			"    void *__gist_keys\n"
			"      = kern_context_alloc(kcxt, sizeof(GpuJoinGiSTKeysDepth%u_t));\n"
			"    if (!__gist_keys)\n"
			"      STROM_EREPORT(kcxt, ERRCODE_OUT_OF_MEMORY,\"out of memory\");\n"
			"    else if (gpujoin_gist_load_keys_depth%u(kcxt,\n"
			"                                         kmrels,\n"
			"                                         kds, extra,\n"
			"                                         o_buffer,\n"
			"                                         __gist_keys))\n"
			"      return __gist_keys;\n"
			"    return (void *)(~0UL);\n"
			"  }\n",
			depth+1, depth+1, depth+1);
	}
	appendStringInfoString(
		&source,
		"  STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,\n"
		"                \"GpuJoin: wrong code generation\");\n"
		"  return (void *)(~0UL);\n"
		"}\n\n");

	appendStringInfoString(
		&source,
		"DEVICE_FUNCTION(cl_bool)\n"
		"gpujoin_gist_index_quals(kern_context *kcxt,\n"
		"                         cl_int depth,\n"
		"                         kern_data_store *kds_gist,\n"
		"                         IndexTupleData *itup,\n"
		"                         void *gist_keys)\n"
		"{\n");
	for (depth=0; depth < gj_path->num_rels; depth++)
	{
		if (!gj_path->inners[depth].gist_index)
			continue;
		appendStringInfo(
			&source,
			"  if (depth == %u)\n"
			"    return gpujoin_gist_index_quals_depth%u(kcxt,\n"
			"                                          kds_gist,\n"
			"                                          itup,\n"
			"                                          gist_keys);\n",
			depth+1, depth+1);
	}
	appendStringInfoString(
		&source,
		"  STROM_EREPORT(kcxt, ERRCODE_STROM_WRONG_CODE_GENERATION,\n"
		"                \"GpuJoin: wrong code generation\");\n"
		"  return false;\n"
		"}\n\n");

	/*
	 * gpujoin_projection
	 */
	context->varlena_bufsz = 0;
	gpujoin_codegen_projection(&source, cscan, gj_info, context);
	varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);

	/* required varlena buffer size */
	gj_info->varlena_bufsz = varlena_bufsz;

	return source.data;
}

/*
 * GpuJoinSetupTask
 */
Size
GpuJoinSetupTask(struct kern_gpujoin *kgjoin, GpuTaskState *gts,
				 pgstrom_data_store *pds_src)
{
	GpuJoinState *gjs = (GpuJoinState *) gts;
	GpuContext *gcontext = gjs->gts.gcontext;
	cl_int		nrels = gjs->num_rels;
	size_t		head_sz;
	size_t		param_sz;
	size_t		suspend_sz;
	int			mp_count;
	gpujoinPseudoStack *pstack;

	mp_count = (GPUKERNEL_MAX_SM_MULTIPLICITY *
				devAttrs[gcontext->cuda_dindex].MULTIPROCESSOR_COUNT);
	head_sz = STROMALIGN(offsetof(kern_gpujoin, stat[gjs->num_rels+1]));
	param_sz = STROMALIGN(gjs->gts.kern_params->length);
	pstack = (gpujoinPseudoStack *)kparam_get_value(gjs->gts.kern_params, 0);
	suspend_sz = MAXALIGN(offsetof(gpujoinSuspendContext, pd[nrels + 1]));
	if (kgjoin)
	{
		memset(kgjoin, 0, head_sz);
		kgjoin->kparams_offset	= head_sz;
		kgjoin->pstack_offset	= head_sz + param_sz;
		kgjoin->suspend_offset	= head_sz + param_sz + mp_count * pstack->ps_unitsz;
		kgjoin->suspend_size	= mp_count * suspend_sz;
		kgjoin->num_rels		= gjs->num_rels;
		kgjoin->src_read_pos	= 0;

		/* kern_parambuf */
		memcpy(KERN_GPUJOIN_PARAMBUF(kgjoin),
			   gjs->gts.kern_params,
			   gjs->gts.kern_params->length);
	}
	return (head_sz + param_sz +
			mp_count * pstack->ps_unitsz +
			mp_count * suspend_sz);
}

/*
 * gpujoin_create_task
 */
static GpuTask *
gpujoin_create_task(GpuJoinState *gjs,
					pgstrom_data_store *pds_src,
					int outer_depth)
{
	TupleTableSlot *scan_slot = gjs->gts.css.ss.ss_ScanTupleSlot;
	TupleDesc		scan_tupdesc = scan_slot->tts_tupleDescriptor;
	GpuContext	   *gcontext = gjs->gts.gcontext;
	GpuJoinTask	   *pgjoin;
	Size			required;
	CUdeviceptr		m_deviceptr;
	CUresult		rc;

	Assert(pds_src || (outer_depth > 0 && outer_depth <= gjs->num_rels));

	required = GpuJoinSetupTask(NULL, &gjs->gts, pds_src);
	rc = gpuMemAllocManaged(gcontext,
							&m_deviceptr,
							offsetof(GpuJoinTask,
									 kern) + required,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on gpuMemAllocManaged: %s", errorText(rc));
	pgjoin = (GpuJoinTask *)m_deviceptr;

	memset(pgjoin, 0, offsetof(GpuJoinTask, kern));
	pgstromInitGpuTask(&gjs->gts, &pgjoin->task);
	pgjoin->pds_src = pds_src;
	pgjoin->pds_dst = PDS_create_row(gcontext,
									 scan_tupdesc,
									 pgstrom_chunk_size());
	pgjoin->outer_depth = outer_depth;

	/* Is NVMe-Strom available to run this GpuJoin? */
	if (pds_src && ((pds_src->kds.format == KDS_FORMAT_BLOCK &&
					 pds_src->nblocks_uncached > 0) ||
					(pds_src->kds.format == KDS_FORMAT_ARROW &&
					 pds_src->iovec != NULL)))
	{
		pgjoin->with_nvme_strom = true;
	}
	GpuJoinSetupTask(&pgjoin->kern, &gjs->gts, pds_src);

	return &pgjoin->task;
}

/*
 * gpujoinExecOuterScanChunk
 */
pgstrom_data_store *
GpuJoinExecOuterScanChunk(GpuTaskState *gts)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	pgstrom_data_store *pds = NULL;

	if (gjs->gts.css.ss.ss_currentRelation)
	{
		if (gjs->gts.af_state)
			pds = ExecScanChunkArrowFdw(gts);
		else if (gjs->gts.gs_state)
			pds = ExecScanChunkGpuStore(gts);
		else
			pds = pgstromExecScanChunk(gts);
	}
	else
	{
		PlanState	   *outer_node = outerPlanState(gjs);
		TupleTableSlot *slot;

		for (;;)
		{
			if (gjs->gts.scan_overflow)
			{
				if (gjs->gts.scan_overflow == (void *)(~0UL))
					break;
				slot = gjs->gts.scan_overflow;
				gjs->gts.scan_overflow = NULL;
			}
			else
			{
				slot = ExecProcNode(outer_node);
				if (TupIsNull(slot))
				{
					/*
					 * FIXME: Why not just scan_done = true here?
					 */
					gjs->gts.scan_overflow = (void *)(~0UL);
					break;
				}
			}

			/* creation of a new data-store on demand */
			if (!pds)
			{
				pds = PDS_create_row(gjs->gts.gcontext,
									 ExecGetResultType(outer_node),
									 pgstrom_chunk_size());
			}
			/* insert the tuple on the data-store */
			if (!PDS_insert_tuple(pds, slot))
			{
				gjs->gts.scan_overflow = slot;
				break;
			}
		}
	}
	return pds;
}

/*
 * gpujoin_switch_task
 */
static void
gpujoin_switch_task(GpuTaskState *gts, GpuTask *gtask)
{
}

/*
 * gpujoin_next_task
 */
static GpuTask *
gpujoin_next_task(GpuTaskState *gts)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	GpuTask		   *gtask = NULL;
	pgstrom_data_store *pds;

	if (gjs->gts.af_state)
		pds = ExecScanChunkArrowFdw(gts);
	else if (gjs->gts.gs_state)
		pds = ExecScanChunkGpuStore(gts);
	else
		pds = GpuJoinExecOuterScanChunk(gts);
	if (pds)
		gtask = gpujoin_create_task(gjs, pds, -1);
	else
		pg_atomic_write_u32(&gjs->gj_sstate->outer_scan_done, 1);

	return gtask;
}

/*
 * gpujoinNextRightOuterJoinIfAny
 */
int
gpujoinNextRightOuterJoinIfAny(GpuTaskState *gts)
{
	GpuJoinState   *gjs = (GpuJoinState *)gts;
	GpuJoinSharedState *gj_sstate = gjs->gj_sstate;
	GpuContext	   *gcontext = gjs->gts.gcontext;
	kern_multirels *h_kmrels = gjs->h_kmrels;
	int				i, dindex = gcontext->cuda_dindex;
	int				depth = -1;
	uint32			needs_colocation;

	if (gjs->sibling)
	{
		GpuJoinSiblingState *sibling = gjs->sibling;

		if (++sibling->nr_processed < sibling->nr_siblings)
			return -1;
		gj_sstate = sibling->leader->gj_sstate;
	}
	
	SpinLockAcquire(&gj_sstate->mutex);
	Assert(gj_sstate->phase == INNER_PHASE__GPUJOIN_EXEC);
	Assert(h_kmrels != NULL);

	if (h_kmrels->ojmaps_length == 0)
	{
		/*
		 * This GpuJoin has no RIGHT/FULL OUTER JOIN.
		 * So, we need to do nothing special at the end.
		 */
		gj_sstate->pergpu[dindex].nr_workers_gpujoin--;
		goto out_unlock;
	}

	/*
	 * Now we don't support RIGHT/FULL OUTER JOIN with asymmetric
	 * partition-wise JOIN
	 */
	Assert(!gjs->sibling);

	/*
	 * This context is not the last one to process this GpuJoin
	 * at the current GPU device. Likely, other backend/workers
	 * that shares same GPU shall handle RIGHT/FULL OUTER JOIN.
	 */
	if (gj_sstate->pergpu[dindex].nr_workers_gpujoin > 1)
	{
		gj_sstate->pergpu[dindex].nr_workers_gpujoin--;
		goto out_unlock;
	}

	/*
	 * In case when RIGHT/FULL OUTER JOIN was processed on multiple
	 * GPU devices, or CPU fallback happen, we must collocate the
	 * outer-join-map once.
	 */
	needs_colocation = pg_atomic_read_u32(&gj_sstate->needs_colocation);
	if (needs_colocation > 1)
		gpujoinColocateOuterJoinMapsToHost(gjs);

	/*
	 * If this process is exactly the last player for the RIGHT/FULL
	 * OUTER JOIN, we suggest to kick GpuJoin kernel with NULL outer
	 * buffer from a particular depth.
	 */
	Assert(gj_sstate->pergpu[dindex].nr_workers_gpujoin == 1);
	for (i=0; i < numDevAttrs; i++)
	{
		if (i == dindex)
			continue;
		if (gj_sstate->pergpu[i].nr_workers_gpujoin > 0)
			break;
	}
	if (i >= numDevAttrs)
	{
		int		__depth;

		for (__depth = Max(gj_sstate->curr_outer_depth + 1, 1);
			 __depth <= gjs->num_rels;
			 __depth++)
		{
			if (h_kmrels->chunks[__depth - 1].right_outer)
			{
				depth = __depth;
				gj_sstate->curr_outer_depth = depth;
				break;
			}
		}
		/*
		 * Once colocation happened, outer-join-map at the GPU device
		 * memory is not latest. So, refresh it.
		 */
		if (depth >= 0 && needs_colocation > 1)
		{
			size_t		offset = h_kmrels->kmrels_length;
			size_t		length = MAXALIGN(h_kmrels->ojmaps_length);
			CUresult	rc;

			rc = cuMemcpyHtoD(gjs->m_kmrels + offset,
							  (char *)h_kmrels + offset,
							  length);
			if (rc != CUDA_SUCCESS)
			{
				 SpinLockRelease(&gj_sstate->mutex);
				 elog(ERROR, "failed on cuMemcpyHtoD: %s", errorText(rc));
			}
		}
	}
out_unlock:
	SpinLockRelease(&gj_sstate->mutex);
	return depth;
}

/*
 * gpujoin_terminator_task
 */
static GpuTask *
gpujoin_terminator_task(GpuTaskState *gts, cl_bool *task_is_ready)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	GpuTask		   *gtask = NULL;
	cl_int			outer_depth;
	
	/* Has RIGHT/FULL OUTER JOIN? */
	outer_depth = gpujoinNextRightOuterJoinIfAny(&gjs->gts);
	if (outer_depth > 0)
		gtask = gpujoin_create_task(gjs, NULL, outer_depth);

	return gtask;
}

static TupleTableSlot *
gpujoin_next_tuple(GpuTaskState *gts)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	GpuJoinTask	   *pgjoin = (GpuJoinTask *)gjs->gts.curr_task;
	TupleTableSlot *slot;

	if (pgjoin->task.cpu_fallback)
	{
		/*
		 * MEMO: We may reuse tts_values[]/tts_isnull[] of the previous
		 * tuple, to avoid same part of tuple extraction. For example,
		 * portion by depth < 2 will not be changed during iteration in
		 * depth == 3. You may need to pay attention on the core changes
		 * in the future version.
		 */
		slot = gpujoinNextTupleFallback(&gjs->gts,
										&pgjoin->kern,
										pgjoin->pds_src,
										Max(pgjoin->outer_depth,0));
	}
	else
	{
		slot = gjs->gts.css.ss.ss_ScanTupleSlot;
		ExecClearTuple(slot);
		if (!PDS_fetch_tuple(slot, pgjoin->pds_dst, &gjs->gts))
			slot = NULL;
	}
	return slot;
}

/* ----------------------------------------------------------------
 *
 * Routines for CPU fallback, if kernel code returned CpuReCheck
 * error code.
 *
 * ----------------------------------------------------------------
 */
static void
gpujoin_fallback_tuple_extract(TupleTableSlot *slot_fallback,
							   kern_data_store *kds,
							   ItemPointer t_self,
							   HeapTupleHeader htup,
							   AttrNumber *tuple_dst_resno,
							   AttrNumber src_anum_min,
							   AttrNumber src_anum_max)
{
	bool		hasnulls;
	TupleDesc	tts_tupdesc __attribute__((unused))
		= slot_fallback->tts_tupleDescriptor;
	Datum	   *tts_values = slot_fallback->tts_values;
	bool	   *tts_isnull = slot_fallback->tts_isnull;
	cl_uint		offset;
	int			i, nattrs;
	AttrNumber	resnum;

	Assert(kds->format == KDS_FORMAT_ROW ||
		   kds->format == KDS_FORMAT_HASH ||
		   kds->format == KDS_FORMAT_BLOCK);
	Assert(src_anum_min > FirstLowInvalidHeapAttributeNumber);
	Assert(src_anum_max <= kds->ncols);

	/* fill up the destination with NULL, if no tuple was supplied. */
	if (!htup)
	{
		for (i = src_anum_min; i <= src_anum_max; i++)
		{
			resnum = tuple_dst_resno[i-FirstLowInvalidHeapAttributeNumber-1];
			if (resnum)
			{
				Assert(resnum > 0 && resnum <= tts_tupdesc->natts);
				tts_values[resnum - 1] = (Datum) 0;
				tts_isnull[resnum - 1] = true;
			}
		}
		return;
	}
	hasnulls = ((htup->t_infomask & HEAP_HASNULL) != 0);

	/* Extract system columns if any */
	for (i = src_anum_min; i < 0; i++)
	{
		ItemPointer	temp;
		Datum		datum;

		resnum = tuple_dst_resno[i - FirstLowInvalidHeapAttributeNumber - 1];
		if (!resnum)
			continue;
		Assert(resnum > 0 && resnum <= tts_tupdesc->natts);
		switch (i)
		{
			case SelfItemPointerAttributeNumber:
				temp = palloc(sizeof(ItemPointerData));
				ItemPointerCopy(t_self, temp);
				datum = PointerGetDatum(temp);
				break;
			case MaxCommandIdAttributeNumber:
				datum = CommandIdGetDatum(HeapTupleHeaderGetRawCommandId(htup));
				break;
			case MaxTransactionIdAttributeNumber:
				datum = TransactionIdGetDatum(HeapTupleHeaderGetRawXmax(htup));
				break;
			case MinCommandIdAttributeNumber:
				datum = CommandIdGetDatum(HeapTupleHeaderGetRawCommandId(htup));
				break;
			case MinTransactionIdAttributeNumber:
				datum = TransactionIdGetDatum(HeapTupleHeaderGetRawXmin(htup));
				break;
#if PG_VERSION_NUM < 120000
			case ObjectIdAttributeNumber:
				datum = ObjectIdGetDatum(HeapTupleHeaderGetOid(htup));
				break;
#endif
			case TableOidAttributeNumber:
				datum = ObjectIdGetDatum(kds->table_oid);
				break;
			default:
				elog(ERROR, "Bug? unknown system attribute: %d", i);
		}
		tts_isnull[resnum - 1] = false;
		tts_values[resnum - 1] = datum;
	}

	/*
	 * Extract user defined columns, according to the logic in
	 * heap_deform_tuple(), but implemented by ourselves for performance.
	 */
	nattrs = HeapTupleHeaderGetNatts(htup);
	nattrs = Min3(nattrs, kds->ncols, src_anum_max);

	offset = htup->t_hoff;
	for (i=0; i < nattrs; i++)
	{
		resnum = tuple_dst_resno[i - FirstLowInvalidHeapAttributeNumber];
		if (hasnulls && att_isnull(i, htup->t_bits))
		{
			if (resnum > 0)
			{
				Assert(resnum <= tts_tupdesc->natts);
				tts_values[resnum - 1] = (Datum) 0;
				tts_isnull[resnum - 1] = true;
			}
		}
		else
		{
			kern_colmeta   *cmeta = &kds->colmeta[i];

			if (cmeta->attlen > 0)
				offset = TYPEALIGN(cmeta->attalign, offset);
			else if (!VARATT_NOT_PAD_BYTE((char *)htup + offset))
				offset = TYPEALIGN(cmeta->attalign, offset);
			if (resnum > 0)
			{
				void	   *addr = ((char *)htup + offset);

				Assert(resnum <= tts_tupdesc->natts);
				tts_isnull[resnum - 1] = false;
				if (cmeta->attbyval)
				{
					Datum	datum = 0;

					if (cmeta->attlen == sizeof(cl_char))
                        datum = *((cl_char *)addr);
                    else if (cmeta->attlen == sizeof(cl_short))
                        datum = *((cl_short *)addr);
                    else if (cmeta->attlen == sizeof(cl_int))
						datum = *((cl_int *)addr);
					else if (cmeta->attlen == sizeof(cl_long))
						datum = *((cl_long *)addr);
					else
					{
						Assert(cmeta->attlen <= sizeof(Datum));
						memcpy(&datum, addr, cmeta->attlen);
					}
					tts_values[resnum - 1] = datum;
					offset += cmeta->attlen;
				}
				else
				{
					tts_values[resnum - 1] = PointerGetDatum(addr);
				    offset += (cmeta->attlen < 0
							   ? VARSIZE_ANY(addr)
							   : cmeta->attlen);
				}
			}
		}
	}

	/*
     * If tuple doesn't have all the atts indicated by src_anum_max,
	 * read the rest as null
	 */
	for (; i < src_anum_max; i++)
	{
		resnum = tuple_dst_resno[i - FirstLowInvalidHeapAttributeNumber];
		if (resnum > 0)
		{
			Assert(resnum <= tts_tupdesc->natts);
			tts_values[resnum - 1] = (Datum) 0;
			tts_isnull[resnum - 1] = true;
		}
	}
}

/*
 * Hash-Join for CPU fallback
 */
static int
gpujoinFallbackHashJoin(int depth, GpuJoinState *gjs)
{
	ExprContext	   *econtext = gjs->gts.css.ss.ps.ps_ExprContext;
	innerState	   *istate = &gjs->inners[depth-1];
	kern_multirels *h_kmrels = gjs->h_kmrels;
	kern_data_store *kds_in = KERN_MULTIRELS_INNER_KDS(h_kmrels, depth);
	cl_bool		   *ojmaps = KERN_MULTIRELS_OUTER_JOIN_MAP(h_kmrels, depth);
	kern_hashitem  *khitem;
	cl_uint			hash;
	bool			retval;

	do {
		if (istate->fallback_inner_index == 0)
		{
			bool	is_nullkeys;

			hash = get_tuple_hashvalue(istate,
									   false,
									   gjs->slot_fallback,
									   &is_nullkeys);
			/* all-null keys never match to inner rows */
			if (is_nullkeys)
				goto end;
			istate->fallback_inner_hash = hash;
			for (khitem = KERN_HASH_FIRST_ITEM(kds_in, hash);
				 khitem && khitem->hash != hash;
				 khitem = KERN_HASH_NEXT_ITEM(kds_in, khitem));
			if (!khitem)
				goto end;
		}
		else
		{
			hash = istate->fallback_inner_hash;
			khitem = (kern_hashitem *)
				((char *)kds_in + istate->fallback_inner_index);
			for (khitem = KERN_HASH_NEXT_ITEM(kds_in, khitem);
				 khitem && khitem->hash != hash;
				 khitem = KERN_HASH_NEXT_ITEM(kds_in, khitem));
			if (!khitem)
				goto end;
		}
		istate->fallback_inner_index =
			(cl_uint)((char *)khitem - (char *)kds_in);

		gpujoin_fallback_tuple_extract(gjs->slot_fallback,
									   kds_in,
									   &khitem->t.htup.t_ctid,
									   &khitem->t.htup,
									   istate->inner_dst_resno,
									   istate->inner_src_anum_min,
									   istate->inner_src_anum_max);
		retval = ExecQual(istate->other_quals, econtext);
	} while (!retval);

	/* update outer join map */
	if (ojmaps)
		ojmaps[khitem->t.rowid] = 1;
	/* rewind the next depth */
	if (depth < gjs->num_rels)
	{
		istate++;
		istate->fallback_inner_index = 0;
		istate->fallback_inner_matched = false;
	}
	return depth+1;

end:
	if (!istate->fallback_inner_matched &&
		(istate->join_type == JOIN_LEFT ||
		 istate->join_type == JOIN_FULL))
	{
		istate->fallback_inner_matched = true;
		gpujoin_fallback_tuple_extract(gjs->slot_fallback,
									   kds_in,
                                       NULL,
                                       NULL,
									   istate->inner_dst_resno,
									   istate->inner_src_anum_min,
									   istate->inner_src_anum_max);
		if (depth < gjs->num_rels)
		{
			istate++;
			istate->fallback_inner_index = 0;
			istate->fallback_inner_matched = false;
		}
		return depth+1;
	}
	/* pop up one level */
	return depth-1;
}

/*
 * Nest-Loop for CPU fallback
 */
static int
gpujoinFallbackNestLoop(int depth, GpuJoinState *gjs)
{
	ExprContext	   *econtext = gjs->gts.css.ss.ps.ps_ExprContext;
	innerState	   *istate = &gjs->inners[depth-1];
	kern_multirels *h_kmrels = gjs->h_kmrels;
	kern_data_store *kds_in = KERN_MULTIRELS_INNER_KDS(h_kmrels, depth);
	cl_bool		   *ojmaps = KERN_MULTIRELS_OUTER_JOIN_MAP(h_kmrels, depth);
	cl_uint			index;

	for (index = istate->fallback_inner_index;
		 index < kds_in->nitems;
		 index++)
	{
		kern_tupitem   *tupitem = KERN_DATA_STORE_TUPITEM(kds_in, index);
		bool			retval;

		gpujoin_fallback_tuple_extract(gjs->slot_fallback,
									   kds_in,
									   &tupitem->htup.t_ctid,
									   &tupitem->htup,
									   istate->inner_dst_resno,
									   istate->inner_src_anum_min,
									   istate->inner_src_anum_max);
		retval = ExecQual(istate->join_quals, econtext);
		if (retval)
		{
			istate->fallback_inner_index = index + 1;
			/* update outer join map */
			if (ojmaps)
				ojmaps[index] = 1;
			/* rewind the next depth */
			if (depth < gjs->num_rels)
			{
				istate++;
				istate->fallback_inner_index = 0;
				istate->fallback_inner_matched = false;
			}
			return depth+1;
		}
	}

	if (!istate->fallback_inner_matched &&
		(istate->join_type == JOIN_LEFT ||
		 istate->join_type == JOIN_FULL))
	{
		istate->fallback_inner_index = kds_in->nitems;
		istate->fallback_inner_matched = true;

		gpujoin_fallback_tuple_extract(gjs->slot_fallback,
									   kds_in,
									   NULL,
									   NULL,
									   istate->inner_dst_resno,
									   istate->inner_src_anum_min,
									   istate->inner_src_anum_max);
		/* rewind the next depth */
		if (depth < gjs->num_rels)
		{
			istate++;
			istate->fallback_inner_index = 0;
			istate->fallback_inner_matched = false;
		}
		return depth+1;
	}
	/* pop up one level */
	return depth-1;
}

static int
gpujoinFallbackLoadOuter(int depth, GpuJoinState *gjs)
{
	kern_multirels *h_kmrels = gjs->h_kmrels;
	kern_data_store *kds_in = KERN_MULTIRELS_INNER_KDS(h_kmrels, depth);
	cl_bool		   *ojmaps = KERN_MULTIRELS_OUTER_JOIN_MAP(h_kmrels, depth);
	cl_uint			index;

	for (index = gjs->inners[depth-1].fallback_inner_index;
		 index < kds_in->nitems;
		 index++)
	{
		if (!ojmaps[index])
		{
			innerState	   *istate = &gjs->inners[depth-1];
			kern_tupitem   *tupitem = KERN_DATA_STORE_TUPITEM(kds_in, index);

			gpujoin_fallback_tuple_extract(gjs->slot_fallback,
										   kds_in,
										   &tupitem->htup.t_ctid,
										   &tupitem->htup,
										   istate->inner_dst_resno,
										   istate->inner_src_anum_min,
										   istate->inner_src_anum_max);
			istate->fallback_inner_index = index + 1;
			/* rewind the next depth */
			if (depth < gjs->num_rels)
			{
				istate++;
				istate->fallback_inner_index = 0;
				istate->fallback_inner_matched = false;
			}
			return depth + 1;
		}
	}
	return -1;
}

static int
gpujoinFallbackLoadSource(int depth, GpuJoinState *gjs,
						  pgstrom_data_store *pds_src)
{
	kern_data_store *kds_src = &pds_src->kds;
	ExprContext	   *econtext = gjs->gts.css.ss.ps.ps_ExprContext;
	bool			retval;

	Assert(depth == 0);
	do {
		if (kds_src->format == KDS_FORMAT_ROW)
		{
			cl_uint			index = gjs->fallback_outer_index++;
			kern_tupitem   *tupitem;

			if (index >= kds_src->nitems)
				return -1;
			/* fills up fallback_slot with outer columns */
			tupitem = KERN_DATA_STORE_TUPITEM(kds_src, index);
			gpujoin_fallback_tuple_extract(gjs->slot_fallback,
										   kds_src,
										   &tupitem->htup.t_ctid,
										   &tupitem->htup,
										   gjs->outer_dst_resno,
										   gjs->outer_src_anum_min,
										   gjs->outer_src_anum_max);
		}
		else if (kds_src->format == KDS_FORMAT_BLOCK)
		{
			HeapTupleHeader	htup;
			ItemPointerData	t_self;
			PageHeaderData *pg_page;
			BlockNumber		block_nr;
			cl_uint			line_nr;
			cl_uint			index;
			ItemIdData	   *lpp;

			index = (gjs->fallback_outer_index >> 16);
			line_nr = (gjs->fallback_outer_index++ & 0xffff);
			if (index >= kds_src->nitems)
				return -1;
			pg_page = KERN_DATA_STORE_BLOCK_PGPAGE(kds_src, index);
			block_nr = KERN_DATA_STORE_BLOCK_BLCKNR(kds_src, index);
			if (line_nr >= PageGetMaxOffsetNumber(pg_page))
			{
				gjs->fallback_outer_index = (cl_ulong)(index + 1) << 16;
				continue;
			}
			lpp = PageGetItemId(pg_page, line_nr + 1);
			if (!ItemIdIsNormal(lpp))
				continue;
			htup = (HeapTupleHeader)PageGetItem(pg_page, lpp);
			t_self.ip_blkid.bi_hi = block_nr >> 16;
			t_self.ip_blkid.bi_lo = block_nr & 0xffff;
			t_self.ip_posid = line_nr + 1;

			gpujoin_fallback_tuple_extract(gjs->slot_fallback,
										   kds_src,
										   &t_self,
										   htup,
										   gjs->outer_dst_resno,
										   gjs->outer_src_anum_min,
										   gjs->outer_src_anum_max);
		}
		else
			elog(ERROR, "Bug? unexpected KDS format: %d", pds_src->kds.format);
		//TODO: add KDS_FORMAT_COLUMN here
		retval = ExecQual(gjs->outer_quals, econtext);
	} while (!retval);

	/* rewind the next depth */
	gjs->inners[0].fallback_inner_index = 0;
	return 1;
}

/*
 * gpujoinFallbackLoadFromSuspend
 */
static int
gpujoinFallbackLoadFromSuspend(GpuJoinState *gjs,
							   kern_gpujoin *kgjoin,
							   pgstrom_data_store *pds_src,
							   int outer_depth)
{
	kern_multirels *h_kmrels = gjs->h_kmrels;
	cl_int		num_rels = gjs->num_rels;
	cl_uint		block_sz = kgjoin->block_sz;
	cl_uint		grid_sz = kgjoin->grid_sz;
	cl_uint		global_sz = block_sz * grid_sz;
	cl_long		thread_index;
	cl_long		thread_loops;
	cl_int		depth;
	cl_uint		global_id;
	cl_uint		group_id;
	cl_uint		local_id;
	cl_uint		write_pos;
	cl_uint		read_pos;
	cl_uint		row_index;
	gpujoinPseudoStack *pstack;
	cl_uint	   *pstack_base;
	cl_int		j;
	gpujoinSuspendContext *sb;
	HeapTupleHeaderData *htup;
	ItemPointerData t_self;

lnext:
	/* setup pseudo thread-id based on fallback_thread_count */
	thread_index = (gjs->fallback_thread_count >> 10);
	thread_loops = (gjs->fallback_thread_count & 0x03ff);
	depth = thread_index / global_sz + outer_depth;
	global_id = thread_index % global_sz;
	group_id = global_id / block_sz;
	local_id = global_id % block_sz;

	/* no more pending rows in the suspend context */
	if (depth > num_rels)
	{
		gjs->fallback_outer_index = kgjoin->src_read_pos;
		kgjoin->resume_context = false;
		return 0;
	}
	gjs->fallback_resume_depth = depth;

	/* suspend context and pseudo stack */
	pstack = (gpujoinPseudoStack *)kparam_get_value(gjs->gts.kern_params, 0);
	pstack_base = (cl_uint *)((char *)kgjoin + kgjoin->pstack_offset +
							  group_id * pstack->ps_unitsz +
							  pstack->ps_offset[depth]);
	sb = KERN_GPUJOIN_SUSPEND_CONTEXT(kgjoin, group_id);
	if (sb->depth < 0)
	{
		/*
		 * This threads-group successfull finished.
		 * So, move to the next threads-groups.
		 */
		gjs->fallback_thread_count =
			((thread_index / block_sz + 1) * block_sz) << 10;
		goto lnext;
	}
	else if (sb->depth != num_rels + 1)
		elog(ERROR, "Bug? unexpected point for GpuJoin kernel suspend");

	write_pos = sb->pd[depth].write_pos;
	read_pos = sb->pd[depth].read_pos;
	row_index = block_sz * thread_loops + local_id;
	if (row_index >= write_pos)
	{
		if (local_id < block_sz)
		{
			/* move to the next thread */
			gjs->fallback_thread_count = (thread_index + 1) << 10;
		}
		else
		{
			/* move to the next threads group */
			gjs->fallback_thread_count =
				((thread_index / block_sz + 1) * block_sz) << 10;
		}
		goto lnext;
	}
	gjs->fallback_thread_count++;

	/* extract partially joined tuples */
	pstack_base += row_index * (depth + 1);
	for (j=outer_depth; j <= depth; j++)
	{
		if (j == 0)
		{
			/* load from the outer source buffer */
			if (pds_src->kds.format == KDS_FORMAT_ROW)
			{
				htup = KDS_ROW_REF_HTUP(&pds_src->kds,
										pstack_base[0],
										&t_self, NULL);
				gpujoin_fallback_tuple_extract(gjs->slot_fallback,
											   &pds_src->kds,
											   &t_self,
											   htup,
											   gjs->outer_dst_resno,
											   gjs->outer_src_anum_min,
											   gjs->outer_src_anum_max);
			}
			else if (pds_src->kds.format == KDS_FORMAT_BLOCK)
			{
				HeapTupleHeader	htup;
				ItemPointerData	t_self;

				htup = KDS_BLOCK_REF_HTUP(&pds_src->kds,
										  pstack_base[0],
										  &t_self, NULL);
				gpujoin_fallback_tuple_extract(gjs->slot_fallback,
											   &pds_src->kds,
											   &t_self,
											   htup,
											   gjs->outer_dst_resno,
											   gjs->outer_src_anum_min,
											   gjs->outer_src_anum_max);
			}
			else
			{
				elog(ERROR, "Bug? unexpected PDS format: %d",
					 pds_src->kds.format);
			}
		}
		else
		{
			innerState	   *istate = &gjs->inners[j-1];
			kern_data_store *kds_in = KERN_MULTIRELS_INNER_KDS(h_kmrels, j);

			htup = KDS_ROW_REF_HTUP(kds_in,pstack_base[j],&t_self,NULL);
			gpujoin_fallback_tuple_extract(gjs->slot_fallback,
										   kds_in,
										   &t_self,
										   htup,
										   istate->inner_dst_resno,
										   istate->inner_src_anum_min,
										   istate->inner_src_anum_max);
		}
	}

	/* assign starting point of the next depth */
	if (depth < num_rels)
	{
		innerState	   *istate = &gjs->inners[depth];

		if (row_index < read_pos)
		{
			/*
			 * This partially joined row is already processed by the deeper
			 * level, so no need to move deeper level any more.
			 */
			goto lnext;
		}
		else if (row_index < read_pos + kgjoin->block_sz)
		{
			/*
			 * This partially joined row is now processed by the deeper
			 * level, so we must restart from the next position.
			 */
			kern_data_store *kds_in;
			cl_uint		l_state = sb->pd[depth+1].l_state[local_id];
			cl_bool		matched = sb->pd[depth+1].matched[local_id];

			kds_in = KERN_MULTIRELS_INNER_KDS(h_kmrels, depth+1);
			if (kds_in->format == KDS_FORMAT_HASH)
			{
				if (l_state == 0)
				{
					/* restart from the head */
					gjs->inners[depth].fallback_inner_index = 0;
				}
				else if (l_state == UINT_MAX)
				{
					/* already reached end of the hash-chain */
					gjs->fallback_thread_count = (thread_index + 1) << 10;
					goto lnext;
				}
				else
				{
					kern_hashitem  *khitem = (kern_hashitem *)
						((char *)kds_in
						 + __kds_unpack(l_state)
						 - offsetof(kern_hashitem, t.htup));
					istate->fallback_inner_index =
						((char *)khitem - (char *)kds_in);
					istate->fallback_inner_hash = khitem->hash;
					istate->fallback_inner_matched = matched;
				}
			}
			else if (kds_in->format == KDS_FORMAT_ROW)
			{
				cl_uint		x_unitsz = Min(write_pos - read_pos,
										   kgjoin->grid_sz);
				cl_uint		y_unitsz = kgjoin->grid_sz / x_unitsz;

				istate->fallback_inner_index = l_state + y_unitsz;
			}
			else
				elog(ERROR, "Bug? unexpected inner buffer format: %d",
					 kds_in->format);
		}
		else
		{
			/*
			 * This partially joined row is not processed in the deeper
			 * level, so we shall suspend join from the head.
			 */
			istate->fallback_inner_index = 0;
		}
	}
	else
	{
		/*
		 * This completely joined row is already written to the destination
		 * buffer, thus should be preliminary fetched.
		 */
		if (row_index < read_pos)
			goto lnext;
	}
	/* make the fallback_thread_count advanced */
	return depth + 1;
}

/*
 * gpujoinNextTupleFallback - CPU Fallback
 */
TupleTableSlot *
gpujoinNextTupleFallback(GpuTaskState *gts,
						 kern_gpujoin *kgjoin,
						 pgstrom_data_store *pds_src,
						 cl_int outer_depth)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	GpuJoinSharedState *gj_sstate = gjs->gj_sstate;
	ExprContext	   *econtext = gjs->gts.css.ss.ps.ps_ExprContext;
	cl_int			depth;

	econtext->ecxt_scantuple = gjs->slot_fallback;
	ResetExprContext(econtext);

	if (gjs->fallback_outer_index < 0)
	{
		cl_int		i, num_rels = gjs->num_rels;

		/* init cpu fallback state for each GpuTask */
		if (pds_src)
			Assert(outer_depth == 0);
		else
		{
			Assert(outer_depth > 0 && outer_depth <= num_rels);
			gpujoinColocateOuterJoinMapsToHost(gjs);
		}
		gjs->fallback_resume_depth = outer_depth;
		gjs->fallback_thread_count = 0;
		gjs->fallback_outer_index = 0;
		for (i=0; i < num_rels; i++)
			gjs->inners[i].fallback_inner_index = 0;

		/*
		 * Once CPU fallback happen, RIGHT/FULL OUTER JOIN map must
		 * be colocated, regardless of the number of GPU devices.
		 * So, we ensure colocation by setting number larger than 1.
		 */
		pg_atomic_write_u32(&gj_sstate->needs_colocation, 123);
		
		depth = outer_depth;
	}
	else
	{
		depth = gjs->num_rels;
	}

	while (depth >= 0)
	{
		Assert(depth >= outer_depth);
		if (depth == (kgjoin->resume_context
					  ? gjs->fallback_resume_depth
					  : outer_depth))
		{
			ExecStoreAllNullTuple(gjs->slot_fallback);
			if (kgjoin->resume_context)
				depth = gpujoinFallbackLoadFromSuspend(gjs, kgjoin, pds_src,
													   outer_depth);
			else if (pds_src)
				depth = gpujoinFallbackLoadSource(depth, gjs, pds_src);
			else
				depth = gpujoinFallbackLoadOuter(depth, gjs);
		}
		else if (depth <= gjs->num_rels)
		{
			if (gjs->inners[depth-1].hash_outer_keys != NIL)
				depth = gpujoinFallbackHashJoin(depth, gjs);
			else
				depth = gpujoinFallbackNestLoop(depth, gjs);
		}
		else
		{
			TupleTableSlot *slot = gjs->slot_fallback;

			/* projection? */
			if (gjs->proj_fallback)
				slot = ExecProject(gjs->proj_fallback);
			Assert(slot == gjs->gts.css.ss.ss_ScanTupleSlot);
			return slot;
		}
	}
	/* rewind the fallback status for the further GpuJoinTask */
	gjs->fallback_outer_index = -1;
	return NULL;
}

/* ----------------------------------------------------------------
 *
 * Routines to support combined GpuPreAgg + GpuJoin
 *
 * ----------------------------------------------------------------
 */
ProgramId
GpuJoinCreateCombinedProgram(PlanState *node,
							 GpuTaskState *gpa_gts,
							 cl_uint gpa_extra_flags,
							 cl_uint gpa_varlena_bufsz,
							 const char *gpa_kern_source,
							 bool explain_only)
{
	GpuJoinState   *gjs = (GpuJoinState *) node;
	GpuJoinInfo	   *gj_info;
	StringInfoData	kern_define;
	StringInfoData	kern_source;
	cl_uint			extra_flags;
	ProgramId		program_id;

	initStringInfo(&kern_define);
	initStringInfo(&kern_source);

	gj_info = deform_gpujoin_info((CustomScan *) gjs->gts.css.ss.ps.plan);
	extra_flags = (gpa_extra_flags | gj_info->extra_flags);
	pgstrom_build_session_info(&kern_define,
							   gpa_gts,
							   extra_flags & ~DEVKERNEL_NEEDS_GPUJOIN);
	assign_gpujoin_session_info(&kern_define, &gjs->gts);

	appendStringInfoString(
		&kern_source,
		"\n/* ====== BEGIN GpuJoin Portion ====== */\n\n");
	appendStringInfoString(
		&kern_source,
		gj_info->kern_source);
	appendStringInfoString(
		&kern_source,
		"\n/* ====== BEGIN GpuPreAgg Portion ====== */\n\n");
	appendStringInfoString(&kern_source, gpa_kern_source);

	program_id = pgstrom_create_cuda_program(gpa_gts->gcontext,
											 extra_flags,
											 Max(gj_info->varlena_bufsz,
												 gpa_varlena_bufsz),
											 kern_source.data,
											 kern_define.data,
											 false,
											 explain_only);
	pfree(kern_source.data);
	pfree(kern_define.data);

	return program_id;
}

/* ----------------------------------------------------------------
 *
 * GpuTask handlers of GpuJoin
 *
 * ----------------------------------------------------------------
 */
void
gpujoin_release_task(GpuTask *gtask)
{
	GpuJoinTask	   *pgjoin = (GpuJoinTask *) gtask;
	GpuTaskState   *gts = (GpuTaskState *) gtask->gts;

	if (pgjoin->pds_src)
		PDS_release(pgjoin->pds_src);
	if (pgjoin->pds_dst)
		PDS_release(pgjoin->pds_dst);
	/* release this gpu-task itself */
	gpuMemFree(gts->gcontext, (CUdeviceptr)pgjoin);
}

void
gpujoinUpdateRunTimeStat(GpuTaskState *gts, kern_gpujoin *kgjoin)
{
	GpuJoinState	   *gjs = (GpuJoinState *)gts;
	GpuJoinRuntimeStat *gj_rtstat = GPUJOIN_RUNTIME_STAT(gjs->gj_sstate);
	cl_int		i;

	pg_atomic_fetch_add_u64(&gj_rtstat->c.source_nitems,
							kgjoin->source_nitems);
	pg_atomic_fetch_add_u64(&gj_rtstat->c.nitems_filtered,
							kgjoin->source_nitems -
							kgjoin->outer_nitems);
	pg_atomic_fetch_add_u64(&gj_rtstat->jstat[0].inner_nitems,
							kgjoin->outer_nitems);
	for (i=0; i < gjs->num_rels; i++)
	{
		pg_atomic_fetch_add_u64(&gj_rtstat->jstat[i+1].inner_nitems,
								kgjoin->stat[i].nitems);
		pg_atomic_fetch_add_u64(&gj_rtstat->jstat[i+1].inner_nitems2,
								kgjoin->stat[i].nitems2);
	}
	/* debug counters if any */
	if (kgjoin->debug_counter0 != 0)
		pg_atomic_fetch_add_u64(&gj_rtstat->c.debug_counter0, kgjoin->debug_counter0);
	if (kgjoin->debug_counter1 != 0)
		pg_atomic_fetch_add_u64(&gj_rtstat->c.debug_counter1, kgjoin->debug_counter1);
	if (kgjoin->debug_counter2 != 0)
		pg_atomic_fetch_add_u64(&gj_rtstat->c.debug_counter2, kgjoin->debug_counter2);
	if (kgjoin->debug_counter3 != 0)
		pg_atomic_fetch_add_u64(&gj_rtstat->c.debug_counter3, kgjoin->debug_counter3);
	
	/* reset counters (may be reused by the resumed kernel) */
	kgjoin->source_nitems = 0;
	kgjoin->outer_nitems  = 0;
	for (i=0; i < gjs->num_rels; i++)
	{
		kgjoin->stat[i].nitems = 0;
		kgjoin->stat[i].nitems2 = 0;
	}
}

/*
 * gpujoin_throw_partial_result
 */
static void
gpujoin_throw_partial_result(GpuJoinTask *pgjoin)
{
	GpuContext	   *gcontext = GpuWorkerCurrentContext;
	GpuTaskState   *gts = pgjoin->task.gts;
	pgstrom_data_store *pds_dst = pgjoin->pds_dst;
	pgstrom_data_store *pds_new = PDS_clone(pds_dst);
	cl_int			num_rels = pgjoin->kern.num_rels;
	GpuJoinTask	   *gresp;
	size_t			head_sz;
	size_t			param_sz;
	CUresult		rc;

	/* async prefetch kds_dst; which should be on the device memory */
	rc = cuMemPrefetchAsync((CUdeviceptr) &pds_dst->kds,
							pds_dst->kds.length,
							CU_DEVICE_CPU,
							CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemPrefetchAsync: %s", errorText(rc));

	/* setup responder task with supplied @kds_dst */
	head_sz = STROMALIGN(offsetof(GpuJoinTask, kern) +
						 offsetof(kern_gpujoin, stat[num_rels+1]));
	param_sz = KERN_GPUJOIN_PARAMBUF_LENGTH(&pgjoin->kern);
	/* pstack/suspend buffer is not necessary */
	rc = gpuMemAllocManaged(gcontext,
							(CUdeviceptr *)&gresp,
							head_sz + param_sz,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));

	memset(gresp, 0, head_sz);
	gresp->task.task_kind	= pgjoin->task.task_kind;
	gresp->task.program_id	= pgjoin->task.program_id;
	gresp->task.cpu_fallback= false;
	gresp->task.gts			= gts;
	gresp->pds_src			= PDS_retain(pgjoin->pds_src);
	gresp->pds_dst			= pds_dst;
	gresp->outer_depth		= pgjoin->outer_depth;

	gresp->kern.num_rels	= num_rels;
	memcpy((char *)gresp + head_sz,
		   KERN_GPUJOIN_PARAMBUF(&pgjoin->kern),
		   KERN_GPUJOIN_PARAMBUF_LENGTH(&pgjoin->kern));
	/* assign a new empty buffer */
	pgjoin->pds_dst			= pds_new;

	/* Back GpuTask to GTS */
	pthreadMutexLock(&gcontext->worker_mutex);
	dlist_push_tail(&gts->ready_tasks,
					&gresp->task.chain);
	gts->num_ready_tasks++;
	pthreadMutexUnlock(&gcontext->worker_mutex);

	SetLatch(MyLatch);
}

/*
 * gpujoinColocateOuterJoinMapsToHost
 *
 * It moves outer-join-map on the device memory to the host memory prior to
 * CPU fallback of RIGHT/FULL OUTER JOIN. When this function is called,
 * no GPU kernel shall not be working, so just cuMemcpyDtoH() works.
 */
static void
gpujoinColocateOuterJoinMapsToHost(GpuJoinState *gjs)
{
	kern_multirels *h_kmrels = gjs->h_kmrels;
	size_t			offset = h_kmrels->kmrels_length;
	size_t			length = h_kmrels->ojmaps_length;
	cl_bool		   *h_ojmaps = (char *)h_kmrels + offset;
	cl_bool		   *m_ojmaps = alloca(length);
	CUresult		rc;

	rc = cuMemcpyDtoH(m_ojmaps, gjs->m_kmrels + offset, length);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on cuMemcpyHtoD: %s", errorText(rc));
	/* merge outer join map */
	for (offset=0; offset < length; offset += sizeof(cl_ulong))
	{
		*((cl_ulong *)(h_ojmaps + offset))
			|= *((cl_ulong *)(m_ojmaps + offset));
	}
}

static cl_int
gpujoin_process_inner_join(GpuJoinTask *pgjoin, CUmodule cuda_module)
{
	GpuContext		   *gcontext = GpuWorkerCurrentContext;
	GpuJoinState	   *gjs = (GpuJoinState *) pgjoin->task.gts;
	pgstrom_data_store *pds_src = pgjoin->pds_src;
	pgstrom_data_store *pds_dst = pgjoin->pds_dst;
	CUfunction			kern_gpujoin_main;
	CUdeviceptr			m_kgjoin = (CUdeviceptr)&pgjoin->kern;
	CUdeviceptr			m_kds_src = 0UL;
	CUdeviceptr			m_kds_extra = 0UL;
	CUdeviceptr			m_kds_dst;
	CUdeviceptr			m_nullptr = 0UL;
	CUresult			rc;
	bool				m_kds_src_release = false;
	cl_int				grid_sz;
	cl_int				block_sz;
	cl_int				retval = 10001;
	void			   *kern_args[10];
	void			   *last_suspend = NULL;

	/* sanity checks */
	Assert(pds_src->kds.format == KDS_FORMAT_ROW ||
		   pds_src->kds.format == KDS_FORMAT_BLOCK ||
		   pds_src->kds.format == KDS_FORMAT_ARROW ||
		   pds_src->kds.format == KDS_FORMAT_COLUMN);
	Assert(pds_dst->kds.format == KDS_FORMAT_ROW);

	/* Lookup GPU kernel function */
	rc = cuModuleGetFunction(&kern_gpujoin_main,
							 cuda_module,
							 "kern_gpujoin_main");
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	/*
	 * Device memory allocation
	 */
	if (pgjoin->with_nvme_strom)
	{
		Size	required = GPUMEMALIGN(pds_src->kds.length);

		Assert(pds_src->kds.format == KDS_FORMAT_BLOCK ||
			   pds_src->kds.format == KDS_FORMAT_ARROW);
		rc = gpuMemAllocIOMap(gcontext,
							  &m_kds_src,
							  required);
		if (rc == CUDA_SUCCESS)
			m_kds_src_release = true;
		else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		{
			pgjoin->with_nvme_strom = false;
			if (pds_src->kds.format == KDS_FORMAT_BLOCK)
			{
				PDS_fillup_blocks(pds_src);

				rc = gpuMemAlloc(gcontext,
								 &m_kds_src,
                                 required);
				if (rc == CUDA_SUCCESS)
					m_kds_src_release = true;
				else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
					goto out_of_resource;
				else
					werror("failed on gpuMemAlloc: %s", errorText(rc));
			}
			else
			{
				pds_src = PDS_fillup_arrow(pgjoin->pds_src);
				PDS_release(pgjoin->pds_src);
				pgjoin->pds_src = pds_src;
				Assert(!pds_src->iovec);
			}
		}
		else
			werror("failed on gpuMemAllocIOMap: %s", errorText(rc));
	}
	else if (pds_src->kds.format == KDS_FORMAT_COLUMN)
	{
		m_kds_src = pds_src->m_kds_base;
		m_kds_extra = pds_src->m_kds_extra;
	}
	else
	{
		m_kds_src = (CUdeviceptr)&pds_src->kds;
	}

	/*
	 * OK, kick a series of GpuJoin invocations
	 */
	if (pgjoin->with_nvme_strom)
	{
		gpuMemCopyFromSSD(m_kds_src, pds_src);
	}
	else if (pds_src->kds.format == KDS_FORMAT_BLOCK)
	{
		rc = cuMemcpyHtoDAsync(m_kds_src,
							   &pds_src->kds,
							   pds_src->kds.length,
							   CU_STREAM_PER_THREAD);
		if (rc != CUDA_SUCCESS)
			werror("failed on cuMemcpyHtoD: %s", errorText(rc));

	}
	else if (pds_src->kds.format != KDS_FORMAT_COLUMN)
	{
		rc = cuMemPrefetchAsync(m_kds_src,
								pds_src->kds.length,
								CU_DEVICE_PER_THREAD,
								CU_STREAM_PER_THREAD);
		if (rc != CUDA_SUCCESS)
			werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
	}

	/* Launch:
	 * KERNEL_FUNCTION(void)
	 * gpujoin_main(kern_gpujoin *kgjoin,
	 *              kern_multirels *kmrels,
	 *              kern_data_store *kds_src,
	 *              kern_data_extra *kds_extra,
	 *              kern_data_store *kds_dst,
	 *              kern_parambuf *kparams_gpreagg)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_gpujoin_main,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(cl_int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
	pgjoin->kern.grid_sz	= grid_sz;
	pgjoin->kern.block_sz	= block_sz;

resume_kernel:
	m_kds_dst = (CUdeviceptr)&pds_dst->kds;
	kern_args[0] = &m_kgjoin;
	kern_args[1] = &gjs->m_kmrels;
	kern_args[2] = &m_kds_src;
	kern_args[3] = &m_kds_extra;
	kern_args[4] = &m_kds_dst;
	kern_args[5] = &m_nullptr;

	rc = cuLaunchKernel(kern_gpujoin_main,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * block_sz,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuLaunchKernel: %s", errorText(rc));

	rc = cuEventRecord(CU_EVENT_PER_THREAD, CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuEventRecord: %s", errorText(rc));

	/* Point of synchronization */
	rc = cuEventSynchronize(CU_EVENT_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuEventSynchronize: %s", errorText(rc));

	memcpy(&pgjoin->task.kerror,
		   &pgjoin->kern.kerror, sizeof(kern_errorbuf));
	if (pgjoin->task.kerror.errcode == ERRCODE_STROM_SUCCESS)
	{
		if (pgjoin->kern.suspend_count > 0)
		{
			CHECK_WORKER_TERMINATION();
			gpujoin_throw_partial_result(pgjoin);

			pgjoin->kern.suspend_count = 0;
			pgjoin->kern.resume_context = true;
			if (!last_suspend)
				last_suspend = alloca(pgjoin->kern.suspend_size);
			memcpy(last_suspend,
				   KERN_GPUJOIN_SUSPEND_CONTEXT(&pgjoin->kern, 0),
				   pgjoin->kern.suspend_size);
			//fprintf(stderr, "suspend / resume\n");
			/* renew buffer and restart */
			pds_dst = pgjoin->pds_dst;
			goto resume_kernel;
		}
		gpujoinUpdateRunTimeStat(&gjs->gts, &pgjoin->kern);
		/* return task if any result rows */
		retval = (pds_dst->kds.nitems > 0 ? 0 : -1);
	}
	else if (pgstrom_cpu_fallback_enabled &&
			 (pgjoin->kern.kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
	{
		/*
		 * In case of KDS_FORMAT_BLOCK, we have to write back the kernel
		 * buffer to the host-side, because SSD2GPU mode bypass the host
		 * memory, thus, CPU fallback routine will miss the data.
		 */
		if (pds_src->kds.format == KDS_FORMAT_BLOCK)
		{
			rc = cuMemcpyDtoH(&pds_src->kds,
							  m_kds_src,
							  pds_src->kds.length);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuMemcpyDtoH: %s", errorText(rc));
			pds_src->nblocks_uncached = 0;
		}
		else if (pds_src->kds.format == KDS_FORMAT_ARROW &&
				 pds_src->iovec != NULL)
		{
			pgjoin->pds_src = PDS_writeback_arrow(pds_src, m_kds_src);
		}
		memset(&pgjoin->task.kerror, 0, sizeof(kern_errorbuf));
		pgjoin->task.cpu_fallback = true;
		pgjoin->kern.resume_context = (last_suspend != NULL);
		if (last_suspend)
		{
			memcpy(KERN_GPUJOIN_SUSPEND_CONTEXT(&pgjoin->kern, 0),
				   last_suspend,
				   pgjoin->kern.suspend_size);
		}
		retval = 0;
	}
	else
	{
		/* raise an error */
		retval = 0;
	}
out_of_resource:
	if (m_kds_src_release)
		gpuMemFree(gcontext, m_kds_src);
	return retval;
}

static cl_int
gpujoin_process_right_outer(GpuJoinTask *pgjoin, CUmodule cuda_module)
{
	GpuJoinState	   *gjs = (GpuJoinState *) pgjoin->task.gts;
	pgstrom_data_store *pds_dst = pgjoin->pds_dst;
	CUfunction			kern_gpujoin_main;
	CUdeviceptr			m_kgjoin = (CUdeviceptr)&pgjoin->kern;
	CUdeviceptr			m_kds_dst;
	CUdeviceptr			m_nullptr = 0UL;
	CUresult			rc;
	cl_int				outer_depth = pgjoin->outer_depth;
	cl_int				grid_sz;
	cl_int				block_sz;
	void			   *kern_args[5];
	void			   *last_suspend = NULL;
	cl_int				retval;

	/* sanity checks */
	Assert(!pgjoin->pds_src);
	Assert(pds_dst->kds.format == KDS_FORMAT_ROW);
	Assert(outer_depth > 0 && outer_depth <= gjs->num_rels);

	/* Co-location of the outer join map */
	//gpujoinColocateOuterJoinMaps(&gjs->gts, cuda_module);

	/* Lookup GPU kernel function */
	rc = cuModuleGetFunction(&kern_gpujoin_main,
							 cuda_module,
							 "kern_gpujoin_right_outer");
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	/*
	 * KERNEL_FUNCTION(void)
	 * gpujoin_right_outer(kern_gpujoin *kgjoin,
	 *                     kern_multirels *kmrels,
	 *                     cl_int outer_depth,
	 *                     kern_data_store *kds_dst,
	 *                     kern_parambuf *kparams_gpreagg)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_gpujoin_main,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(cl_int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
resume_kernel:
	m_kds_dst = (CUdeviceptr)&pds_dst->kds;
	kern_args[0] = &m_kgjoin;
	kern_args[1] = &gjs->m_kmrels;
	kern_args[2] = &outer_depth;
	kern_args[3] = &m_kds_dst;
	kern_args[4] = &m_nullptr;

	rc = cuLaunchKernel(kern_gpujoin_main,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * block_sz,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuLaunchKernel: %s", errorText(rc));

	rc = cuEventRecord(CU_EVENT_PER_THREAD, CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuEventRecord: %s", errorText(rc));

	/* Point of synchronization */
	rc = cuEventSynchronize(CU_EVENT_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuEventSynchronize: %s", errorText(rc));

	memcpy(&pgjoin->task.kerror,
		   &pgjoin->kern.kerror, sizeof(kern_errorbuf));
	if (pgjoin->task.kerror.errcode == ERRCODE_STROM_SUCCESS)
	{
		if (pgjoin->kern.suspend_count > 0)
		{
			CHECK_WORKER_TERMINATION();

			gpujoin_throw_partial_result(pgjoin);
			pds_dst = pgjoin->pds_dst;	/* buffer renew */

			pgjoin->kern.suspend_count = 0;
			pgjoin->kern.resume_context = true;
			if (!last_suspend)
				last_suspend = alloca(pgjoin->kern.suspend_size);
			memcpy(last_suspend,
				   KERN_GPUJOIN_SUSPEND_CONTEXT(&pgjoin->kern, 0),
				   pgjoin->kern.suspend_size);
			goto resume_kernel;
		}
		gpujoinUpdateRunTimeStat(&gjs->gts, &pgjoin->kern);
		/* return task if any result rows */
		retval = (pds_dst->kds.nitems > 0 ? 0 : -1);
	}
	else if (pgstrom_cpu_fallback_enabled &&
			 (pgjoin->task.kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
	{
		memset(&pgjoin->task.kerror, 0, sizeof(kern_errorbuf));
		pgjoin->task.cpu_fallback = true;
		pgjoin->kern.resume_context = (last_suspend != NULL);
		if (last_suspend)
		{
			memcpy(KERN_GPUJOIN_SUSPEND_CONTEXT(&pgjoin->kern, 0),
				   last_suspend,
				   pgjoin->kern.suspend_size);
		}
		retval = 0;
	}
	else
	{
		/* raise an error */
		retval = 0;
	}
	return retval;
}

int
gpujoin_process_task(GpuTask *gtask, CUmodule cuda_module)
{
	GpuJoinTask	   *pgjoin = (GpuJoinTask *) gtask;
	pgstrom_data_store *pds_src = pgjoin->pds_src;
	volatile bool	gstore_mapped = false;
	int				retval;
	CUresult		rc;

	STROM_TRY();
	{
		if (pds_src)
		{
			if (pds_src->kds.format == KDS_FORMAT_COLUMN)
			{
				rc = gpuStoreMapDeviceMemory(GpuWorkerCurrentContext, pds_src);
				if (rc != CUDA_SUCCESS)
					werror("failed on gstoreFdwMapDeviceMemory: %s", errorText(rc));
				gstore_mapped = true;
			}
			retval = gpujoin_process_inner_join(pgjoin, cuda_module);
		}
		else
		{
			retval = gpujoin_process_right_outer(pgjoin, cuda_module);
		}
	}
	STROM_CATCH();
	{
		if (gstore_mapped)
			gpuStoreUnmapDeviceMemory(GpuWorkerCurrentContext, pds_src);
		STROM_RE_THROW();
	}
	STROM_END_TRY();
	if (gstore_mapped)
		gpuStoreUnmapDeviceMemory(GpuWorkerCurrentContext, pds_src);
	return retval;
}

/* ================================================================
 *
 * Routines to preload inner relations (heap/hash)
 *
 * ================================================================
 */

/*
 * calculation of the hash-value
 */
static cl_uint
get_tuple_hashvalue(innerState *istate,
					bool is_inner_hashkeys,
					TupleTableSlot *slot,
					bool *p_is_null_keys)
{
	ExprContext	   *econtext = istate->econtext;
	cl_uint			hash;
	List		   *hash_keys_list;
	ListCell	   *lc;
	bool			is_null_keys = true;

	if (is_inner_hashkeys)
	{
		hash_keys_list = istate->hash_inner_keys;
		econtext->ecxt_innertuple = slot;
	}
	else
	{
		hash_keys_list = istate->hash_outer_keys;
		econtext->ecxt_scantuple = slot;
	}

	/* calculation of a hash value of this entry */
	hash = 0xffffffffU;
	foreach (lc, hash_keys_list)
	{
		ExprState	   *clause = lfirst(lc);
		devtype_info   *dtype;
		Datum			datum;
		bool			isnull;

	    datum = ExecEvalExpr(clause, istate->econtext, &isnull);
		if (isnull)
			continue;
		is_null_keys = false;	/* key contains at least a valid value */

		dtype = pgstrom_devtype_lookup(exprType((Node *)clause->expr));
		Assert(dtype != NULL);

		hash ^= dtype->hash_func(dtype, datum);
	}
	hash ^= 0xffffffffU;

	*p_is_null_keys = is_null_keys;

	return hash;
}

typedef struct
{
	slist_node	chain;
	cl_uint		hash;		/* if hash-preload */
	kern_tupitem titem;
} tupleEntry;

static void
innerPreloadExecOneDepth(GpuJoinState *leader, innerState *istate)
{
	GpuJoinRuntimeStat *gj_rtstat = GPUJOIN_RUNTIME_STAT(leader->gj_sstate);
	int				depth = istate->depth;
	PlanState	   *ps = istate->state;
	TupleTableSlot *slot;
	TupleDesc		tupdesc		__attribute__((unused))
		= planStateResultTupleDesc(ps);

	for (;;)
	{
		HeapTuple	htup;
		tupleEntry *entry;
		cl_uint		hash = 0;
		int			j, k;
		size_t		usage;
		Datum		datum;
		bool		isnull;

		CHECK_FOR_INTERRUPTS();

		slot = ExecProcNode(ps);
		if (TupIsNull(slot))
			break;
		if (bms_is_empty(istate->preload_flatten_attrs))
			htup = ExecFetchSlotHeapTuple(slot, false, false);
		else
		{
			/*
			 * NOTE: If varlena datum is compressed / toasted, obviously,
			 * GPU kernel cannot handle operators that reference these
			 * values. Even though we cannot prevent this kind of datum
			 * in OUTER side, we can fix up preloaded values on INNER-side.
			 */
			slot_getallattrs(slot);
			for (k = bms_next_member(istate->preload_flatten_attrs, -1);
				 k >= 0;
				 k = bms_next_member(istate->preload_flatten_attrs, k))
			{
				j = k + FirstLowInvalidHeapAttributeNumber - 1;

				Assert(tupleDescAttr(tupdesc, j)->attlen == -1);
				if (slot->tts_isnull[j])
					continue;
				slot->tts_values[j] = (Datum)
					PG_DETOAST_DATUM(slot->tts_values[j]);
			}
		}

		/* Save the inner tuple temporaray */
		htup = ExecFetchSlotHeapTuple(slot, false, false);
		if (istate->hash_inner_keys != NIL)
		{
			/*
			 * If join-keys are NULL, it is obvious that this inner tuple
			 * shall not have any matching outer tuples.
			 */
			hash = get_tuple_hashvalue(istate, true, slot, &isnull);
			if (isnull && (istate->join_type == JOIN_INNER ||
						   istate->join_type == JOIN_LEFT))
				continue;
		}
		else if (istate->gist_irel)
		{
			/*
			 * GiST index tries to walk down by index-key, then look up
			 * the entry by CTID.
			 */
			datum = slot_getattr(slot, istate->gist_ctid_resno, &isnull);
			if (isnull)
				elog(ERROR, "GPU GiST: Bug? inner ctid is missing");

			hash = hash_any((unsigned char *)datum,
							sizeof(ItemPointerData));
			memcpy(&htup->t_self, DatumGetPointer(datum),
				   sizeof(ItemPointerData));
		}
		entry = MemoryContextAlloc(leader->preload_memcxt,
								   offsetof(tupleEntry,
											titem.htup) + htup->t_len);
		memset(entry, 0, offsetof(tupleEntry, titem.htup));
		entry->hash = hash;
		entry->titem.t_len = htup->t_len;
		memcpy(&entry->titem.htup, htup->t_data, htup->t_len);
		memcpy(&entry->titem.htup.t_ctid, &htup->t_self, sizeof(ItemPointerData));

		if (istate->hash_inner_keys != NIL ||
			istate->gist_irel != NULL)
			usage = offsetof(kern_hashitem, t.htup) + htup->t_len;
		else
			usage = offsetof(kern_tupitem, htup) + htup->t_len;

		istate->preload_nitems++;
		istate->preload_usage += MAXALIGN(usage);
		slist_push_head(&istate->preload_tuples, &entry->chain);
	}
	pg_atomic_add_fetch_u64(&gj_rtstat->jstat[depth].inner_nrooms,
							istate->preload_nitems);
	pg_atomic_add_fetch_u64(&gj_rtstat->jstat[depth].inner_usage,
							istate->preload_usage);
}

/*
 * innerPreloadAllocHostBuffer
 */
static void
innerPreloadAllocHostBuffer(GpuJoinState *leader)
{
	GpuJoinSharedState *gj_sstate = leader->gj_sstate;
	GpuJoinRuntimeStat *gj_rtstat = GPUJOIN_RUNTIME_STAT(gj_sstate);
	kern_multirels *h_kmrels = NULL;
	kern_data_store *kds = NULL;
	int			num_rels = leader->num_rels;
	size_t		kmrels_ofs;
	size_t		ojmaps_ofs;
	int			i;

	/* already allocated? */
	if (gj_sstate->shmem_bytesize != 0)
		return;

	/*
	 * 1st pass: calculation of buffer length
	 * 2nd pass: initialization of buffer metadata
	 */
restart:
	kmrels_ofs = STROMALIGN(offsetof(kern_multirels, chunks[num_rels]));
	ojmaps_ofs = 0;
	for (i=0; i < num_rels; i++)
	{
		innerState *istate = &leader->inners[i];
		TupleDesc	tupdesc = planStateResultTupleDesc(istate->state);
		size_t		nrooms;
		size_t		usage;
		size_t		nbytes;

		nrooms = pg_atomic_read_u64(&gj_rtstat->jstat[i+1].inner_nrooms);
		usage  = pg_atomic_read_u64(&gj_rtstat->jstat[i+1].inner_usage);
		if (h_kmrels)
		{
			kds = (kern_data_store *)((char *)h_kmrels + kmrels_ofs);
			h_kmrels->chunks[i].chunk_offset = kmrels_ofs;
		}

		nbytes = KDS_calculateHeadSize(tupdesc);
		if (istate->hash_inner_keys != NIL)
		{
			nbytes += (STROMALIGN(sizeof(cl_uint) * nrooms) +
					   STROMALIGN(sizeof(cl_uint) * __KDS_NSLOTS(nrooms)) +
					   STROMALIGN(usage));
			if (h_kmrels)
			{
				init_kernel_data_store(kds, tupdesc, nbytes,
									   KDS_FORMAT_HASH, nrooms);
				kds->nslots = __KDS_NSLOTS(nrooms);
			}
		}
		else if (istate->gist_irel != NULL)
		{
			TupleDesc	itupdesc = RelationGetDescr(istate->gist_irel);
			BlockNumber	nblocks = RelationGetNumberOfBlocks(istate->gist_irel);
			size_t		gist_length;

			nbytes += (STROMALIGN(sizeof(cl_uint) * nrooms) +
					   STROMALIGN(sizeof(cl_uint) * __KDS_NSLOTS(nrooms)) +
					   STROMALIGN(usage));
			/* portion of GiST-index (KDS_FORMAT_BLOCK) */
			gist_length = (KDS_calculateHeadSize(itupdesc) +
						   STROMALIGN(sizeof(BlockNumber) * nblocks) +
						   BLCKSZ * nblocks);
			if (gist_length >= (size_t)UINT_MAX)
				elog(ERROR, "GiST-index (%s) is too large to load GPU memory",
					 RelationGetRelationName(istate->gist_irel));
			if (h_kmrels)
			{
				kern_data_store	   *kds_gist;

				/* KDS-Hash portion */
				init_kernel_data_store(kds, tupdesc, nbytes,
									   KDS_FORMAT_HASH, nrooms);
				kds->nslots = __KDS_NSLOTS(nrooms);

				/* GiST-index portion */
				h_kmrels->chunks[i].gist_offset = (kmrels_ofs + nbytes);
				kds_gist = (kern_data_store *)
					((char *)h_kmrels + h_kmrels->chunks[i].gist_offset);
				init_kernel_data_store(kds_gist, itupdesc, gist_length,
									   KDS_FORMAT_BLOCK, nblocks);
			}
			nbytes += gist_length;
		}
		else
		{
			nbytes += (STROMALIGN(sizeof(cl_uint) * nrooms) +
					   STROMALIGN(usage));
			if (h_kmrels)
			{
				init_kernel_data_store(kds, tupdesc, nbytes,
									   KDS_FORMAT_ROW, nrooms);
				h_kmrels->chunks[i].is_nestloop = true;
			}
		}
		kmrels_ofs += nbytes;

		if (istate->join_type == JOIN_RIGHT ||
            istate->join_type == JOIN_FULL)
		{
			if (h_kmrels)
			{
				h_kmrels->chunks[i].right_outer = true;
				h_kmrels->chunks[i].ojmap_offset = ojmaps_ofs;
			}
			ojmaps_ofs += STROMALIGN(nrooms);
		}
		if (istate->join_type == JOIN_LEFT ||
            istate->join_type == JOIN_FULL)
		{
			if (h_kmrels)
				h_kmrels->chunks[i].left_outer = true;
		}
	}

	/*
	 * allocation of the host inner-buffer
	 */
	if (!h_kmrels)
	{
		size_t	bytesize = TYPEALIGN(PAGE_SIZE, kmrels_ofs + ojmaps_ofs);
		int		fdesc;
		char	name[200];

		snprintf(name, sizeof(name), "gpujoin_kmrels.%u.%08x.buf",
				 PostPortNumber, gj_sstate->shmem_handle);
		fdesc = shm_open(name, O_RDWR | O_TRUNC, 0);
		if (fdesc < 0)
			elog(ERROR, "failed on shm_open('%s'): %m", name);
		if (fallocate(fdesc, 0, 0, bytesize) != 0)
		{
			close(fdesc);
			elog(ERROR, "failed on fallocate('%s'): %m", name);
		}
		h_kmrels = __mmapFile(NULL, bytesize,
							  PROT_READ | PROT_WRITE,
							  MAP_SHARED,
							  fdesc, 0);
		if (h_kmrels == MAP_FAILED)
		{
			close(fdesc);
			elog(ERROR, "failed on mmap('%s'): %m", name);
		}
		close(fdesc);
		gj_sstate->shmem_bytesize = bytesize;

		memset(h_kmrels, 0, offsetof(kern_multirels, chunks[num_rels]));
		h_kmrels->kmrels_length = kmrels_ofs;
		h_kmrels->ojmaps_length = ojmaps_ofs;
		h_kmrels->cuda_dindex = 0;		/* deprecated parameter? */
		h_kmrels->nrels = num_rels;

		goto restart;
	}
	leader->h_kmrels = h_kmrels;
}

static void
__innerPreloadSetupHeapBuffer(kern_data_store *kds,
							  innerState *istate,
							  cl_uint base_nitems,
							  cl_uint base_usage)
{
	slist_iter	iter;
	cl_uint	   *row_index = KERN_DATA_STORE_ROWINDEX(kds);
	size_t		rowid = base_nitems;
	char	   *tail_pos;
	char	   *curr_pos;

	tail_pos = (char *)kds + kds->length - __kds_unpack(base_usage);
	curr_pos = tail_pos;
	slist_foreach (iter, &istate->preload_tuples)
	{
		tupleEntry *entry = slist_container(tupleEntry, chain, iter.cur);
		size_t		sz = MAXALIGN(offsetof(kern_tupitem,
										   htup) + entry->titem.t_len);
		kern_tupitem *titem = (kern_tupitem *)(curr_pos - sz);

		Assert(entry->hash == 0);
		memcpy(titem, &entry->titem,
			   offsetof(kern_tupitem, htup) + entry->titem.t_len);
		titem->rowid = rowid;
		row_index[rowid++] = __kds_packed((char *)titem - (char *)kds);
		curr_pos -= sz;
	}
	Assert(istate->preload_nitems == (rowid - base_nitems));
	Assert(istate->preload_usage == (tail_pos - curr_pos));
}

static void
__innerPreloadSetupHashBuffer(kern_data_store *kds,
							  innerState *istate,
							  cl_uint base_nitems,
							  cl_uint base_usage)
{
	cl_uint	   *row_index = KERN_DATA_STORE_ROWINDEX(kds);
	cl_uint	   *hash_slot = KERN_DATA_STORE_HASHSLOT(kds);
	size_t		rowid = base_nitems;
	char	   *tail_pos;
	char	   *curr_pos;
	slist_iter	iter;
	
	tail_pos = (char *)kds + kds->length - __kds_unpack(base_usage);
	curr_pos = tail_pos;
	slist_foreach (iter, &istate->preload_tuples)
	{
		tupleEntry *entry = slist_container(tupleEntry, chain, iter.cur);
		size_t		sz = MAXALIGN(offsetof(kern_hashitem,
										   t.htup) + entry->titem.t_len);
		kern_hashitem *hitem = (kern_hashitem *)(curr_pos - sz);
		size_t		hindex = entry->hash % kds->nslots;
		cl_uint		next, self;

		self = __kds_packed((char *)hitem - (char *)kds);
		__atomic_exchange(&hash_slot[hindex], &self, &next,
						  __ATOMIC_SEQ_CST);
		hitem->hash = entry->hash;
		hitem->next = next;
		memcpy(&hitem->t, &entry->titem,
			   offsetof(kern_tupitem, htup) + entry->titem.t_len);
		hitem->t.rowid = rowid;
		row_index[rowid++] = __kds_packed((char *)&hitem->t - (char *)kds);

		curr_pos -= sz;
	}
	Assert(istate->preload_nitems == (rowid - base_nitems));
	Assert(istate->preload_usage == (tail_pos - curr_pos));
}

static void
__innerPreloadSetupGiSTIndexWalker(char *base,
								   BlockNumber blkno,
								   BlockNumber nblocks,
								   BlockNumber parent_blkno,
								   OffsetNumber parent_offno)
{
	Page			page = (Page)(base + BLCKSZ * blkno);
	PageHeader		hpage = (PageHeader) page;
	GISTPageOpaque	op = GistPageGetOpaque(page);
	OffsetNumber	i, maxoff;

	Assert(hpage->pd_lsn.xlogid == InvalidBlockNumber &&
		   hpage->pd_lsn.xrecoff == InvalidOffsetNumber);
	hpage->pd_lsn.xlogid = parent_blkno;
	hpage->pd_lsn.xrecoff = parent_offno;
	if ((op->flags & F_LEAF) != 0)
		return;
	maxoff = PageGetMaxOffsetNumber(page);
	for (i=FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
	{
		ItemId		iid = PageGetItemId(page, i);
        IndexTuple	it;
		BlockNumber	child;

		if (ItemIdIsDead(iid))
			continue;
		it = (IndexTuple) PageGetItem(page, iid);
		child = BlockIdGetBlockNumber(&it->t_tid.ip_blkid);
		if (child < nblocks)
			__innerPreloadSetupGiSTIndexWalker(base, child, nblocks, blkno, i);
	}
}

static void
__innerPreloadSetupGiSTIndexBuffer(innerState *istate,
								   kern_data_store *kds_gist)
{
	Relation	irel = istate->gist_irel;
	char	   *base = (char *)KERN_DATA_STORE_BLOCK_PGPAGE(kds_gist, 0);
	BlockNumber *block_nr = (BlockNumber *)KERN_DATA_STORE_BODY(kds_gist);
	BlockNumber	i;

	if (irel->rd_amhandler != F_GISTHANDLER)
		elog(ERROR, "Bug? index '%s' is not GiST index",
			 RelationGetRelationName(irel));
	for (i=0; i < kds_gist->nrooms; i++)
	{
		Buffer		buffer;
		Page		page;
		PageHeader	hpage;

		buffer = ReadBuffer(irel, i);
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);
		hpage = (PageHeader)(base + BLCKSZ * i);

		memcpy(hpage, page, BLCKSZ);
		hpage->pd_lsn.xlogid = InvalidBlockNumber;
		hpage->pd_lsn.xrecoff = InvalidOffsetNumber;
		block_nr[i] = i;

		UnlockReleaseBuffer(buffer);
	}
	__innerPreloadSetupGiSTIndexWalker(base, 0, kds_gist->nrooms,
									   InvalidBlockNumber,
									   InvalidOffsetNumber);
}

static kern_multirels *
innerPreloadMmapHostBuffer(GpuJoinState *leader, GpuJoinState *gjs)
{
	GpuJoinSharedState *gj_sstate = leader->gj_sstate;
	kern_multirels *h_kmrels;
	char		name[200];
	int			fdesc;
	struct stat	stat_buf;

	/* already mapped? */
	if (gjs->h_kmrels)
		return gjs->h_kmrels;

	/* already mapped by the siblings? */
	if (leader->h_kmrels)
	{
		gjs->h_kmrels = leader->h_kmrels;
		return gjs->h_kmrels;
	}

	/* mmap host buffer */
	snprintf(name, sizeof(name), "gpujoin_kmrels.%u.%08x.buf",
			 PostPortNumber, gj_sstate->shmem_handle);
	fdesc = shm_open(name, O_RDWR, 0);
	if (fdesc < 0)
		elog(ERROR, "failed on shm_open('%s'): %m", name);
	if (fstat(fdesc, &stat_buf) != 0)
	{
		close(fdesc);
		elog(ERROR, "failed on fstat('%s'): %m", name);
	}
	Assert(stat_buf.st_size == gj_sstate->shmem_bytesize);

	h_kmrels = __mmapFile(NULL, TYPEALIGN(PAGE_SIZE, stat_buf.st_size),
						  PROT_READ | PROT_WRITE,
						  MAP_SHARED,
						  fdesc, 0);
	if (h_kmrels == MAP_FAILED)
	{
		close(fdesc);
		elog(ERROR, "failed on mmap('%s'): %m", name);
	}
	close(fdesc);

	/* simple sanity checks */
	if (h_kmrels->kmrels_length +
		h_kmrels->ojmaps_length > stat_buf.st_size)
		elog(ERROR, "Bug? filesize of '%s' is smaller than host buffer", name);
	leader->h_kmrels = gjs->h_kmrels = h_kmrels;

	return h_kmrels;
}

static void
__innerPreloadInitGiSTIndex(GpuJoinState *gjs, CUdeviceptr m_kmrels)
{
	GpuContext	   *gcontext = gjs->gts.gcontext;
	CUmodule		cuda_module = NULL;
	CUfunction		f_prep_gistindex = NULL;
	CUresult		rc;
	void		   *kern_args[2];
	cl_int			grid_sz;
	cl_int			block_sz;
	cl_int			depth;

	for (depth=1; depth <= gjs->num_rels; depth++)
	{
		if (!gjs->inners[depth-1].gist_irel)
			continue;
		/* load the CUDA module and function */
		if (!cuda_module)
		{
			cuda_module = GpuContextLookupModule(gcontext,
												 gjs->gts.program_id);
           rc = cuModuleGetFunction(&f_prep_gistindex,
                                    cuda_module,
                                    "gpujoin_prep_gistindex");
           if (rc != CUDA_SUCCESS)
               elog(ERROR, "failed on cuModuleGetFunction: %s", errorText(rc));
           rc = gpuOptimalBlockSize(&grid_sz,
                                    &block_sz,
                                    f_prep_gistindex,
                                    gcontext->cuda_device,
                                    0, 0);
          if (rc != CUDA_SUCCESS)
               elog(ERROR, "failed on gpuOptimalBlockSize: %s", errorText(rc));
       }
       /* launch kern_gpujoin_prep_gistindex */
       kern_args[0] = &m_kmrels;
       kern_args[1] = &depth;

       rc = cuLaunchKernel(f_prep_gistindex,
                           grid_sz, 1, 1,
                           block_sz, 1, 1,
                           0,
                           CU_STREAM_PER_THREAD,
                           kern_args,
                           NULL);
       if (rc != CUDA_SUCCESS)
           elog(ERROR, "failed on cuLaunchKernel: %s", errorText(rc));
   }

   if (cuda_module)
   {
       rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
       if (rc != CUDA_SUCCESS)
           elog(ERROR, "failed on cuStreamSynchronize: %s", errorText(rc));
   }
}

static void
innerPreloadLoadDeviceBuffer(GpuJoinState *leader,
							 GpuJoinState *gjs)
{
	GpuContext	   *gcontext = gjs->gts.gcontext;
	GpuJoinSiblingState *sibling = gjs->sibling;
	GpuJoinSharedState *gj_sstate = leader->gj_sstate;
	kern_multirels *h_kmrels = gjs->h_kmrels;
	int				dindex = gcontext->cuda_dindex;

	Assert(leader->sibling == gjs->sibling);	
	if (sibling && sibling->pergpu[dindex].m_kmrels != 0UL)
	{
		/*
		 * In case of asymmetric partition-wise join, any of siblings
		 * might already setup device buffer. Please note that leader
		 * GpuJoinState prefers different GPU device from the current one.
		 */
		gjs->m_kmrels = sibling->pergpu[dindex].m_kmrels;
		gjs->m_kmrels_owner = false;
	}
	else if (gj_sstate->pergpu[dindex].bytesize == 0)
	{
		CUdeviceptr		m_kmrels;
		CUresult		rc;
		size_t	bytesize = (h_kmrels->kmrels_length +
							h_kmrels->ojmaps_length);

		rc = gpuMemAllocPreserved(dindex,
								  &gj_sstate->pergpu[dindex].ipc_mhandle,
								  bytesize);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on gpuMemAllocPreserved: %s", errorText(rc));
		gj_sstate->pergpu[dindex].bytesize = bytesize;

		rc = gpuIpcOpenMemHandle(gcontext,
								 &m_kmrels,
								 gj_sstate->pergpu[dindex].ipc_mhandle,
								 CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on gpuIpcOpenMemHandle: %s", errorText(rc));

		GPUCONTEXT_PUSH(gcontext);
		rc = cuMemcpyHtoD(m_kmrels, h_kmrels, bytesize);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuMemcpyHtoD: %s", errorText(rc));
		__innerPreloadInitGiSTIndex(gjs, m_kmrels);
		GPUCONTEXT_POP(gcontext);

		gjs->m_kmrels = m_kmrels;
		gjs->m_kmrels_owner = true;
		if (sibling)
			sibling->pergpu[dindex].m_kmrels = m_kmrels;
		/* add colocation count for each GPU device */
		pg_atomic_fetch_add_u32(&gj_sstate->needs_colocation, 1);
		gj_sstate->curr_outer_depth = -1;
	}
	else
	{
		CUdeviceptr		m_kmrels;
		CUresult		rc;

		rc = gpuIpcOpenMemHandle(gcontext,
								 &m_kmrels,
								 gj_sstate->pergpu[dindex].ipc_mhandle,
								 CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on gpuIpcOpenMemHandle: %s", errorText(rc));

		gjs->m_kmrels = m_kmrels;
		gjs->m_kmrels_owner = true;
		if (sibling)
			sibling->pergpu[dindex].m_kmrels = m_kmrels;
	}
}

bool
GpuJoinInnerPreload(GpuTaskState *gts, CUdeviceptr *p_m_kmrels)
{
	GpuJoinState   *gjs = (GpuJoinState *)gts;
	GpuJoinState   *leader;
	GpuContext	   *gcontext = gjs->gts.gcontext;
	GpuJoinSharedState *gj_sstate;
	kern_multirels *h_kmrels = NULL;
	int				i, dindex = gcontext->cuda_dindex;

	
	/* Quick exit, if inner-buffer is now available */
	if (gjs->m_kmrels != 0UL)
	{
		Assert(gjs->gj_sstate != NULL);
		if (p_m_kmrels)
			*p_m_kmrels = gjs->m_kmrels;
		return (gjs->h_kmrels != NULL);
	}

	/* Allocation of a 'fake' shared-state, if single process */
	if (!gjs->gj_sstate)
		createGpuJoinSharedState(gjs, NULL, NULL);

	/*
	 * In case of asymmetric partition-wise join, inner-nodes shall be
	 * distributed for each partition leaf, and we have to build inner
	 * heap/hash buffer from a particular inner node, to avoid read
	 * duplication.
	 */
	if (gjs->sibling)
		leader = gjs->sibling->leader;
	else
		leader = gjs;
	gj_sstate = leader->gj_sstate;

	/*
	 * Inner PreLoad State Machine
	 */
	SpinLockAcquire(&gj_sstate->mutex);
	switch (gj_sstate->phase)
	{
		case INNER_PHASE__SCAN_RELATIONS:
			if (gjs->inner_parallel ||
				gj_sstate->nr_workers_scanning == 0)
			{
				gj_sstate->nr_workers_scanning++;
				SpinLockRelease(&gj_sstate->mutex);

				/*
				 * Scan inner relations, often in parallel
				 */
				for (i=0; i < leader->num_rels; i++)
					innerPreloadExecOneDepth(leader, &leader->inners[i]);

				/*
				 * Once (parallel) scan completed, no other concurrent
				 * workers will not be able to fetch any records from
				 * the inner relations.
				 * So, 'phase' shall be switched to WAIT_FOR_SCANNING
				 * to prevent other worker try to start inner scan.
				 */
				SpinLockAcquire(&gj_sstate->mutex);
				if (gj_sstate->phase == INNER_PHASE__SCAN_RELATIONS)
					gj_sstate->phase = INNER_PHASE__SETUP_BUFFERS;
				else
					Assert(gj_sstate->phase == INNER_PHASE__SETUP_BUFFERS);
				/*
				 * Wake up any other concurrent workers, if current
				 * process is the last guy who tried to scan inner
				 * relations.
				 */
				if (--gj_sstate->nr_workers_scanning == 0)
					ConditionVariableBroadcast(&gj_sstate->cond);
			}
			/* Falls through. */
		case INNER_PHASE__SETUP_BUFFERS:
			/*
			 * Wait for completion of other workers that still scan
			 * the inner relations.
			 */
			gj_sstate->nr_workers_setup++;
			if (gj_sstate->phase == INNER_PHASE__SCAN_RELATIONS ||
				gj_sstate->nr_workers_scanning > 0)
			{
				ConditionVariablePrepareToSleep(&gj_sstate->cond);
				while (gj_sstate->phase == INNER_PHASE__SCAN_RELATIONS ||
					   gj_sstate->nr_workers_scanning > 0)
				{
					SpinLockRelease(&gj_sstate->mutex);
					ConditionVariableSleep(&gj_sstate->cond,
										   PG_WAIT_EXTENSION);
					SpinLockAcquire(&gj_sstate->mutex);
				}
				ConditionVariableCancelSleep();
			}
			/*
			 * Allocation of the host inner buffer, if not yet
			 */
			PG_TRY();
			{
				innerPreloadAllocHostBuffer(leader);
			}
			PG_CATCH();
			{
				SpinLockRelease(&gj_sstate->mutex);
				PG_RE_THROW();
			}
			PG_END_TRY();
			SpinLockRelease(&gj_sstate->mutex);

			/*
			 * Setup  host inner buffer
			 */
			h_kmrels = innerPreloadMmapHostBuffer(leader, gjs);
			for (i=0; i < leader->num_rels; i++)
			{
				innerState *istate = &leader->inners[i];
				kern_data_store *kds = KERN_MULTIRELS_INNER_KDS(h_kmrels, i+1);
				cl_uint		nitems_base;
				cl_uint		usage_base;

				SpinLockAcquire(&gj_sstate->mutex);
				nitems_base = kds->nitems;
				kds->nitems += istate->preload_nitems;
				usage_base  = kds->usage;
				kds->usage  += __kds_packed(istate->preload_usage);
				SpinLockRelease(&gj_sstate->mutex);

				if (kds->format == KDS_FORMAT_ROW)
					__innerPreloadSetupHeapBuffer(kds, istate,
												  nitems_base,
												  usage_base);
				else if (kds->format == KDS_FORMAT_HASH)
					__innerPreloadSetupHashBuffer(kds, istate,
												  nitems_base,
												  usage_base);
				else
					elog(ERROR, "unexpected inner-KDS format");
				
				/* reset local buffer */
				istate->preload_nitems = 0;
				istate->preload_usage = 0;
				slist_init(&istate->preload_tuples);
			}
			MemoryContextReset(gjs->preload_memcxt);

			/*
			 * Wait for completion of the host buffer setup
			 * by other concurrent workers
			 */
			SpinLockAcquire(&gj_sstate->mutex);
			gj_sstate->nr_workers_setup--;
			if (gj_sstate->nr_workers_scanning == 0 &&
				gj_sstate->nr_workers_setup == 0)
			{
				Assert(gj_sstate->phase == INNER_PHASE__SETUP_BUFFERS);
				/* preload GiST index buffer, if any */
				for (i=0; i < leader->num_rels; i++)
				{
					innerState *istate = &leader->inners[i];
					kern_data_store *kds_gist;

					if (!istate->gist_irel)
						continue;
					kds_gist = (kern_data_store *)
						((char *)h_kmrels + h_kmrels->chunks[i].gist_offset);
					__innerPreloadSetupGiSTIndexBuffer(istate, kds_gist);
				}
				gj_sstate->phase = INNER_PHASE__GPUJOIN_EXEC;
				ConditionVariableBroadcast(&gj_sstate->cond);
			}
			else
			{
				ConditionVariablePrepareToSleep(&gj_sstate->cond);
				while (gj_sstate->nr_workers_scanning > 0 ||
					   gj_sstate->nr_workers_setup > 0)
				{
					SpinLockRelease(&gj_sstate->mutex);
					ConditionVariableSleep(&gj_sstate->cond,
										   PG_WAIT_EXTENSION);
					SpinLockAcquire(&gj_sstate->mutex);
				}
				ConditionVariableCancelSleep();
			}
			/* Falls through. */

		case INNER_PHASE__GPUJOIN_EXEC:
			(void)innerPreloadMmapHostBuffer(leader, gjs);
			/*
			 * If any of backend/workers already reached to the end of
			 * outer relation, no need to load the inner buffer to make
			 * an empty result.
			 */
			if (pg_atomic_read_u32(&gjs->gj_sstate->outer_scan_done) == 0)
			{
				gj_sstate->pergpu[dindex].nr_workers_gpujoin++;
				PG_TRY();
				{
					innerPreloadLoadDeviceBuffer(leader, gjs);
				}
				PG_CATCH();
				{
					SpinLockRelease(&gj_sstate->mutex);
					PG_RE_THROW();
				}
				PG_END_TRY();
			}
			break;

		default:
			SpinLockRelease(&gj_sstate->mutex);
			elog(ERROR, "GpuJoin: unexpected inner buffer phase");
			break;
	}
	SpinLockRelease(&gj_sstate->mutex);

	/*
	 * Any backend or worker process, that tried to fetch the inner buffer
	 * after the 'phase' is switched to INNER_PHASE__GPUJOIN_CLOSING, shall
	 * not contribute any task of GpuJoin, so it returns false for
	 * immediate exit.
	 */
	if (p_m_kmrels)
		*p_m_kmrels = gjs->m_kmrels;
	return (gjs->m_kmrels != 0UL);
}

/*
 * GpuJoinInnerUnload
 */
void
GpuJoinInnerUnload(GpuTaskState *gts, bool is_rescan)
{
	GpuJoinState   *gjs = (GpuJoinState *) gts;
	GpuJoinSharedState *gj_sstate = gjs->gj_sstate;
	GpuContext	   *gcontext = gjs->gts.gcontext;
	CUresult		rc;
	int				dindex;

	if (gjs->m_kmrels)
	{
		if (gjs->m_kmrels_owner)
		{
			rc = gpuIpcCloseMemHandle(gcontext, gjs->m_kmrels);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on gpuIpcCloseMemHandle: %s",
					 errorText(rc));
		}
		gjs->m_kmrels = 0UL;
	}

	if (gjs->h_kmrels)
	{
		if (!gjs->sibling || gjs->sibling->leader == gjs)
		{
			if (__munmapFile(gjs->h_kmrels) != 0)
				elog(WARNING, "failed on __munmapFile: %m");
		}
		gjs->h_kmrels = NULL;
	}

	if (gj_sstate && !IsParallelWorker())
	{
		char		name[200];
		
		for (dindex=0; dindex < numDevAttrs; dindex++)
		{
			if (gj_sstate->pergpu[dindex].bytesize == 0)
				continue;
			rc = gpuMemFreePreserved(dindex,
									 gj_sstate->pergpu[dindex].ipc_mhandle);
			if (rc != CUDA_SUCCESS)
				elog(WARNING, "failed on gpuMemFreePreserved: %s",
					 errorText(rc));
			gj_sstate->pergpu[dindex].bytesize = 0;
		}

		if (gj_sstate->shmem_handle != UINT_MAX)
		{
			snprintf(name, sizeof(name), "gpujoin_kmrels.%u.%08x.buf",
					 PostPortNumber, gj_sstate->shmem_handle);
			if (shm_unlink(name) != 0)
				elog(WARNING, "failed on shm_unlink('%s'): %m", name);
			gj_sstate->shmem_handle = UINT_MAX;
		}
	}
	gjs->h_kmrels = NULL;
	gjs->m_kmrels = 0UL;
	gjs->m_kmrels_owner = false;
}

/*
 * createGpuJoinSharedState
 *
 * It construct an empty inner multi-relations buffer. It can be shared with
 * multiple backends, and referenced by CPU/GPU.
 */
static void
createGpuJoinSharedState(GpuJoinState *gjs,
						 ParallelContext *pcxt,
						 void *dsm_addr)
{
	EState	   *estate = gjs->gts.css.ss.ps.state;
	GpuJoinSharedState *gj_sstate;
	GpuJoinRuntimeStat *gj_rtstat;
	cl_uint		shmem_handle;
	int			fdesc = -1;
	char		name[200];
	size_t		ss_length;

	Assert(!IsParallelWorker());
	/*
	 * creation of the host inner buffer, but fallocate(2) and mmap(2)
	 * shall be done after the inner-preloading.
	 */
	while (fdesc < 0)
	{
		shmem_handle = random();
		if (shmem_handle == UINT_MAX)
			continue;
		snprintf(name, sizeof(name), "gpujoin_kmrels.%u.%08x.buf",
				 PostPortNumber, shmem_handle);
		fdesc = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fdesc < 0 && errno != EEXIST)
			elog(ERROR, "failed on shm_open('%s'): %m", name);
	}
	close(fdesc);

	/* allocation of the GpuJoinSharedState */
	ss_length = (MAXALIGN(offsetof(GpuJoinSharedState,
								   pergpu[numDevAttrs])) +
				 MAXALIGN(offsetof(GpuJoinRuntimeStat,
								   jstat[gjs->num_rels + 1])));
	if (dsm_addr)
		gj_sstate = dsm_addr;
	else
		gj_sstate = MemoryContextAlloc(estate->es_query_cxt, ss_length);
	memset(gj_sstate, 0, ss_length);
	gj_sstate->ss_handle = (pcxt ? dsm_segment_handle(pcxt->seg) : UINT_MAX);
	gj_sstate->ss_length = ss_length;
	gj_sstate->shmem_handle = shmem_handle;
	ConditionVariableInit(&gj_sstate->cond);
	SpinLockInit(&gj_sstate->mutex);
	gj_sstate->phase = INNER_PHASE__SCAN_RELATIONS;
	gj_sstate->nr_workers_scanning = 0;
	gj_sstate->nr_workers_setup = 0;
	pg_atomic_init_u32(&gj_sstate->outer_scan_done, 0);
	pg_atomic_init_u32(&gj_sstate->needs_colocation, 0);

	gj_rtstat = GPUJOIN_RUNTIME_STAT(gj_sstate);
	SpinLockInit(&gj_rtstat->c.lock);

	gjs->gj_sstate = gj_sstate;
}

/*
 * cleanupGpuJoinSharedStateOnAbort
 */
static void
cleanupGpuJoinSharedStateOnAbort(dsm_segment *seg, Datum ptr)
{
	GpuJoinSharedState *gj_sstate = (GpuJoinSharedState *)DatumGetPointer(ptr);
	char		name[200];
	int			dindex;
	CUresult	rc;

	for (dindex=0; dindex < numDevAttrs; dindex++)
	{
		if (gj_sstate->pergpu[dindex].bytesize == 0)
			continue;
		rc = gpuMemFreePreserved(dindex,
								 gj_sstate->pergpu[dindex].ipc_mhandle);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on gpuMemFreePreserved: %s",
				 errorText(rc));
		gj_sstate->pergpu[dindex].bytesize = 0;
	}

	if (gj_sstate->shmem_handle != UINT_MAX)
	{
		snprintf(name, sizeof(name), "gpujoin_kmrels.%u.%08x.buf",
				 PostPortNumber, gj_sstate->shmem_handle);
		if (shm_unlink(name) != 0)
			elog(WARNING, "failed on shm_unlink('%s'): %m", name);
		gj_sstate->shmem_handle = UINT_MAX;
	}
}

/*
 * pgstrom_init_gpujoin
 *
 * Entrypoint of GpuJoin
 */
void
pgstrom_init_gpujoin(void)
{
	/* turn on/off gpunestloop */
	DefineCustomBoolVariable("pg_strom.enable_gpunestloop",
							 "Enables the use of GpuNestLoop logic",
							 NULL,
							 &enable_gpunestloop,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* turn on/off gpuhashjoin */
	DefineCustomBoolVariable("pg_strom.enable_gpuhashjoin",
							 "Enables the use of GpuHashJoin logic",
							 NULL,
							 &enable_gpuhashjoin,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
#if PG_VERSION_NUM >= 110000
	/* turn on/off partition wise gpujoin */
	DefineCustomBoolVariable("pg_strom.enable_partitionwise_gpujoin",
							 "(EXPERIMENTAL) Enables partition wise GpuJoin",
							 NULL,
							 &enable_partitionwise_gpujoin,
							 true,
							 PGC_USERSET,
                             GUC_NOT_IN_SAMPLE,
                             NULL, NULL, NULL);
#else
	enable_partitionwise_gpujoin = false;
#endif
	/* setup path methods */
	gpujoin_path_methods.CustomName				= "GpuJoin";
	gpujoin_path_methods.PlanCustomPath			= PlanGpuJoinPath;

	/* setup plan methods */
	gpujoin_plan_methods.CustomName				= "GpuJoin";
	gpujoin_plan_methods.CreateCustomScanState	= gpujoin_create_scan_state;
	RegisterCustomScanMethods(&gpujoin_plan_methods);

	/* setup exec methods */
	gpujoin_exec_methods.CustomName				= "GpuJoin";
	gpujoin_exec_methods.BeginCustomScan		= ExecInitGpuJoin;
	gpujoin_exec_methods.ExecCustomScan			= ExecGpuJoin;
	gpujoin_exec_methods.EndCustomScan			= ExecEndGpuJoin;
	gpujoin_exec_methods.ReScanCustomScan		= ExecReScanGpuJoin;
	gpujoin_exec_methods.MarkPosCustomScan		= NULL;
	gpujoin_exec_methods.RestrPosCustomScan		= NULL;
	gpujoin_exec_methods.EstimateDSMCustomScan  = ExecGpuJoinEstimateDSM;
	gpujoin_exec_methods.InitializeDSMCustomScan = ExecGpuJoinInitDSM;
	gpujoin_exec_methods.InitializeWorkerCustomScan = ExecGpuJoinInitWorker;
	gpujoin_exec_methods.ReInitializeDSMCustomScan = ExecGpuJoinReInitializeDSM;
	gpujoin_exec_methods.ShutdownCustomScan		= ExecShutdownGpuJoin;
	gpujoin_exec_methods.ExplainCustomScan		= ExplainGpuJoin;

	/* hook registration */
	set_join_pathlist_next = set_join_pathlist_hook;
	set_join_pathlist_hook = gpujoin_add_join_path;
}
