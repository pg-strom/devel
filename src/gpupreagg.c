/*
 * gpupreagg.c
 *
 * Aggregate Pre-processing with GPU acceleration
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
#include "cuda_gpupreagg.h"

static create_upper_paths_hook_type create_upper_paths_next;
static CustomPathMethods	gpupreagg_path_methods;
static CustomScanMethods	gpupreagg_scan_methods;
static CustomExecMethods	gpupreagg_exec_methods;
static bool					enable_gpupreagg;				/* GUC */
static bool					enable_pullup_outer_join;		/* GUC */
static bool					enable_partitionwise_gpupreagg;	/* GUC */
static bool					enable_numeric_aggfuncs; 		/* GUC */
static double				gpupreagg_reduction_threshold;	/* GUC */

typedef struct
{
	cl_int			num_group_keys;	/* number of grouping keys */
	double			plan_ngroups;	/* planned number of groups */
	cl_int			plan_nchunks;	/* planned number of chunks */
	cl_int			plan_extra_sz;	/* planned size of extra-sz per tuple */
	Cost			outer_startup_cost; /* copy of @startup_cost in outer */
	Cost			outer_total_cost; /* copy of @total_cost in outer path */
	double			outer_nrows;	/* number of estimated outer nrows */
	int				outer_width;	/* copy of @plan_width in outer path */
	cl_uint			outer_nrows_per_block;
	Index			outer_scanrelid;/* RTI, if outer path pulled up */
	List		   *outer_quals;	/* device executable quals of outer-scan */
	List		   *outer_refs;		/* referenced columns */
	Oid				index_oid;		/* OID of BRIN-index, if any */
	List		   *index_conds;	/* BRIN-index key conditions */
	List		   *index_quals;	/* Original BRIN-index qualifiers */
	List		   *tlist_fallback;	/* projection from outer-tlist to GPU's
									 * initial projection; note that setrefs.c
									 * should not update this field */
	int				optimal_gpu;
	char		   *kern_source;
	cl_uint			extra_flags;
	cl_uint			varlena_bufsz;
	List		   *used_params;	/* referenced Const/Param */
} GpuPreAggInfo;

static inline void
form_gpupreagg_info(CustomScan *cscan, GpuPreAggInfo *gpa_info)
{
	List	   *privs = NIL;
	List	   *exprs = NIL;

	privs = lappend(privs, makeInteger(gpa_info->num_group_keys));
	privs = lappend(privs, pmakeFloat(gpa_info->plan_ngroups));
	privs = lappend(privs, makeInteger(gpa_info->plan_nchunks));
	privs = lappend(privs, makeInteger(gpa_info->plan_extra_sz));
	privs = lappend(privs, pmakeFloat(gpa_info->outer_startup_cost));
	privs = lappend(privs, pmakeFloat(gpa_info->outer_total_cost));
	privs = lappend(privs, pmakeFloat(gpa_info->outer_nrows));
	privs = lappend(privs, makeInteger(gpa_info->outer_width));
	privs = lappend(privs, makeInteger(gpa_info->outer_nrows_per_block));
	privs = lappend(privs, makeInteger(gpa_info->outer_scanrelid));
	exprs = lappend(exprs, gpa_info->outer_quals);
	privs = lappend(privs, gpa_info->outer_refs);
	privs = lappend(privs, makeInteger(gpa_info->index_oid));
	privs = lappend(privs, gpa_info->index_conds);
	exprs = lappend(exprs, gpa_info->index_quals);
	privs = lappend(privs, gpa_info->tlist_fallback);
	privs = lappend(privs, makeInteger(gpa_info->optimal_gpu));
	privs = lappend(privs, makeString(gpa_info->kern_source));
	privs = lappend(privs, makeInteger(gpa_info->extra_flags));
	privs = lappend(privs, makeInteger(gpa_info->varlena_bufsz));
	exprs = lappend(exprs, gpa_info->used_params);

	cscan->custom_private = privs;
	cscan->custom_exprs = exprs;
}

static inline GpuPreAggInfo *
deform_gpupreagg_info(CustomScan *cscan)
{
	GpuPreAggInfo *gpa_info = palloc0(sizeof(GpuPreAggInfo));
	List	   *privs = cscan->custom_private;
	List	   *exprs = cscan->custom_exprs;
	int			pindex = 0;
	int			eindex = 0;

	gpa_info->num_group_keys = intVal(list_nth(privs, pindex++));
	gpa_info->plan_ngroups = floatVal(list_nth(privs, pindex++));
	gpa_info->plan_nchunks = intVal(list_nth(privs, pindex++));
	gpa_info->plan_extra_sz = intVal(list_nth(privs, pindex++));
	gpa_info->outer_startup_cost = floatVal(list_nth(privs, pindex++));
	gpa_info->outer_total_cost = floatVal(list_nth(privs, pindex++));
	gpa_info->outer_nrows = floatVal(list_nth(privs, pindex++));
	gpa_info->outer_width = intVal(list_nth(privs, pindex++));
	gpa_info->outer_nrows_per_block = intVal(list_nth(privs, pindex++));
	gpa_info->outer_scanrelid = intVal(list_nth(privs, pindex++));
	gpa_info->outer_quals = list_nth(exprs, eindex++);
	gpa_info->outer_refs = list_nth(privs, pindex++);
	gpa_info->index_oid = intVal(list_nth(privs, pindex++));
	gpa_info->index_conds = list_nth(privs, pindex++);
	gpa_info->index_quals = list_nth(exprs, eindex++);
	gpa_info->tlist_fallback = list_nth(privs, pindex++);
	gpa_info->optimal_gpu = intVal(list_nth(privs, pindex++));
	gpa_info->kern_source = strVal(list_nth(privs, pindex++));
	gpa_info->extra_flags = intVal(list_nth(privs, pindex++));
	gpa_info->varlena_bufsz = intVal(list_nth(privs, pindex++));
	gpa_info->used_params = list_nth(exprs, eindex++);
	Assert(pindex == list_length(privs));
	Assert(eindex == list_length(exprs));

	return gpa_info;
}

/*
 * GpuPreAggSharedState - to be allocated on DSM
 */
typedef struct
{
	GpuTaskState	gts;
	struct GpuPreAggSharedState *gpa_sstate;
	struct GpuPreAggRuntimeStat *gpa_rtstat;
	cl_bool			combined_gpujoin;
	cl_bool			terminator_done;
	cl_int			num_group_keys;
	TupleTableSlot *gpreagg_slot;	/* Slot reflects tlist_dev (w/o junks) */
	ExprState	   *outer_quals;
	TupleTableSlot *outer_slot;
	ProjectionInfo *outer_proj;		/* outer tlist -> custom_scan_tlist */

	kern_data_store *kds_slot_head;
	pgstrom_data_store *pds_final;
	CUdeviceptr		m_fhash;
	CUevent			ev_init_fhash;
	size_t			f_hashsize;
	size_t			f_hashlimit;
	pthread_mutex_t	f_mutex;

	size_t			plan_nrows_per_chunk;	/* planned nrows/chunk */
	size_t			plan_nrows_in;	/* num of outer rows planned */
	size_t			plan_ngroups;	/* num of groups planned */
	size_t			plan_extra_sz;	/* size of varlena planned */
} GpuPreAggState;

struct GpuPreAggRuntimeStat
{
	GpuTaskRuntimeStat	c;		/* common statistics */
};
typedef struct GpuPreAggRuntimeStat	GpuPreAggRuntimeStat;

struct GpuPreAggSharedState
{
	dsm_handle		ss_handle;	/* DSM handle of the SharedState */
	cl_uint			ss_length;	/* Length of the SharedState */
	GpuPreAggRuntimeStat gpa_rtstat;	/* Run-time statistics */
};
typedef struct GpuPreAggSharedState	GpuPreAggSharedState;

/*
 * GpuPreAggTask
 *
 * Host side representation of kern_gpupreagg. It can perform as a message
 * object of PG-Strom, has key of OpenCL device program, a source row/column
 * store and a destination kern_data_store.
 */
typedef struct GpuJoinSharedState	GpuJoinSharedState;

typedef enum {
	GpuPreAggTaskRole__Normal,
	GpuPreAggTaskRole__Dummy,
	GpuPreAggTaskRole__LocalTerminator,
	GpuPreAggTaskRole__GlobalTerminator,
} GpuPreAggTaskRole;

typedef struct
{
	GpuTask				task;
	bool				with_nvme_strom;/* true, if NVMe-Strom */
	pgstrom_data_store *pds_src;	/* source row/block buffer */
	kern_data_store	   *kds_slot;	/* partial results generated by combined
									 * GpuJoin, and should be kept for CPU
									 * fallback jobs */
	size_t				kds_slot_nrooms; /* for kds_slot */
	size_t				kds_slot_length; /* for kds_slot */
	kern_gpujoin	   *kgjoin;		/* kern_gpujoin, if combined mode */
	CUdeviceptr			m_kmrels;	/* kern_multirels, if combined mode */
	cl_int				outer_depth;/* RIGHT OUTER depth, if combined mode */
	kern_gpupreagg		kern;
} GpuPreAggTask;

/* declaration of static functions */
static bool		gpupreagg_build_path_target(PlannerInfo *root,
											PathTarget *target_upper,
											PathTarget *target_final,
											PathTarget *target_partial,
											PathTarget *target_device,
											Path       *input_path,
											Bitmapset **p_pfunc_bitmap,
											Node **p_havingQual,
											bool *p_can_pullup_outerscan);
static char	   *gpupreagg_codegen(codegen_context *context,
								  CustomScan *cscan,
								  List *tlist_dev,
								  List *outer_tlist,
								  GpuPreAggInfo *gpa_info,
								  Bitmapset *pfunc_bitmap);
static void createGpuPreAggSharedState(GpuPreAggState *gpas,
									   ParallelContext *pcxt,
									   void *dsm_addr);
static void releaseGpuPreAggSharedState(GpuPreAggState *gpas);
static void resetGpuPreAggSharedState(GpuPreAggState *gpas);

static GpuTask *gpupreagg_next_task(GpuTaskState *gts);
static GpuTask *gpupreagg_terminator_task(GpuTaskState *gts,
										  cl_bool *task_is_ready);
static int  gpupreagg_process_task(GpuTask *gtask, CUmodule cuda_module);
static void gpupreagg_release_task(GpuTask *gtask);
static TupleTableSlot *gpupreagg_next_tuple(GpuTaskState *gts);

/*
 * Arguments of alternative functions.
 */
#define ALTFUNC_EXPR_NROWS			101	/* NROWS(X) */
#define ALTFUNC_EXPR_PMIN			102	/* PMIN(X) */
#define ALTFUNC_EXPR_PMAX			103	/* PMAX(X) */
#define ALTFUNC_EXPR_PSUM			104	/* PSUM(X) */
#define ALTFUNC_EXPR_PSUM_X2		105	/* PSUM_X2(X) = PSUM(X^2) */
#define ALTFUNC_EXPR_PCOV_X			106	/* PCOV_X(X,Y) */
#define ALTFUNC_EXPR_PCOV_Y			107	/* PCOV_Y(X,Y) */
#define ALTFUNC_EXPR_PCOV_X2		108	/* PCOV_X2(X,Y) */
#define ALTFUNC_EXPR_PCOV_Y2		109	/* PCOV_Y2(X,Y) */
#define ALTFUNC_EXPR_PCOV_XY		110	/* PCOV_XY(X,Y) */

/*
 * XXX - GpuPreAgg with Numeric arguments are problematic because
 * it is implemented with normal function call and iteration of
 * cmpxchg. Thus, larger reduction ratio (usually works better)
 * will increase atomic contension. So, at this moment we turned
 * off GpuPreAgg + Numeric
 */
#define GPUPREAGG_SUPPORT_NUMERIC			1

#ifndef INT8ARRAYOID
#define INT8ARRAYOID		1016	/* see pg_type.h */
#endif
#ifndef FLOAT8ARRAYOID
#define FLOAT8ARRAYOID		1022	/* see pg_type.h */
#endif
#ifndef NUMERICARRAYOID
#define NUMERICARRAYOID		1231	/* see pg_type.h */
#endif

/*
 * List of supported aggregate functions
 */
typedef struct {
	/* aggregate function can be preprocessed */
	const char *aggfn_name;
	int			aggfn_nargs;
	Oid			aggfn_argtypes[4];
	/*
	 * A pair of final/partial function will generate same result.
	 * Its prefix indicates the schema that stores these functions.
	 * c: pg_catalog ... the system default
	 * s: pgstrom    ... PG-Strom's special ones
	 */
	const char *finalfn_name;
	Oid			finalfn_argtype;
	const char *partfn_name;
	int			partfn_nargs;
	Oid			partfn_argtypes[8];
	int			partfn_argexprs[8];
	int			extra_flags;
	bool		numeric_aware;	/* ignored, if !enable_numeric_aggfuncs */
} aggfunc_catalog_t;
static aggfunc_catalog_t  aggfunc_catalog[] = {
	/* AVG(X) = EX_AVG(NROWS(), PSUM(X)) */
	{ "avg",    1, {INT2OID},
	  "s:favg",     INT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, INT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "avg",    1, {INT4OID},
	  "s:favg",     INT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, INT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "avg",    1, {INT8OID},
	  "s:favg",     INT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, INT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "avg",    1, {FLOAT4OID},
	  "s:favg",     FLOAT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "avg",    1, {FLOAT8OID},
	  "s:favg",     FLOAT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, false
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "avg",	1, {NUMERICOID},
	  "s:favg_numeric", FLOAT8ARRAYOID,
	  "s:pavg", 2, {INT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS, ALTFUNC_EXPR_PSUM}, 0, true
	},
#endif
	/* COUNT(*) = SUM(NROWS(*|X)) */
	{ "count",  0, {},
	  "s:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_NROWS}, 0, false
	},
	{ "count",  1, {ANYOID},
	  "s:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_NROWS}, 0, false
	},
	/* MAX(X) = MAX(PMAX(X)) */
	{ "max",    1, {INT2OID},
	  "s:fmax_int2", INT4OID,
	  "varref", 1, {INT4OID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {INT4OID},
	  "c:max",      INT4OID,
	  "varref", 1, {INT4OID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {INT8OID},
	  "c:max",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {FLOAT4OID},
	  "c:max",      FLOAT4OID,
	  "varref", 1, {FLOAT4OID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {FLOAT8OID},
	  "c:max",      FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "max",    1, {NUMERICOID},
	  "s:fmax_numeric", FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PMAX}, 0, true
	},
#endif
	{ "max",    1, {CASHOID},
	  "c:max",      CASHOID,
	  "varref", 1, {CASHOID},
	  {ALTFUNC_EXPR_PMAX}, DEVKERNEL_NEEDS_MISCLIB, false
	},
	{ "max",    1, {DATEOID},
	  "c:max",      DATEOID,
	  "varref", 1, {DATEOID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {TIMEOID},
	  "c:max",      TIMEOID,
	  "varref", 1, {TIMEOID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {TIMESTAMPOID},
	  "c:max",      TIMESTAMPOID,
	  "varref", 1, {TIMESTAMPOID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},
	{ "max",    1, {TIMESTAMPTZOID},
	  "c:max",      TIMESTAMPTZOID,
	  "varref", 1, {TIMESTAMPTZOID},
	  {ALTFUNC_EXPR_PMAX}, 0, false
	},

	/* MIX(X) = MIN(PMIN(X)) */
	{ "min",    1, {INT2OID},
	  "s:fmin_int2", INT4OID,
	  "varref", 1, {INT4OID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {INT4OID},
	  "c:min",      INT4OID,
	  "varref", 1, {INT4OID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {INT8OID},
	  "c:min",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {FLOAT4OID},
	  "c:min",      FLOAT4OID,
	  "varref", 1, {FLOAT4OID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {FLOAT8OID},
	  "c:min",      FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "min",    1, {NUMERICOID},
	  "s:fmin_numeric", FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PMIN}, 0, true
	},
#endif
	{ "min",    1, {CASHOID},
	  "c:min",      CASHOID,
	  "varref", 1, {CASHOID},
	  {ALTFUNC_EXPR_PMAX}, DEVKERNEL_NEEDS_MISCLIB, false
	},
	{ "min",    1, {DATEOID},
	  "c:min",      DATEOID,
	  "varref", 1, {DATEOID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {TIMEOID},
	  "c:min",      TIMEOID,
	  "varref", 1, {TIMEOID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {TIMESTAMPOID},
	  "c:min",      TIMESTAMPOID,
	  "varref", 1, {TIMESTAMPOID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},
	{ "min",    1, {TIMESTAMPTZOID},
	  "c:min",      TIMESTAMPTZOID,
	  "varref", 1, {TIMESTAMPTZOID},
	  {ALTFUNC_EXPR_PMIN}, 0, false
	},

	/* SUM(X) = SUM(PSUM(X)) */
	{ "sum",    1, {INT2OID},
	  "s:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "sum",    1, {INT4OID},
	  "s:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "sum",    1, {INT8OID},
	  "c:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "sum",    1, {FLOAT4OID},
	  "c:sum",      FLOAT4OID,
	  "varref", 1, {FLOAT4OID},
	  {ALTFUNC_EXPR_PSUM}, 0, false
	},
	{ "sum",    1, {FLOAT8OID},
	  "c:sum",      FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PSUM}, 0, false
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "sum",    1, {NUMERICOID},
	  "s:fsum_numeric", FLOAT8OID,
	  "varref", 1, {FLOAT8OID},
	  {ALTFUNC_EXPR_PSUM}, 0, true
	},
#endif
	{ "sum",    1, {CASHOID},
	  "c:sum",      CASHOID,
	  "varref", 1, {CASHOID},
	  {ALTFUNC_EXPR_PSUM}, DEVKERNEL_NEEDS_MISCLIB, false
	},
	/* STDDEV(X) = EX_STDDEV(NROWS(),PSUM(X),PSUM(X*X)) */
	{ "stddev",      1, {INT2OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0, false
	},
	{ "stddev",      1, {INT4OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0, false
	},
	{ "stddev",      1, {INT8OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0, false
	},
	{ "stddev",      1, {FLOAT4OID},
	  "s:stddev",        FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0, false
	},
	{ "stddev",      1, {FLOAT8OID},
	  "s:stddev",        FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0, false
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "stddev",      1, {NUMERICOID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/* STDDEV_POP(X) = EX_STDDEV(NROWS(),PSUM(X),PSUM(X*X)) */
	{ "stddev_pop",  1, {INT2OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_pop",  1, {INT4OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_pop",  1, {INT8OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_pop",  1, {FLOAT4OID},
	  "s:stddev_pop",    FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_pop",  1, {FLOAT8OID},
	  "s:stddev_pop",    FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "stddev_pop",  1, {NUMERICOID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/* STDDEV_POP(X) = EX_STDDEV(NROWS(),PSUM(X),PSUM(X*X)) */
	{ "stddev_samp", 1, {INT2OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_samp", 1, {INT4OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_samp", 1, {INT8OID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_samp", 1, {FLOAT4OID},
	  "s:stddev_samp",   FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "stddev_samp", 1, {FLOAT8OID},
	  "s:stddev_samp",   FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "stddev_samp", 1, {NUMERICOID},
	  "s:stddev_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/* VARIANCE(X) = PGSTROM.VARIANCE(NROWS(), PSUM(X),PSUM(X^2)) */
	{ "variance",    1, {INT2OID},
	  "s:variance_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "variance",    1, {INT4OID},
	  "s:variance_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "variance",    1, {INT8OID},
	  "s:variance_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "variance",    1, {FLOAT4OID},
	  "s:variance",      FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "variance",    1, {FLOAT8OID},
	  "s:variance",      FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "variance",    1, {NUMERICOID},
	  "s:variance_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/* VAR_POP(X) = PGSTROM.VAR_POP(NROWS(), PSUM(X),PSUM(X^2)) */
	{ "var_pop",     1, {INT2OID},
	  "s:var_pop_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_pop",     1, {INT4OID},
	  "s:var_pop_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_pop",     1, {INT8OID},
	  "s:var_pop_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_pop",     1, {FLOAT4OID},
	  "s:var_pop",       FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_pop",     1, {FLOAT8OID},
	  "s:var_pop",       FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "var_pop",     1, {NUMERICOID},
	  "s:var_pop_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/* VAR_SAMP(X) = PGSTROM.VAR_SAMP(NROWS(), PSUM(X),PSUM(X^2)) */
	{ "var_samp",    1, {INT2OID},
	  "s:var_samp_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_samp",    1, {INT4OID},
	  "s:var_samp_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_samp",    1, {INT8OID},
	  "s:var_samp_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_samp",    1, {FLOAT4OID},
	  "s:var_samp",      FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
	{ "var_samp",    1, {FLOAT8OID},
	  "s:var_samp",      FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#ifdef GPUPREAGG_SUPPORT_NUMERIC
	{ "var_samp",    1, {NUMERICOID},
	  "s:var_samp_numeric", FLOAT8ARRAYOID,
	  "s:pvariance", 3, {INT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PSUM,
	   ALTFUNC_EXPR_PSUM_X2}, 0
	},
#endif
	/*
	 * CORR(X,Y) = PGSTROM.CORR(NROWS(X,Y),
	 *                          PCOV_X(X,Y),  PCOV_Y(X,Y)
	 *                          PCOV_X2(X,Y), PCOV_Y2(X,Y),
	 *                          PCOV_XY(X,Y))
	 */
	{ "corr",     2, {FLOAT8OID, FLOAT8OID},
	  "s:corr",       FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "covar_pop", 2, {FLOAT8OID, FLOAT8OID},
	  "s:covar_pop",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "covar_samp", 2, {FLOAT8OID, FLOAT8OID},
	  "s:covar_samp",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	/*
	 * Aggregation to support least squares method
	 *
	 * That takes PSUM_X, PSUM_Y, PSUM_X2, PSUM_Y2, PSUM_XY according
	 * to the function
	 */
	{ "regr_avgx", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_avgx",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
       ALTFUNC_EXPR_PCOV_X,
       ALTFUNC_EXPR_PCOV_X2,
       ALTFUNC_EXPR_PCOV_Y,
       ALTFUNC_EXPR_PCOV_Y2,
       ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_avgy", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_avgy",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_count", 2, {FLOAT8OID, FLOAT8OID},
	  "s:sum",      INT8OID,
	  "varref", 1, {INT8OID},
	  {ALTFUNC_EXPR_NROWS}, 0
	},
	{ "regr_intercept", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_intercept",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_r2", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_r2",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_slope", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_slope",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_sxx", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_sxx",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_sxy", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_sxy",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
	{ "regr_syy", 2, {FLOAT8OID, FLOAT8OID},
	  "s:regr_syy",   FLOAT8ARRAYOID,
	  "s:pcovar", 6,
	  {INT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID, FLOAT8OID},
	  {ALTFUNC_EXPR_NROWS,
	   ALTFUNC_EXPR_PCOV_X,
	   ALTFUNC_EXPR_PCOV_X2,
	   ALTFUNC_EXPR_PCOV_Y,
	   ALTFUNC_EXPR_PCOV_Y2,
	   ALTFUNC_EXPR_PCOV_XY}, 0
	},
};

static const aggfunc_catalog_t *
aggfunc_lookup_by_oid(Oid aggfnoid)
{
	Form_pg_proc	proform;
	HeapTuple		htup;
	int				i;

	htup = SearchSysCache1(PROCOID, ObjectIdGetDatum(aggfnoid));
	if (!HeapTupleIsValid(htup))
		elog(ERROR, "cache lookup failed for function %u", aggfnoid);
	proform = (Form_pg_proc) GETSTRUCT(htup);

	for (i=0; i < lengthof(aggfunc_catalog); i++)
	{
		aggfunc_catalog_t  *catalog = &aggfunc_catalog[i];

		if (strcmp(catalog->aggfn_name, NameStr(proform->proname)) == 0 &&
			catalog->aggfn_nargs == proform->pronargs &&
			memcmp(catalog->aggfn_argtypes,
				   proform->proargtypes.values,
				   sizeof(Oid) * catalog->aggfn_nargs) == 0)
		{
			/* check status of device NUMERIC type support */
			if (!enable_numeric_aggfuncs && catalog->numeric_aware)
				catalog = NULL;

			ReleaseSysCache(htup);
			return catalog;
		}
	}
	ReleaseSysCache(htup);
	return NULL;
}

/*
 * cost_gpupreagg
 *
 * cost estimation for GpuPreAgg node
 */
static bool
cost_gpupreagg(PlannerInfo *root,
			   CustomPath *cpath,
			   GpuPreAggInfo *gpa_info,
			   PathTarget *target_partial,
			   PathTarget *target_device,
			   Path *input_path,
			   int parallel_nworkers,
			   double num_groups,
			   IndexOptInfo *index_opt,
			   List *index_quals,
			   cl_long index_nblocks)
{
	double		gpu_cpu_ratio = pgstrom_gpu_operator_cost / cpu_operator_cost;
	double		ntuples_out;
	Cost		startup_cost;
	Cost		run_cost;
	QualCost	qual_cost;
	int			num_group_keys = 0;
	Size		extra_sz = 0;
	cl_int		key_dist_salt;
	cl_int		index;
	ListCell   *lc;

	/* Cost come from the underlying path */
	if (gpa_info->outer_scanrelid == 0)
	{
		RelOptInfo *outer_rel = input_path->parent;
		Cost	outer_startup = input_path->startup_cost;
		Cost	outer_total   = input_path->total_cost;
		List   *outer_tlist   = input_path->pathtarget->exprs;
		Cost	discount = 0.0;

		/*
		 * Discount cost for DMA-receive if GpuPreAgg can pull-up
		 * outer GpuJoin.
		 */
		if (enable_pullup_outer_join &&
			pgstrom_path_is_gpujoin(input_path) &&
			pgstrom_device_expression(root, outer_rel, (Expr *)outer_tlist))
		{
			discount = (cost_for_dma_receive(input_path->parent, -1.0) +
						cpu_tuple_cost * input_path->rows);
		}
		else if (pathtree_has_gpupath(input_path))
			outer_total += pgstrom_gpu_setup_cost / 2;
		else
			outer_total += pgstrom_gpu_setup_cost;

		gpa_info->outer_startup_cost = Max(outer_startup - discount, 0.0);
		gpa_info->outer_total_cost   = Max(outer_total - discount, 0.0);

		startup_cost = outer_total;
		run_cost = 0.0;
	}
	else
	{
		double		parallel_divisor;
		double		ntuples;
		double		nchunks;

		pgstrom_common_relscan_cost(root,
									input_path->parent,
									gpa_info->outer_quals,
									parallel_nworkers,	/* parallel scan */
									index_opt,			/* BRIN-index */
									index_quals,		/* BRIN-index */
									index_nblocks,		/* BRIN-index */
									&ntuples,
									&nchunks,
									&parallel_divisor,
									&gpa_info->outer_nrows_per_block,
									&startup_cost,
									&run_cost);
		run_cost -= cpu_tuple_cost * ntuples;
		if (run_cost < 0.0)
			run_cost = 0.0;
		gpa_info->outer_startup_cost = startup_cost;
		gpa_info->outer_total_cost	= startup_cost + run_cost;

		startup_cost += run_cost;
		run_cost = 0.0;
	}
	gpa_info->outer_nrows		= input_path->rows;
	gpa_info->outer_width		= input_path->pathtarget->width;

	/*
	 * Estimation of the result buffer. It must fit to the target GPU device
	 * memory size.
	 */
	index = 0;
	foreach (lc, target_device->exprs)
	{
		Expr   *expr = lfirst(lc);
		Oid		type_oid = exprType((Node *)expr);
		int32	type_mod = exprTypmod((Node *)expr);
		int16	typlen;
		bool	typbyval;

		/* extra buffer */
		if (type_oid == NUMERICOID)
			extra_sz += 32;
		else
		{
			get_typlenbyval(type_oid, &typlen, &typbyval);
			if (!typbyval)
				extra_sz += get_typavgwidth(type_oid, type_mod);
		}
		/* count up number of the grouping keys */
		if (get_pathtarget_sortgroupref(target_device, index))
			num_group_keys++;
		index++;
	}
	if (num_group_keys == 0)
		num_groups = 1.0;	/* AGG_PLAIN */
	/*
	 * NOTE: In case when the number of groups are too small, it leads too
	 * many atomic contention on the device. So, we add a small salt to
	 * distribute grouping keys than the actual number of keys.
	 * It shall be adjusted on run-time, so configuration below is just
	 * a baseline parameter.
	 */
	if (num_groups < (devBaselineMaxThreadsPerBlock / 5))
	{
		key_dist_salt = (devBaselineMaxThreadsPerBlock / (5 * num_groups));
		key_dist_salt = Max(key_dist_salt, 1);
	}
	else
		key_dist_salt = 1;
	ntuples_out = num_groups * (double)key_dist_salt;
#if 0
	//FIXME
	ncols = list_length(target_device->exprs);
	nrooms = (cl_uint)(2.5 * num_groups * (double)key_dist_salt);
	kds_length = (KDS_CALCULATE_SLOT_LENGTH(ncols, nrooms) +
				  STROMALIGN(extra_sz) * nrooms);
	// unified memory eliminates limitation of the device memory
	// however, some penalty is needed for large buffer
	if (kds_length > gpuMemMaxAllocSize())
		return false;	/* expected buffer size is too large */
#endif

	/* Cost estimation for the initial projection */
	cost_qual_eval(&qual_cost, target_device->exprs, root);
	startup_cost += (target_device->cost.per_tuple * input_path->rows +
					 target_device->cost.startup) * gpu_cpu_ratio;
	/* Cost estimation for grouping */
	startup_cost += (pgstrom_gpu_operator_cost *
					 num_group_keys *
					 input_path->rows);
	/* Cost estimation for aggregate function */
	startup_cost += (target_device->cost.per_tuple * input_path->rows +
					 target_device->cost.startup) * gpu_cpu_ratio;
	/* Cost estimation for host side functions */
	startup_cost += target_partial->cost.startup;
	run_cost += target_partial->cost.per_tuple * ntuples_out;

	/* Cost estimation to fetch results */
	run_cost += cpu_tuple_cost * ntuples_out;

	cpath->path.rows			= ntuples_out;
	cpath->path.startup_cost	= startup_cost;
	cpath->path.total_cost		= startup_cost + run_cost;

	gpa_info->num_group_keys    = num_group_keys;
	gpa_info->plan_ngroups		= num_groups;
	gpa_info->plan_nchunks		= estimate_num_chunks(input_path);
	gpa_info->plan_extra_sz		= extra_sz;

	return true;
}

#if PG_VERSION_NUM < 120000
/*
 * estimate_hashagg_tablesize - had been declared as a static function
 * until PG12 at the optimizer/plan/planner.c.
 */
static double
estimate_hashagg_tablesize(Path *path, const AggClauseCosts *agg_costs,
                           double dNumGroups)
{
	Size		hashentrysize;

	/* Estimate per-hash-entry space at tuple width... */
	hashentrysize = MAXALIGN(path->pathtarget->width) +
		MAXALIGN(SizeofMinimalTupleHeader);

	/* plus space for pass-by-ref transition values... */
	hashentrysize += agg_costs->transitionSpace;
	/* plus the per-hash-entry overhead */
	hashentrysize += hash_agg_entry_size(agg_costs->numAggs);

	return hashentrysize * dNumGroups;
}
#endif

/*
 * make_gpupreagg_path
 *
 * constructor of the GpuPreAgg path node
 */
static CustomPath *
make_gpupreagg_path(PlannerInfo *root,
					RelOptInfo *group_rel,
					PathTarget *target_partial,
					PathTarget *target_device,
					Bitmapset *pfunc_bitmap,
					Path *input_path,
					double num_groups,
					bool can_pullup_outerscan)
{
	CustomPath	   *cpath = makeNode(CustomPath);
	GpuPreAggInfo  *gpa_info = palloc0(sizeof(GpuPreAggInfo));
	List		   *custom_paths = NIL;
	int				parallel_nworkers = 0;
	IndexOptInfo   *index_opt = NULL;
	List		   *index_conds = NIL;
	List		   *index_quals = NIL;
	cl_long			index_nblocks;

	/* obviously, not suitable for GpuPreAgg */
	if (num_groups < 1.0 || num_groups > (double)INT_MAX)
		return NULL;

	/* Try to pull up input_path if simple relation scan */
	gpa_info->optimal_gpu = -1;
	if (!can_pullup_outerscan ||
		!pgstrom_pullup_outer_scan(root, input_path,
								   &gpa_info->outer_scanrelid,
								   &gpa_info->outer_quals,
								   &gpa_info->optimal_gpu,
								   &index_opt,
								   &index_conds,
								   &index_quals,
								   &index_nblocks))
	{
		if (pgstrom_path_is_gpujoin(input_path))
			gpa_info->optimal_gpu = gpujoin_get_optimal_gpu(input_path);
		custom_paths = list_make1(input_path);
	}

	/* Number of workers if parallel */
	if (group_rel->consider_parallel &&
		input_path->parallel_safe)
		parallel_nworkers = input_path->parallel_workers;

	/* cost estimation */
	if (!cost_gpupreagg(root, cpath, gpa_info,
						target_partial, target_device,
						input_path, parallel_nworkers, num_groups,
						index_opt, index_quals, index_nblocks))
	{
		pfree(cpath);
		return NULL;
	}
	/* BRIN-index options */
	gpa_info->index_oid = (index_opt ? index_opt->indexoid : InvalidOid);
	gpa_info->index_conds = index_conds;
	gpa_info->index_quals = extract_actual_clauses(index_quals, false);

	/* Setup CustomPath */
	cpath->path.pathtype = T_CustomScan;
	cpath->path.parent = input_path->parent;
	cpath->path.pathtarget = target_partial;
	cpath->path.param_info = NULL;
	cpath->path.parallel_safe = (group_rel->consider_parallel &&
								 input_path->parallel_safe);
	cpath->path.parallel_workers = parallel_nworkers;
	cpath->path.pathkeys = NIL;
	cpath->custom_paths = custom_paths;
	cpath->custom_private = list_make3(gpa_info,
									   target_device,
									   pfunc_bitmap);
	cpath->methods = &gpupreagg_path_methods;

	return cpath;
}

/*
 * prepend_gpupreagg_path
 */
static Path *
prepend_gpupreagg_path(PlannerInfo *root,
					   RelOptInfo *group_rel,
					   PathTarget *target_partial,
					   PathTarget *target_device,
					   Path *input_path,
					   Bitmapset *pfunc_bitmap,
					   double num_groups,
					   bool can_pullup_outerscan,
					   bool with_gather_node)
{
	CustomPath *cpath;
	Path	   *partial_path;

	/*
	 * MEMO: See grouping_planner() where it calls create_projection_path()
	 * on the partial Path-nodes. It forcibly injects ProjectionPath to
	 * have individual PathTarget on top of the scan/join paths, because
	 * these scan/join paths may be referenced by other path-trees, thus
	 * it is unable to set PathTarget in-place.
	 * In fact, create_projection_plan() pulls up sub-plan and attach its
	 * target-list if it can be compatible, however, this ProjectionPath
	 * prevents GpuJoin to have compatible host_tlist and dev_tlist, and
	 * leads host-side projection. It works as a blocker of combined-GpuJoin
	 * which is one of the performance key of reporting queries.
	 * So, we duplicate GpuJoinPath by ourself, and set PathTarget of
	 * the ProjectionPath here.
	 */
	if (IsA(input_path, ProjectionPath))
	{
		ProjectionPath *pjpath = (ProjectionPath *)input_path;
		RelOptInfo	   *pjrel = pjpath->path.parent;
		PathTarget	   *pathtarget = pjpath->path.pathtarget;

		if (pjpath->dummypp &&
			pgstrom_path_is_gpujoin(pjpath->subpath) &&
			pgstrom_device_expression(root, pjrel, (Expr *)pathtarget->exprs))
		{
			input_path = pgstrom_copy_gpujoin_path(pjpath->subpath);
			input_path->pathtarget = pathtarget;
		}
	}

	/*
	 * construction of GpuPreAgg pathnode on top of the cheapest total
	 * cost pathnode (partial aggregation)
	 */
	cpath = make_gpupreagg_path(root, group_rel,
								target_partial,
								target_device,
								pfunc_bitmap,
								input_path,
								num_groups,
								can_pullup_outerscan);
	if (!cpath)
		return NULL;

	/* Is it parallel capable? */
	if (cpath->path.parallel_safe &&
		cpath->path.parallel_workers > 0)
	{
		cpath->path.parallel_aware = true;

		if (with_gather_node)
		{
			double	total_groups = (cpath->path.rows *
									cpath->path.parallel_workers);
			partial_path = (Path *)create_gather_path(root,
													  group_rel,
													  &cpath->path,
													  target_partial,
													  NULL,
													  &total_groups);
		}
		else
			partial_path = &cpath->path;
	}
	else if (with_gather_node)
		partial_path = NULL;
	else
		partial_path = &cpath->path;

	return partial_path;
}

/*
 * try_add_final_aggregation_paths
 */
static void
try_add_final_aggregation_paths(PlannerInfo *root,
								RelOptInfo *group_rel,
								PathTarget *target_final,
								Path *partial_path,
								List *havingQuals,
								double num_groups,
								AggClauseCosts *agg_final_costs)
{
	Query	   *parse = root->parse;
	PathTarget *target_upper = root->upper_targets[UPPERREL_GROUP_AGG];
	Path	   *sort_path;
	Path	   *final_path;
	bool		can_sort;
	bool		can_hash;

	/* strategy of the final aggregation */
	can_sort = grouping_is_sortable(parse->groupClause);
	can_hash = (parse->groupClause != NIL &&
				parse->groupingSets == NIL &&
				agg_final_costs->numOrderedAggs == 0 &&
				grouping_is_hashable(parse->groupClause));

	/* make a final grouping path (nogroup) */
	if (!parse->groupClause)
	{
		final_path = (Path *)create_agg_path(root,
											 group_rel,
											 partial_path,
											 target_final,
											 AGG_PLAIN,
											 AGGSPLIT_SIMPLE,
											 parse->groupClause,
											 havingQuals,
											 agg_final_costs,
											 num_groups);
		add_path(group_rel, pgstrom_create_dummy_path(root,
													  final_path,
													  target_upper));
	}
	else
	{
		/* make a final grouping path (sort) */
		if (can_sort)
		{
			PathTarget *target_orig __attribute__((unused));

			sort_path = (Path *)
				create_sort_path(root,
								 group_rel,
								 partial_path,
								 root->group_pathkeys,
								 -1.0);
			if (parse->groupingSets)
			{
				AggStrategy	rollup_strategy = AGG_PLAIN;
				List	   *rollup_data_list = NIL;
				ListCell   *lc;
				/*
				 * TODO: In this version, we expect group_rel->pathlist have
				 * a GroupingSetsPath constructed by the built-in code.
				 * It may not be right, if multiple CSP/FDW is installed and
				 * cheaper path already eliminated the standard path.
				 * However, it is a corner case now, and we don't support
				 * this scenario _right now_.
				 */
				foreach (lc, group_rel->pathlist)
				{
					GroupingSetsPath   *pathnode = lfirst(lc);

					if (IsA(pathnode, GroupingSetsPath))
					{
						rollup_strategy = pathnode->aggstrategy;
						rollup_data_list = pathnode->rollups;
						break;
					}
				}
				if (!lc)
					return;		/* give up */
				final_path = (Path *)
					create_groupingsets_path(root,
											 group_rel,
											 sort_path,
#if PG_VERSION_NUM < 110000
											 target_final,
#endif
											 (List *) parse->havingQual,
											 rollup_strategy,
											 rollup_data_list,
											 agg_final_costs,
											 num_groups);
#if PG_VERSION_NUM >= 110000
				/* adjust cost and overwrite PathTarget */
				target_orig = final_path->pathtarget;
				final_path->startup_cost += (target_final->cost.startup -
											 target_orig->cost.startup);
				final_path->total_cost += (target_final->cost.startup -
										   target_orig->cost.startup) +
					(target_final->cost.per_tuple -
					 target_orig->cost.per_tuple) * final_path->rows;
				final_path->pathtarget = target_final;
#endif
			}
			else if (parse->hasAggs)
				final_path = (Path *)
					create_agg_path(root,
									group_rel,
									sort_path,
									target_final,
									AGG_SORTED,
									AGGSPLIT_SIMPLE,
									parse->groupClause,
								    havingQuals,
									agg_final_costs,
									num_groups);
			else if (parse->groupClause)
			{
				final_path = (Path *)
					create_group_path(root,
									  group_rel,
									  sort_path,
#if PG_VERSION_NUM < 110000
									  target_final,
#endif
									  parse->groupClause,
									  havingQuals,
									  num_groups);
#if PG_VERSION_NUM >= 110000
				/* adjust cost and overwrite PathTarget */
				target_orig = final_path->pathtarget;
				final_path->startup_cost += (target_final->cost.startup -
											 target_orig->cost.startup);
				final_path->total_cost += (target_final->cost.startup -
										   target_orig->cost.startup) +
					(target_final->cost.per_tuple -
					 target_orig->cost.per_tuple) * final_path->rows;
				final_path->pathtarget = target_final;
#endif
			}
			else
				elog(ERROR, "Bug? unexpected AGG/GROUP BY requirement");

			add_path(group_rel, pgstrom_create_dummy_path(root,
														  final_path,
														  target_upper));
		}

		/* make a final grouping path (hash) */
		if (can_hash)
		{
			double	hashaggtablesize
				= estimate_hashagg_tablesize(partial_path,
											 agg_final_costs,
											 num_groups);
			if (hashaggtablesize < work_mem * 1024L)
			{
				final_path = (Path *)
					create_agg_path(root,
									group_rel,
									partial_path,
									target_final,
									AGG_HASHED,
									AGGSPLIT_SIMPLE,
									parse->groupClause,
									havingQuals,
									agg_final_costs,
									num_groups);
				add_path(group_rel, pgstrom_create_dummy_path(root,
															  final_path,
															  target_upper));
			}
		}
	}
}

/*
 * try_add_gpupreagg_append_paths
 */
static void
try_add_gpupreagg_append_paths(PlannerInfo *root,
							   RelOptInfo *group_rel,
							   PathTarget *target_final,
							   PathTarget *target_partial,
							   PathTarget *target_device,
							   Path *input_path,
							   Bitmapset *pfunc_bitmap,
							   List *havingQual,
							   double num_groups,
							   AggClauseCosts *agg_final_costs,
							   bool can_pullup_outerscan,
							   bool try_outer_parallel)
{
#if PG_VERSION_NUM >= 110000
	bool		try_inner_parallel = false;
	List	   *append_paths_list = NIL;
	List	   *sub_paths_list;
	List	   *partitioned_rels;
	int			parallel_nworkers;
	AppendPath *append_path;
	Cost		discount_cost;
	Path	   *partial_path;
	ListCell   *lc;

retry:
	sub_paths_list = extract_partitionwise_pathlist(root,
													input_path,
													try_outer_parallel,
													false,
													&append_path,
													&parallel_nworkers,
													&discount_cost);
	if (sub_paths_list == NIL)
		return;
	if (list_length(sub_paths_list) > 1)
		discount_cost /= (Cost)(list_length(sub_paths_list) - 1);
	else
		discount_cost = 0.0;

	foreach (lc, sub_paths_list)
	{
		Path	   *sub_path = (Path *) lfirst(lc);
		RelOptInfo *sub_rel = sub_path->parent;
		PathTarget *curr_partial = copy_pathtarget(target_partial);
		PathTarget *curr_device = copy_pathtarget(target_device);
		Path	   *partial_path;
		AppendRelInfo **appinfos;
		int				nappinfos;

		appinfos = find_appinfos_by_relids_nofail(root, sub_rel->relids,
												  &nappinfos);
		/* fixup varno */
		curr_partial->exprs = (List *)
			adjust_appendrel_attrs(root, (Node *)curr_partial->exprs,
								   nappinfos, appinfos);
		curr_device->exprs = (List *)
			adjust_appendrel_attrs(root, (Node *)curr_device->exprs,
								   nappinfos, appinfos);

		partial_path = prepend_gpupreagg_path(root,
											  group_rel,
											  curr_partial,
											  curr_device,
											  sub_path,
											  pfunc_bitmap,
											  num_groups,
											  can_pullup_outerscan,
											  false);
		if (!partial_path)
			return;
		partial_path->total_cost -= discount_cost;
		append_paths_list = lappend(append_paths_list, partial_path);
	}
	/* also see create_append_path(), some fields must be fixed up */
	partitioned_rels = copyObject(append_path->partitioned_rels);
	if (try_outer_parallel)
		append_path = create_append_path(root, input_path->parent,
										 NIL, append_paths_list,
										 NIL, NULL,
										 parallel_nworkers, true,
										 partitioned_rels, -1.0);
	else
		append_path = create_append_path(root, input_path->parent,
										 append_paths_list, NIL,
										 NIL, NULL,
										 parallel_nworkers, false,
										 partitioned_rels, -1.0);
	append_path->path.pathtarget = target_partial;
	append_path->path.total_cost -= discount_cost;

	/* prepend Gather on demand */
	if (try_outer_parallel &&
		append_path->path.parallel_safe &&
		append_path->path.parallel_workers > 0)
	{
		double		total_groups = (append_path->path.rows *
									append_path->path.parallel_workers);
		append_path->path.parallel_aware = true;
		partial_path = (Path *)create_gather_path(root,
												  group_rel,
												  &append_path->path,
												  target_partial,
												  NULL,
												  &total_groups);
	}
	else
	{
		partial_path = &append_path->path;
		try_outer_parallel = false;		/* never retry again */
	}

	try_add_final_aggregation_paths(root,
									group_rel,
									target_final,
									partial_path,
									(List *) havingQual,
									num_groups,
									agg_final_costs);
	if (try_outer_parallel && !try_inner_parallel)
	{
		try_inner_parallel = true;
		goto retry;
	}
#endif	/* PG_VERSION_NUM >= 110000 */
}

/*
 * try_add_gpupreagg_paths
 */
static void
try_add_gpupreagg_paths(PlannerInfo *root,
						RelOptInfo *group_rel,
						Path *input_path,
						bool try_parallel_path)
{
	Query		   *parse = root->parse;
	PathTarget	   *target_upper	= root->upper_targets[UPPERREL_GROUP_AGG];
	PathTarget	   *target_final	= create_empty_pathtarget();
	PathTarget	   *target_partial	= create_empty_pathtarget();
	PathTarget	   *target_device	= create_empty_pathtarget();
	Path		   *partial_path;
	Bitmapset	   *pfunc_bitmap;
	Node		   *havingQual;
	double			num_groups;
	double			reduction_ratio;
	bool			can_pullup_outerscan = true;
	AggClauseCosts	agg_final_costs;

	/*
	 * MEMO: The 'pg_strom.gpupreagg_reduction_threshold' is a tentative
	 * solution to avoid overflow of GPU device memory for GpuPreAgg.
	 * In case of large table scan with small reduction ratio is almost
	 * equivalent to cache most of input records in GPU device memory.
	 * Then, it shall be aggregated on CPU-side again, it is usually waste
	 * of computing power and data transfer.
	 * Of course, a threshold is not a perfect solution. We may need to
	 * switch to bypass GPU once reduction ratio (or absolute data size) is
	 * worse than the estimation at the planning stage.
	 */
	if (!parse->groupClause)
		num_groups = 1.0;
	else
	{
		Path   *pathnode = linitial(group_rel->pathlist);

		num_groups = Max(pathnode->rows, 1.0);
	}
	reduction_ratio = input_path->rows / num_groups;
	if (reduction_ratio < gpupreagg_reduction_threshold)
	{
		elog(DEBUG2, "GpuPreAgg: %.0f -> %.0f reduction ratio (%.2f) is bad",
			 input_path->rows, num_groups, reduction_ratio);
		return;
	}

	/* construction of the target-list for each level */
	if (!gpupreagg_build_path_target(root,
									 target_upper,
									 target_final,
									 target_partial,
									 target_device,
									 input_path,
									 &pfunc_bitmap,
									 &havingQual,
									 &can_pullup_outerscan))
		return;

	/* Get cost of aggregations */
	memset(&agg_final_costs, 0, sizeof(AggClauseCosts));
	if (parse->hasAggs)
	{
		get_agg_clause_costs(root, (Node *)target_final->exprs,
							 AGGSPLIT_SIMPLE, &agg_final_costs);
		get_agg_clause_costs(root, havingQual,
							 AGGSPLIT_SIMPLE, &agg_final_costs);
	}
	/* GpuPreAgg does not support ordered aggregation */
	if (agg_final_costs.numOrderedAggs > 0)
	{
		elog(DEBUG2, "GpuPreAgg does not support ordered aggregation");
		return;
	}

	if (enable_partitionwise_gpupreagg)
		try_add_gpupreagg_append_paths(root,
									   group_rel,
									   target_final,
									   target_partial,
									   target_device,
									   input_path,
									   pfunc_bitmap,
									   (List *) havingQual,
									   num_groups,
									   &agg_final_costs,
									   can_pullup_outerscan,
									   try_parallel_path);

	partial_path = prepend_gpupreagg_path(root,
										  group_rel,
										  target_partial,
										  target_device,
										  input_path,
										  pfunc_bitmap,
										  num_groups,
										  can_pullup_outerscan,
										  try_parallel_path);
	if (!partial_path ||
		(try_parallel_path && !IsA(partial_path, GatherPath)))
		return;

	try_add_final_aggregation_paths(root,
									group_rel,
									target_final,
									partial_path,
									(List *) havingQual,
									num_groups,
									&agg_final_costs);
}

/*
 * gpupreagg_add_grouping_paths
 *
 * entrypoint to add grouping path by GpuPreAgg logic
 */
static void
gpupreagg_add_grouping_paths(PlannerInfo *root,
							 UpperRelationKind stage,
							 RelOptInfo *input_rel,
							 RelOptInfo *group_rel
#if PG_VERSION_NUM >= 110000
							 ,void *extra
#endif
	)
{
	Path	   *input_path;
	ListCell   *lc;

	if (create_upper_paths_next)
	{
#if PG_VERSION_NUM < 110000
		(*create_upper_paths_next)(root, stage, input_rel, group_rel);
#else
		(*create_upper_paths_next)(root, stage, input_rel, group_rel, extra);
#endif
	}

	if (stage != UPPERREL_GROUP_AGG)
		return;

	if (!pgstrom_enabled || !enable_gpupreagg)
		return;

	/* CREATE EXTENSION pg_strom; was not executed */
	if (get_namespace_oid("pgstrom", true) == InvalidOid)
		return;

	/* traditional GpuPreAgg + Agg path consideration */
	input_path = input_rel->cheapest_total_path;
	try_add_gpupreagg_paths(root, group_rel, input_path, false);

	/*
	 * add GpuPreAgg + Gather + Agg path for CPU+GPU hybrid parallel
	 */
	if (group_rel->consider_parallel)
	{
		foreach (lc, input_rel->partial_pathlist)
		{
			input_path = lfirst(lc);
			try_add_gpupreagg_paths(root, group_rel, input_path, true);
		}
	}
}

/*
 * replace_expression_by_outerref
 *
 * It transforms expression into the form of execution time.
 * Even if expression contains device non-executable portion, it is possible
 * to run as long as it is calculated on the sub-plan.
 */
static Node *
replace_expression_by_outerref(Node *node, PathTarget *target_input)
{
	ListCell   *lc;
	cl_int		resno = 1;

	if (!node)
		return NULL;
	foreach (lc, target_input->exprs)
	{
		if (equal(node, lfirst(lc)))
		{
			Var	   *newnode;

			newnode = makeVar(INDEX_VAR,
							  resno,
							  exprType(node),
							  exprTypmod(node),
							  exprCollation(node),
							  0);
			if (IsA(node, Var))
			{
				Var	   *varnode = (Var *) node;

				newnode->varnosyn  = varnode->varno;
				newnode->varattnosyn = varnode->varattno;
			}
			return (Node *) newnode;
		}
		resno++;
	}

	if (IsA(node, Var))
		elog(ERROR, "Bug? Var-node didn'd appear on the input targetlist: %s",
			 nodeToString(node));

	return expression_tree_mutator(node,
								   replace_expression_by_outerref,
								   target_input);
}

/*
 * is_altfunc_expression - true, if expression derives ALTFUNC_EXPR_*
 */
static bool
is_altfunc_expression(Node *node)
{
	FuncExpr	   *f;
	HeapTuple		tuple;
	Form_pg_proc	form_proc;
	bool			retval = false;

	if (!IsA(node, FuncExpr))
		return false;
	f = (FuncExpr *) node;

	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(f->funcid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", f->funcid);
	form_proc = (Form_pg_proc) GETSTRUCT(tuple);

	if (form_proc->pronamespace == get_namespace_oid("pgstrom", false) &&
		(strcmp(NameStr(form_proc->proname), "nrows") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pmin") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pmax") == 0 ||
		 strcmp(NameStr(form_proc->proname), "psum") == 0 ||
		 strcmp(NameStr(form_proc->proname), "psum_x2") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pcov_x") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pcov_y") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pcov_x2") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pcov_y2") == 0 ||
		 strcmp(NameStr(form_proc->proname), "pcov_xy") == 0))
		retval = true;
	ReleaseSysCache(tuple);

	return retval;
}

/*
 * make_expr_typecast - constructor of type cast
 */
static Expr *
make_expr_typecast(Expr *expr, Oid target_type)
{
	Oid			source_type = exprType((Node *) expr);
	HeapTuple	tup;
	Form_pg_cast cast;

	/*
	 * NOTE: Var->vano shall be replaced to INDEX_VAR on the following
	 * make_altfunc_expr(), so we keep the expression as-is, at this
	 * moment.
	 */
	if (source_type == target_type)
		return expr;

	tup = SearchSysCache2(CASTSOURCETARGET,
						  ObjectIdGetDatum(source_type),
						  ObjectIdGetDatum(target_type));
	Assert(HeapTupleIsValid(tup));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "could not find tuple for cast (%u,%u)",
			 source_type, target_type);
	cast = (Form_pg_cast) GETSTRUCT(tup);
	if (cast->castmethod == COERCION_METHOD_FUNCTION)
	{
		FuncExpr	   *func;

		Assert(OidIsValid(cast->castfunc));
		func = makeFuncExpr(cast->castfunc,
							target_type,
							list_make1(expr),
							InvalidOid,	/* always right? */
							exprCollation((Node *) expr),
							COERCE_EXPLICIT_CAST);
		expr = (Expr *) func;
	}
	else if (cast->castmethod == COERCION_METHOD_BINARY)
	{
		RelabelType	   *relabel = makeNode(RelabelType);

		relabel->arg = expr;
		relabel->resulttype = target_type;
		relabel->resulttypmod = exprTypmod((Node *) expr);
		relabel->resultcollid = exprCollation((Node *) expr);
		relabel->relabelformat = COERCE_EXPLICIT_CAST;
		relabel->location = -1;

		expr = (Expr *) relabel;
	}
	else
	{
		elog(ERROR, "cast-method '%c' is not supported in opencl kernel",
			 cast->castmethod);
	}
	ReleaseSysCache(tup);

	return expr;
}

/*
 * make_expr_conditional - constructor of CASE ... WHEN ... END expression
 * which returns the supplied expression if condition is valid.
 */
static Expr *
make_expr_conditional(Expr *expr, Expr *filter, bool zero_if_unmatched)
{
	Oid			expr_typeoid = exprType((Node *)expr);
	int32		expr_typemod = exprTypmod((Node *)expr);
	Oid			expr_collid = exprCollation((Node *)expr);
	CaseWhen   *case_when;
	CaseExpr   *case_expr;
	Expr	   *defresult;

	if (!filter)
		return expr;

	if (!zero_if_unmatched)
		defresult = (Expr *) makeNullConst(expr_typeoid,
										   expr_typemod,
										   expr_collid);
	else
	{
		int16	typlen;
		bool	typbyval;

		get_typlenbyval(expr_typeoid, &typlen, &typbyval);
		defresult = (Expr *) makeConst(expr_typeoid,
									   expr_typemod,
									   expr_collid,
									   (int) typlen,
									   (Datum) 0,
									   false,
									   typbyval);
	}

	/* in case when the 'filter' is matched */
	case_when = makeNode(CaseWhen);
	case_when->expr = filter;
	case_when->result = expr;
	case_when->location = -1;

	/* case body */
	case_expr = makeNode(CaseExpr);
	case_expr->casetype = exprType((Node *) expr);
	case_expr->arg = NULL;
	case_expr->args = list_make1(case_when);
	case_expr->defresult = defresult;
	case_expr->location = -1;

	return (Expr *) case_expr;
}

/*
 * make_altfunc_simple_expr - constructor of simple function call
 */
static FuncExpr *
make_altfunc_simple_expr(const char *func_name, Expr *func_arg)
{
	Oid			namespace_oid = get_namespace_oid("pgstrom", false);
	Oid			argtype_oid = InvalidOid;
	oidvector  *func_argtypes;
	HeapTuple	tuple;
	Form_pg_proc proc_form;
	FuncExpr   *func_expr;

	if (func_arg)
	{
		argtype_oid = exprType((Node *)func_arg);
		func_argtypes = buildoidvector(&argtype_oid, 1);
	}
	else
		func_argtypes = buildoidvector(NULL, 0);

	/* find an alternative partial function */
	tuple = SearchSysCache3(PROCNAMEARGSNSP,
							PointerGetDatum(func_name),
							PointerGetDatum(func_argtypes),
							ObjectIdGetDatum(namespace_oid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "alternative function not found: %s",
			 func_arg != NULL
			 ? funcname_signature_string(func_name, 1, NIL, &argtype_oid)
			 : funcname_signature_string(func_name, 0, NIL, NULL));

	proc_form = (Form_pg_proc) GETSTRUCT(tuple);
	func_expr = makeFuncExpr(PgProcTupleGetOid(tuple),
							 proc_form->prorettype,
							 func_arg ? list_make1(func_arg) : NIL,
							 InvalidOid,
							 InvalidOid,
							 COERCE_EXPLICIT_CALL);
	ReleaseSysCache(tuple);

	return func_expr;
}

/*
 * make_altfunc_nrows_expr - constructor of the partial number of rows
 */
static FuncExpr *
make_altfunc_nrows_expr(Aggref *aggref)
{
	List	   *nrows_args = NIL;
	ListCell   *lc;
	Expr	   *expr;

	foreach (lc, aggref->args)
	{
		TargetEntry *tle = lfirst(lc);
		NullTest	*ntest = makeNode(NullTest);

		Assert(IsA(tle, TargetEntry));
		ntest->arg = copyObject(tle->expr);
		ntest->nulltesttype = IS_NOT_NULL;
		ntest->argisrow = false;

		nrows_args = lappend(nrows_args, ntest);
	}

	if (aggref->aggfilter)
	{
		Assert(exprType((Node *)aggref->aggfilter) == BOOLOID);
		nrows_args = lappend(nrows_args, copyObject(aggref->aggfilter));
	}

	if (nrows_args == NIL)
		expr = NULL;
	else if (list_length(nrows_args) == 1)
		expr = linitial(nrows_args);
	else
		expr = make_andclause(nrows_args);

	return make_altfunc_simple_expr("nrows", expr);
}

/*
 * make_altfunc_minmax_expr
 */
static FuncExpr *
make_altfunc_minmax_expr(Aggref *aggref, const char *func_name,
						 Oid pminmax_typeoid)
{
	TargetEntry	   *tle;
	Expr		   *expr;

	Assert(list_length(aggref->args) == 1);
    tle = linitial(aggref->args);
    Assert(IsA(tle, TargetEntry));
	/* cast to pminmax_typeoid, if mismatch */
	expr = make_expr_typecast(tle->expr, pminmax_typeoid);
	/* make conditional if aggref has any filter */
	expr = make_expr_conditional(expr, aggref->aggfilter, false);

	return make_altfunc_simple_expr(func_name, expr);
}

/*
 * make_altfunc_psum - constructor of a SUM/SUM_X2 reference
 */
static FuncExpr *
make_altfunc_psum_expr(Aggref *aggref, const char *func_name, Oid psum_typeoid)
{
	TargetEntry	   *tle;
	Expr		   *expr;

	Assert(list_length(aggref->args) == 1);
	tle = linitial(aggref->args);
	Assert(IsA(tle, TargetEntry));

	/* cast to psum_typeoid, if mismatch */
	expr = make_expr_typecast(tle->expr, psum_typeoid);
	/* make conditional if aggref has any filter */
	expr = make_expr_conditional(expr, aggref->aggfilter, true);

	return make_altfunc_simple_expr(func_name, expr);
}

/*
 * make_altfunc_pcov_xy - constructor of a co-variance arguments
 */
static FuncExpr *
make_altfunc_pcov_xy(Aggref *aggref, const char *func_name)
{
	Oid				namespace_oid = get_namespace_oid("pgstrom", false);
	oidvector	   *func_argtypes;
	Oid				func_argtypes_oid[3];
	Oid				func_oid;
	TargetEntry	   *tle_x;
	TargetEntry	   *tle_y;
	Expr		   *filter_expr;

	Assert(list_length(aggref->args) == 2);
	tle_x = linitial(aggref->args);
	tle_y = lsecond(aggref->args);
	if (exprType((Node *)tle_x->expr) != FLOAT8OID ||
		exprType((Node *)tle_y->expr) != FLOAT8OID)
		elog(ERROR, "Bug? unexpected argument type for co-variance");

	/* lookup pcov_XXX functions */
	func_argtypes_oid[0] = BOOLOID;
	func_argtypes_oid[1] = FLOAT8OID;
	func_argtypes_oid[2] = FLOAT8OID;
	func_argtypes = buildoidvector(func_argtypes_oid, 3);
	func_oid = get_function_oid(func_name,
								func_argtypes,
								namespace_oid, false);
	/* filter if any */
	if (aggref->aggfilter)
		filter_expr = aggref->aggfilter;
	else
		filter_expr = (Expr *)makeBoolConst(true, false);

	return makeFuncExpr(func_oid,
						FLOAT8OID,
						list_make3(filter_expr,
								   tle_x->expr,
								   tle_y->expr),
						InvalidOid,
						InvalidOid,
						COERCE_EXPLICIT_CALL);
}

/*
 * make_alternative_aggref
 *
 * It makes an alternative final aggregate function towards the supplied
 * Aggref, and append its arguments on the target_partial/target_device.
 */
static Node *
make_alternative_aggref(PlannerInfo *root,
						Aggref *aggref,
						PathTarget *target_partial,
						PathTarget *target_device,
						PathTarget *target_input,
						RelOptInfo *input_rel,
						Bitmapset **p_pfunc_bitmap)
{
	const aggfunc_catalog_t *aggfn_cat;
	Aggref	   *aggref_new;
	List	   *altfunc_args = NIL;
	Expr	   *expr_host;
	Oid			namespace_oid;
	Oid			func_oid;
	const char *func_name;
	oidvector  *func_argtypes;
	HeapTuple	tuple;
	int			i;
	Form_pg_proc proc_form;
	Form_pg_aggregate agg_form;

	if (aggref->aggorder || aggref->aggdistinct)
	{
		elog(DEBUG2, "Aggregate with DISTINCT/ORDER BY is not supported: %s",
			 nodeToString(aggref));
		return NULL;
	}
	if (AGGKIND_IS_ORDERED_SET(aggref->aggkind))
	{
		elog(DEBUG2, "ORDERED SET Aggregation is not supported: %s",
			 nodeToString(aggref));
		return NULL;
	}

	/*
	 * Lookup properties of aggregate function
	 */
	aggfn_cat = aggfunc_lookup_by_oid(aggref->aggfnoid);
	if (!aggfn_cat)
	{
		elog(DEBUG2, "Aggregate function is not device executable: %s",
			 format_procedure(aggref->aggfnoid));
		return NULL;
	}
	/* sanity checks */
	Assert(aggref->aggkind == AGGKIND_NORMAL &&
		   !aggref->aggvariadic &&
		   list_length(aggref->args) <= 2);

	/*
	 * construct arguments list of the partial aggregation
	 */
	for (i=0; i < aggfn_cat->partfn_nargs; i++)
	{
		cl_int		action = aggfn_cat->partfn_argexprs[i];
		cl_int		argtype = aggfn_cat->partfn_argtypes[i];
		FuncExpr   *pfunc;

		switch (action)
		{
			case ALTFUNC_EXPR_NROWS:    /* NROWS(X) */
				pfunc = make_altfunc_nrows_expr(aggref);
				break;
			case ALTFUNC_EXPR_PMIN:     /* PMIN(X) */
				pfunc = make_altfunc_minmax_expr(aggref, "pmin", argtype);
				break;
			case ALTFUNC_EXPR_PMAX:     /* PMAX(X) */
				pfunc = make_altfunc_minmax_expr(aggref, "pmax", argtype);
				break;
			case ALTFUNC_EXPR_PSUM:     /* PSUM(X) */
				pfunc = make_altfunc_psum_expr(aggref, "psum", argtype);
				break;
			case ALTFUNC_EXPR_PSUM_X2:  /* PSUM_X2(X) = PSUM(X^2) */
				pfunc = make_altfunc_psum_expr(aggref, "psum_x2", argtype);
				break;
			case ALTFUNC_EXPR_PCOV_X:   /* PCOV_X(X,Y) */
				pfunc = make_altfunc_pcov_xy(aggref, "pcov_x");
				break;
			case ALTFUNC_EXPR_PCOV_Y:   /* PCOV_Y(X,Y) */
				pfunc = make_altfunc_pcov_xy(aggref, "pcov_y");
				break;
			case ALTFUNC_EXPR_PCOV_X2:  /* PCOV_X2(X,Y) */
				pfunc = make_altfunc_pcov_xy(aggref, "pcov_x2");
				break;
			case ALTFUNC_EXPR_PCOV_Y2:  /* PCOV_Y2(X,Y) */
				pfunc = make_altfunc_pcov_xy(aggref, "pcov_y2");
				break;
			case ALTFUNC_EXPR_PCOV_XY:  /* PCOV_XY(X,Y) */
				pfunc = make_altfunc_pcov_xy(aggref, "pcov_xy");
				break;
			default:
				elog(ERROR, "unknown alternative function code: %d", action);
				break;
		}
		/* device executable? */
		if (pfunc->args)
		{
			Node   *temp = replace_expression_by_outerref((Node *)pfunc->args,
														  target_input);
			/*
			 * MEMO: Expressions are replaced to Var-node that references
			 * one of target_input, and these Var-nodes have INDEX_VAR.
			 * So, it is obvious Var-nodes references adeauate input relation,
			 * thus no need to provide relids to pgstrom_device_expression().
			 */
			if (!pgstrom_device_expression(root, NULL, (Expr *)temp))
				return NULL;
		}
		/*
		 * Add partial-aggregate function expression
		 * Also see add_new_column_to_pathtarget().
		 */
		if (!list_member(target_device->exprs, pfunc))
		{
			add_column_to_pathtarget(target_device, (Expr *)pfunc, 0);
			*p_pfunc_bitmap = bms_add_member(*p_pfunc_bitmap,
											 list_length(target_device->exprs) - 1);
		}
		/* append to the argument list */
		altfunc_args = lappend(altfunc_args, (Expr *)pfunc);
	}

	/*
	 * Lookup an alternative function that generates partial state
	 * of the final aggregate function, or varref if internal state
	 * of aggregation is as-is.
	 */
	if (strcmp(aggfn_cat->partfn_name, "varref") == 0)
	{
		Assert(list_length(altfunc_args) == 1);
		expr_host = linitial(altfunc_args);
	}
	else
	{
		Assert(list_length(altfunc_args) == aggfn_cat->partfn_nargs);
		if (strncmp(aggfn_cat->partfn_name, "c:", 2) == 0)
			namespace_oid = PG_CATALOG_NAMESPACE;
		else if (strncmp(aggfn_cat->partfn_name, "s:", 2) == 0)
			namespace_oid = get_namespace_oid("pgstrom", false);
		else
			elog(ERROR, "Bug? incorrect alternative function catalog");

		func_name = aggfn_cat->partfn_name + 2;
		func_argtypes = buildoidvector(aggfn_cat->partfn_argtypes,
									   aggfn_cat->partfn_nargs);
		tuple = SearchSysCache3(PROCNAMEARGSNSP,
								PointerGetDatum(func_name),
								PointerGetDatum(func_argtypes),
								ObjectIdGetDatum(namespace_oid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for function %s",
				 funcname_signature_string(func_name,
										   aggfn_cat->partfn_nargs,
										   NIL,
										   aggfn_cat->partfn_argtypes));
		proc_form = (Form_pg_proc) GETSTRUCT(tuple);
		expr_host = (Expr *)makeFuncExpr(PgProcTupleGetOid(tuple),
										 proc_form->prorettype,
										 altfunc_args,
										 InvalidOid,
										 InvalidOid,
										 COERCE_EXPLICIT_CALL);
		ReleaseSysCache(tuple);
	}
	/* add expression if unique */
	add_new_column_to_pathtarget(target_partial, expr_host);

	/* construction of the final Aggref */
	if (strncmp(aggfn_cat->finalfn_name, "c:", 2) == 0)
		namespace_oid = PG_CATALOG_NAMESPACE;
	else if (strncmp(aggfn_cat->finalfn_name, "s:", 2) == 0)
		namespace_oid = get_namespace_oid("pgstrom", false);
	else
		elog(ERROR, "Bug? incorrect alternative function catalog");

	func_name = aggfn_cat->finalfn_name + 2;
	func_argtypes = buildoidvector(&aggfn_cat->finalfn_argtype, 1);
	func_oid = get_function_oid(func_name,
								func_argtypes,
								namespace_oid, false);
	/* sanity check */
	Assert(aggref->aggtype == get_func_rettype(func_oid));

	tuple = SearchSysCache1(AGGFNOID, ObjectIdGetDatum(func_oid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for pg_aggregate %u", func_oid);
	agg_form = (Form_pg_aggregate) GETSTRUCT(tuple);

	aggref_new = makeNode(Aggref);
	aggref_new->aggfnoid		= func_oid;
	aggref_new->aggtype			= aggref->aggtype;
	aggref_new->aggcollid		= aggref->aggcollid;
	aggref_new->inputcollid		= aggref->inputcollid;
	aggref_new->aggtranstype	= agg_form->aggtranstype;
	aggref_new->aggargtypes		= list_make1_oid(exprType((Node *)expr_host));
	aggref_new->aggdirectargs	= NIL;
	aggref_new->args			= list_make1(makeTargetEntry(expr_host,
															 1,
															 NULL,
															 false));
	aggref_new->aggorder		= NIL;	/* see sanity check */
	aggref_new->aggdistinct		= NIL;	/* see sanity check */
	aggref_new->aggfilter		= NULL;	/* moved to GpuPreAgg */
	aggref_new->aggstar			= false;
	aggref_new->aggvariadic		= false;
	aggref_new->aggkind			= AGGKIND_NORMAL;	/* see sanity check */
	aggref_new->agglevelsup		= 0;
	aggref_new->aggsplit		= AGGSPLIT_SIMPLE;
	aggref_new->location		= aggref->location;

	ReleaseSysCache(tuple);

	return (Node *)aggref_new;
}

typedef struct
{
	bool		device_executable;
	PlannerInfo *root;
	PathTarget *target_upper;
	PathTarget *target_partial;
	PathTarget *target_device;
	PathTarget *target_input;
	RelOptInfo *input_rel;
	Bitmapset  *pfunc_bitmap;
} gpupreagg_build_path_target_context;

static Node *
replace_expression_by_altfunc(Node *node,
							  gpupreagg_build_path_target_context *con)
{
	PathTarget *target_input = con->target_input;
	ListCell   *lc;

	if (!node)
		return NULL;
	if (IsA(node, Aggref))
	{
		Node   *aggfn = make_alternative_aggref(con->root,
												(Aggref *)node,
												con->target_partial,
												con->target_device,
												con->target_input,
												con->input_rel,
												&con->pfunc_bitmap);
		if (!aggfn)
			con->device_executable = false;
		return aggfn;
	}

	foreach (lc, target_input->exprs)
	{
		Expr   *expr_in = lfirst(lc);

		if (equal(node, expr_in))
		{
			add_new_column_to_pathtarget(con->target_partial,
										 copyObject(expr_in));
			add_new_column_to_pathtarget(con->target_device,
										 copyObject(expr_in));
			return copyObject(node);
		}
	}
	if (IsA(node, Var) || IsA(node, PlaceHolderVar))
		elog(ERROR, "Bug? referenced variable is neither grouping-key nor its dependent key: %s",
			 nodeToString(node));
	return expression_tree_mutator(node, replace_expression_by_altfunc, con);
}

/*
 * gpupreagg_build_path_target
 *
 *
 *
 */
static bool
gpupreagg_build_path_target(PlannerInfo *root,			/* in */
							PathTarget *target_upper,	/* in */
							PathTarget *target_final,	/* out */
							PathTarget *target_partial,	/* out */
							PathTarget *target_device,	/* out */
							Path       *input_path,     /* in */
							Bitmapset **p_pfunc_bitmap,	/* out */
							Node **p_havingQual,		/* out */
							bool *p_can_pullup_outerscan) /* out */
{
	gpupreagg_build_path_target_context con;
	Query	   *parse = root->parse;
	PathTarget *target_input = input_path->pathtarget;
	RelOptInfo *input_rel = input_path->parent;
	Node	   *havingQual = NULL;
	ListCell   *lc;
	cl_int		i, j, n;

	memset(&con, 0, sizeof(con));
	con.device_executable = true;
	con.root			= root;
	con.target_upper	= target_upper;
	con.target_partial	= target_partial;
	con.target_device	= target_device;
	con.target_input	= target_input;
	con.input_rel       = input_rel;
	con.pfunc_bitmap    = NULL;

	/*
	 * NOTE: Not to inject unnecessary projection on the sub-path node,
	 * target_device shall be initialized according to the target_input
	 * once, but its sortgrouprefs are not set.
	 */
	n = list_length(target_input->exprs);
	target_device->exprs = copyObject(target_input->exprs);
	target_device->sortgrouprefs = palloc0(sizeof(Index) * (n + 1));

	i = 0;
	foreach (lc, target_upper->exprs)
	{
		Expr   *expr = lfirst(lc);
		Index	sortgroupref = get_pathtarget_sortgroupref(target_upper, i);
	
		if (sortgroupref && parse->groupClause &&
			get_sortgroupref_clause_noerr(sortgroupref,
										  parse->groupClause) != NULL)
		{
			devtype_info   *dtype;
			Oid				coll_oid;
			ListCell	   *cell;

			/*
			 * Type of the grouping-key must have device equality-function
			 */
			dtype = pgstrom_devtype_lookup(exprType((Node *)expr));
			if (!dtype || !dtype->hash_func)
			{
				elog(DEBUG2, "GROUP BY contains unsupported type (%s): %s",
					 format_type_be(exprType((Node *)expr)),
					 nodeToString((Node *)expr));
				return false;
			}
			coll_oid = exprCollation((Node *)expr);
			if (!pgstrom_devfunc_lookup_type_equal(dtype, coll_oid))
			{
				elog(DEBUG2, "GROUP BY contains unsupported type (%s): %s",
					 format_type_be(exprType((Node *)expr)),
					 nodeToString((Node *)expr));
				return false;
			}

			/*
			 * If expression cannot execute on device, unable to pull up
			 * outer scan node. This expression must be calculated on the
			 * host-side.
			 */
			if (!pgstrom_device_expression(root, input_rel, expr))
				*p_can_pullup_outerscan = false;

			/* grouping-key should be on the any of input items */
			j = 0;
			foreach (cell, target_device->exprs)
			{
				if (equal(expr, lfirst(cell)))
				{
					if (target_device->sortgrouprefs[j] != 0)
						elog(ERROR, "Bug? duplicated grouping-keys");
					target_device->sortgrouprefs[j] = sortgroupref;
					break;
				}
				j++;
			}
			if (!cell)
				elog(ERROR, "Bug? grouping-key is not found on input tlist");
			/*
			 * OK, It's a grouping-key column, so add it to both of
			 * the target_final, target_partial and target_device as-is.
			 */
			j=0;
			foreach (cell, target_partial->exprs)
			{
				if (equal(expr, lfirst(cell)) &&
					(!target_partial->sortgrouprefs ||
					 target_partial->sortgrouprefs[j] == 0))
				{
					n = list_length(target_partial->exprs);
					target_partial->sortgrouprefs =
						(!target_partial->sortgrouprefs
						 ? palloc0(sizeof(Index) * (n+1))
						 : repalloc(target_partial->sortgrouprefs,
									sizeof(Index) * (n+1)));
					target_partial->sortgrouprefs[j] = sortgroupref;
					break;
				}
				j++;
			}
			if (!cell)
				add_column_to_pathtarget(target_partial, expr, sortgroupref);

			add_column_to_pathtarget(target_final, expr, sortgroupref);
		}
		else
		{
			Oid		orig_type = exprType((Node *)expr);
			Expr   *temp;

			temp = (Expr *)replace_expression_by_altfunc((Node *)expr, &con);
			if (!con.device_executable)
			{
				elog(DEBUG2, "alt-aggregation is not device executable: %s",
					 nodeToString((Node *)expr));
				return false;
			}
			if (orig_type != exprType((Node *)temp))
				elog(ERROR, "Bug? GpuPreAgg catalog is not consistent: %s",
					 nodeToString(expr));
			add_column_to_pathtarget(target_final, temp, 0);
		}
		i++;
	}

	/*
	 * If there's a HAVING clause, we'll need the Vars/Aggrefs it uses, too.
	 */
	if (parse->havingQual)
	{
		havingQual = replace_expression_by_altfunc(parse->havingQual, &con);
		if (!con.device_executable)
		{
			elog(DEBUG2, "HAVING clause is not device executable: %s",
				 nodeToString((Node *)parse->havingQual));
			return false;
		}
	}
	*p_havingQual = havingQual;

	set_pathtarget_cost_width(root, target_final);
	set_pathtarget_cost_width(root, target_partial);
	set_pathtarget_cost_width(root, target_device);
	*p_pfunc_bitmap = con.pfunc_bitmap;

	return true;
}

/*
 * PlanGpuPreAggPath
 *
 * Entrypoint to create CustomScan node
 */
static Plan *
PlanGpuPreAggPath(PlannerInfo *root,
				  RelOptInfo *rel,
				  struct CustomPath *best_path,
				  List *tlist,
				  List *clauses,
				  List *custom_plans)
{
	CustomScan	   *cscan = makeNode(CustomScan);
	GpuPreAggInfo  *gpa_info;
	PathTarget	   *target_device;
	Bitmapset	   *pfunc_bitmap;
	List		   *tlist_dev = NIL;
	Index			outer_scanrelid = 0;
	Bitmapset	   *referenced = NULL;
	List		   *outer_refs = NIL;
	Plan		   *outer_plan = NULL;
	List		   *outer_tlist = NIL;
	ListCell	   *lc;
	int				index;
	char		   *kern_source;
	codegen_context	context;

	Assert(list_length(best_path->custom_private) == 3);
	gpa_info = linitial(best_path->custom_private);
	target_device = lsecond(best_path->custom_private);
	pfunc_bitmap = lthird(best_path->custom_private);

	Assert(list_length(custom_plans) <= 1);
	if (custom_plans == NIL)
		outer_scanrelid = gpa_info->outer_scanrelid;
	else
	{
		outer_plan = linitial(custom_plans);
		outer_tlist = outer_plan->targetlist;
	}

	/*
	 * Transform expressions in the @target_device to usual TLE form
	 */
	index = 0;
	foreach (lc, target_device->exprs)
	{
		TargetEntry *tle;
		Node	   *node = lfirst(lc);

		Assert(!best_path->path.param_info);
		tle = makeTargetEntry((Expr *)node,
							  index + 1,
							  NULL,
							  false);
		if (target_device->sortgrouprefs &&
			target_device->sortgrouprefs[index])
			tle->ressortgroupref = target_device->sortgrouprefs[index];

		tlist_dev = lappend(tlist_dev, tle);
		index++;
	}

	/*
	 * In case when outer relation scan was pulled-up to the GpuPreAgg,
	 * variables referenced by the outer quals may not appear in the
	 * @target_device. So, add junk ones on demand.
	 * (EXPLAIN needs junk entry to lookup variable name)
	 */
	if (gpa_info->outer_quals)
	{
		List	   *outer_vars;

		if (outer_scanrelid)
			pull_varattnos((Node *)gpa_info->outer_quals,
						   outer_scanrelid, &referenced);

		outer_vars = pull_var_clause((Node *)gpa_info->outer_quals,
									 PVC_RECURSE_AGGREGATES |
									 PVC_RECURSE_WINDOWFUNCS |
									 PVC_INCLUDE_PLACEHOLDERS);
		foreach (lc, outer_vars)
		{
			TargetEntry *tle;
			void		*node = lfirst(lc);

			if (!tlist_member(node, tlist_dev))
			{
				tle =  makeTargetEntry((Expr *)node,
									   list_length(tlist_dev) + 1,
									   NULL,
									   true);
				tlist_dev = lappend(tlist_dev, tle);
			}
		}
	}

	/* pick up referenced columns */
	if (outer_scanrelid)
	{
		RelOptInfo *baserel = root->simple_rel_array[outer_scanrelid];
		int			i, j, k;

		for (i=baserel->min_attr, j=0; i <= baserel->max_attr; i++, j++)
		{
			if (i < 0 || baserel->attr_needed[j] == NULL)
				continue;
			k = i - FirstLowInvalidHeapAttributeNumber;
			referenced = bms_add_member(referenced, k);
		}
		for (k = bms_next_member(referenced, -1);
			 k >= 0;
			 k = bms_next_member(referenced, k))
		{
			i = k + FirstLowInvalidHeapAttributeNumber;
			outer_refs = lappend_int(outer_refs, i);
		}
	}

	/* setup CustomScan node */
	cscan->scan.plan.targetlist = tlist;
	cscan->scan.plan.qual = NIL;
	outerPlan(cscan) = outer_plan;
	cscan->scan.scanrelid = gpa_info->outer_scanrelid;
	cscan->flags = best_path->flags;
	cscan->custom_scan_tlist = tlist_dev;
	cscan->methods = &gpupreagg_scan_methods;

	/*
	 * construction of the GPU kernel code
	 */
	pgstrom_init_codegen_context(&context, root, best_path->path.parent);
	kern_source = gpupreagg_codegen(&context,
									cscan,
									tlist_dev,
									outer_tlist,
									gpa_info,
									pfunc_bitmap);
	gpa_info->kern_source = kern_source;
	gpa_info->extra_flags = context.extra_flags | DEVKERNEL_NEEDS_GPUPREAGG;
	gpa_info->outer_refs = outer_refs;
	gpa_info->used_params = context.used_params;

	form_gpupreagg_info(cscan, gpa_info);

	return &cscan->scan.plan;
}

/*
 * pgstrom_path_is_gpupreagg
 */
bool
pgstrom_path_is_gpupreagg(const Path *pathnode)
{
	if (IsA(pathnode, CustomPath) &&
		pathnode->pathtype == T_CustomScan &&
		((CustomPath *) pathnode)->methods == &gpupreagg_path_methods)
		return true;
	return false;
}

/*
 * pgstrom_plan_is_gpupreagg
 */
bool
pgstrom_plan_is_gpupreagg(const Plan *plan)
{
	if (IsA(plan, CustomScan) &&
		((CustomScan *) plan)->methods == &gpupreagg_scan_methods)
		return true;
	return false;
}

/*
 * pgstrom_planstate_is_gpupreagg
 */
bool
pgstrom_planstate_is_gpupreagg(const PlanState *ps)
{
	if (IsA(ps, CustomScanState) &&
		((CustomScanState *) ps)->methods == &gpupreagg_exec_methods)
		return true;
	return false;
}

/*
 * pgstrom_copy_gpupreagg_path
 */
Path *
pgstrom_copy_gpupreagg_path(const Path *pathnode)
{
	Assert(pgstrom_path_is_gpupreagg(pathnode));
	return pmemdup(pathnode, sizeof(CustomPath));
}

/*
 * make_tlist_device_projection
 *
 * It pulls a set of referenced resource numbers according to the supplied
 * outer_scanrelid/outer_tlist.
 */
typedef struct
{
	Bitmapset  *outer_refs_any;
	Bitmapset  *outer_refs_expr;
	bool		in_expression;
	Index		outer_scanrelid;
	List	   *outer_tlist;
} make_tlist_device_projection_context;

static Node *
__make_tlist_device_projection(Node *node, void *__con)
{
	make_tlist_device_projection_context *con = __con;
	bool	in_expression_saved = con->in_expression;
	int		k;
	Node   *newnode;

	if (!node)
		return NULL;
	if (con->outer_scanrelid > 0)
	{
		Assert(con->outer_tlist == NIL);
		if (IsA(node, Var))
		{
			Var	   *varnode = (Var *) node;
			Var	   *newnode;

			if (varnode->varno != con->outer_scanrelid)
				elog(ERROR, "Bug? varnode references unknown relid: %s",
					 nodeToString(varnode));
			k = varnode->varattno - FirstLowInvalidHeapAttributeNumber;
			con->outer_refs_any = bms_add_member(con->outer_refs_any, k);
			if (con->in_expression)
				con->outer_refs_expr = bms_add_member(con->outer_refs_expr, k);

			Assert(varnode->varlevelsup == 0);
			newnode = makeVar(INDEX_VAR,
							  varnode->varattno,
							  varnode->vartype,
							  varnode->vartypmod,
							  varnode->varcollid,
							  varnode->varlevelsup);
			newnode->varnosyn  = varnode->varno;
			newnode->varattnosyn = varnode->varattno;
			return (Node *) newnode;
		}
	}
	else
	{
		ListCell	   *lc;

		foreach (lc, con->outer_tlist)
		{
			TargetEntry    *tle = lfirst(lc);
			Var			   *newnode;

			if (equal(node, tle->expr))
			{
				k = tle->resno - FirstLowInvalidHeapAttributeNumber;
				con->outer_refs_any = bms_add_member(con->outer_refs_any, k);
				if (con->in_expression)
					con->outer_refs_expr = bms_add_member(con->outer_refs_expr,
														  k);
				newnode = makeVar(INDEX_VAR,
								  tle->resno,
								  exprType((Node *)tle->expr),
								  exprTypmod((Node *)tle->expr),
								  exprCollation((Node *)tle->expr),
								  0);
				if (IsA(node, Var))
				{
					Var	   *varnode = (Var *) node;

					newnode->varnosyn = varnode->varno;
					newnode->varattnosyn = varnode->varattno;
				}
				return (Node *)newnode;
			}
		}

		if (IsA(node, Var))
			elog(ERROR, "Bug? varnode (%s) references unknown outer entry: %s",
				 nodeToString(node),
				 nodeToString(con->outer_tlist));
	}
	con->in_expression = true;
	newnode = expression_tree_mutator(node,
									  __make_tlist_device_projection,
									  con);
	con->in_expression = in_expression_saved;

	return newnode;
}

static List *
make_tlist_device_projection(List *tlist_dev,
							 Index outer_scanrelid,
							 List *outer_tlist,
							 Bitmapset **p_outer_refs_any,
							 Bitmapset **p_outer_refs_expr)
{
	make_tlist_device_projection_context con;
	List	   *tlist_dev_alt = NIL;
	ListCell   *lc;

	memset(&con, 0, sizeof(con));
	con.outer_scanrelid = outer_scanrelid;
	con.outer_tlist = outer_tlist;

	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		TargetEntry	   *tle_new = flatCopyTargetEntry(tle);

		con.in_expression = false;
		tle_new->expr = (Expr *)
			__make_tlist_device_projection((Node *)tle->expr, &con);
		tlist_dev_alt = lappend(tlist_dev_alt, tle_new);
	}
	*p_outer_refs_any = con.outer_refs_any;
	*p_outer_refs_expr = con.outer_refs_expr;

	return tlist_dev_alt;
}

/*
 * gpupreagg_codegen_projection_XXXX - code generator for
 *
 * DEVICE_FUNCTION(void)
 * gpupreagg_projection_row(kern_context *kcxt,
 *                          kern_data_store *kds_src,
 *                          HeapTupleHeaderData *htup,
 *                          Datum *dst_values,
 *                          cl_char *dst_isnull);
 * and
 *
 * DEVICE_FUNCTION(void)
 * gpupreagg_projection_slot(kern_context *kcxt,
 *                           Datum *src_values,
 *                           cl_bool *src_isnull,
 *                           Datum *dst_values,
 *                           cl_bool *dst_values);
 * and
 * DEVICE_FUNCTION(void)
 * gpupreagg_projection_arrow(kern_context *kcxt,
 *                            kern_data_store *kds_src,
 *                            cl_uint src_index,
 *                            Datum *dst_values,
 *                            cl_char *dst_isnull);
 * and
 * DEVICE_FUNCTION(void)
 * gpupreagg_projection_column(kern_context *kcxt,
 *                             kern_data_store *kds,
 *                             kern_data_extra *extra,
 *                             cl_uint rowid,
 *                             cl_char *dst_dclass,
 *                             Datum   *dst_values);
 */
static Expr *
codegen_projection_partial_funcion(FuncExpr *f,
								   codegen_context *context,
								   const char **p_null_const_value)
{
	HeapTuple		tuple;
	Form_pg_proc	proc_form;
	const char	   *proc_name;
	devtype_info   *dtype;
	Expr		   *expr;

	Assert(IsA(f, FuncExpr));
	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(f->funcid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", f->funcid);
	proc_form = (Form_pg_proc) GETSTRUCT(tuple);
	proc_name = NameStr(proc_form->proname);
	if (proc_form->pronamespace != get_namespace_oid("pgstrom", false))
		elog(ERROR, "Bug? unexpected partial aggregate function: %s",
			 format_procedure(f->funcid));

	if (strcmp(proc_name, "nrows") == 0)
	{
		Assert(list_length(f->args) <= 1);
		expr = (Expr *)makeConst(INT8OID,
								 -1,
								 InvalidOid,
								 sizeof(int64),
								 1,
								 false,
								 FLOAT8PASSBYVAL);
		if (f->args)
			expr = make_expr_conditional(expr, linitial(f->args), true);
		*p_null_const_value = "0";
	}
	else if (strcmp(proc_name, "pmin") == 0 ||
			 strcmp(proc_name, "pmax") == 0)
	{
		Assert(list_length(f->args) == 1);
		expr = linitial(f->args);
		dtype = pgstrom_devtype_lookup_and_track(exprType((Node *)expr),
												 context);
		if (!dtype)
			elog(ERROR, "device type lookup failed: %s",
				 format_type_be(exprType((Node *)expr)));
		*p_null_const_value = (strcmp(proc_name, "pmin") == 0
							   ? dtype->max_const
							   : dtype->min_const);
	}
	else if (strcmp(proc_name, "psum") == 0 ||
			 strcmp(proc_name, "psum_x2") == 0)
	{
		Assert(list_length(f->args) == 1);
		expr = linitial(f->args);
		dtype = pgstrom_devtype_lookup_and_track(exprType((Node *)expr),
												 context);
		if (!dtype)
			elog(ERROR, "device type lookup failed: %s",
				 format_type_be(exprType((Node *)expr)));
		if (strcmp(proc_name, "psum_x2") == 0)
		{
			Assert(dtype->type_oid == FLOAT8OID);
			expr = (Expr *)makeFuncExpr(F_FLOAT8MUL,
										FLOAT8OID,
										list_make2(copyObject(expr),
												   copyObject(expr)),
										InvalidOid,
										InvalidOid,
										COERCE_EXPLICIT_CALL);
		}
		*p_null_const_value = dtype->zero_const;		
	}
	else if (strcmp(proc_name, "pcov_x")  == 0 ||
			 strcmp(proc_name, "pcov_y")  == 0 ||
			 strcmp(proc_name, "pcov_x2") == 0 ||
			 strcmp(proc_name, "pcov_y2") == 0 ||
			 strcmp(proc_name, "pcov_xy") == 0)
	{
		Expr   *filter;
		Expr   *x_value;
		Expr   *y_value;

		Assert(list_length(f->args) == 3);
		filter = linitial(f->args);
		x_value = lsecond(f->args);
		y_value = lthird(f->args);

		if (strcmp(proc_name, "pcov_x") == 0)
			expr = x_value;
		else if (strcmp(proc_name, "pcov_y") == 0)
			expr = y_value;
		else if (strcmp(proc_name, "pcov_x2") == 0)
			expr = (Expr *)makeFuncExpr(F_FLOAT8MUL,
										FLOAT8OID,
										list_make2(x_value,
												   x_value),
										InvalidOid,
										InvalidOid,
										COERCE_EXPLICIT_CALL);
		else if (strcmp(proc_name, "pcov_y2") == 0)
			expr = (Expr *)makeFuncExpr(F_FLOAT8MUL,
										FLOAT8OID,
										list_make2(y_value,
												   y_value),
										InvalidOid,
										InvalidOid,
										COERCE_EXPLICIT_CALL);
		else if (strcmp(proc_name, "pcov_xy") == 0)
			expr = (Expr *)makeFuncExpr(F_FLOAT8MUL,
										FLOAT8OID,
										list_make2(x_value,
												   y_value),
										InvalidOid,
										InvalidOid,
										COERCE_EXPLICIT_CALL);
		else
			elog(ERROR, "Bug? unexpected code path");

		Assert(exprType((Node *)filter) == BOOLOID);
		if (IsA(filter, Const) &&
			DatumGetBool(((Const *)filter)->constvalue) &&
			!((Const *)filter)->constisnull)
		{
			*p_null_const_value = "0.0";
		}
		else
		{
			expr = make_expr_conditional(expr, filter, true);
		}
	}
	else
	{
		elog(ERROR, "Bug? unexpected partial aggregate function: %s",
			 format_procedure(f->funcid));
	}
	ReleaseSysCache(tuple);

	return expr;
}

static void
gpupreagg_codegen_projection_row(StringInfo kern,
								 codegen_context *context,
								 List *tlist_alt,
								 Bitmapset *outer_refs_any,
								 Bitmapset *outer_refs_expr,
								 Index outer_scanrelid,
								 List *outer_tlist)
{
	PlannerInfo	   *root = context->root;
	StringInfoData	decl;
	StringInfoData	tbody;		/* Row/Block */
	StringInfoData	sbody;		/* Slot */
	StringInfoData	abody;		/* Arrow */
	StringInfoData	cbody;		/* Column */
	StringInfoData	temp;
	Relation		outer_rel = NULL;
	TupleDesc		outer_desc = NULL;
	List		   *type_oid_list = NIL;
	ListCell	   *lc;
	int				i, k, nattrs;

	initStringInfo(&decl);
	initStringInfo(&tbody);
	initStringInfo(&sbody);
	initStringInfo(&abody);
	initStringInfo(&cbody);
	initStringInfo(&temp);
	context->param_refs = NULL;

	appendStringInfoString(
		&decl,
		"  void        *addr    __attribute__((unused));\n");

	/* open relation if GpuPreAgg looks at physical relation */
	if (outer_scanrelid > 0)
	{
		RangeTblEntry  *rte;

		Assert(outer_scanrelid > 0 &&
			   outer_scanrelid < root->simple_rel_array_size);
		rte = root->simple_rte_array[outer_scanrelid];
		outer_rel = table_open(rte->relid, NoLock);
		outer_desc = RelationGetDescr(outer_rel);
		nattrs = outer_desc->natts;
	}
	else
	{
		Assert(outer_scanrelid == 0);
		nattrs = list_length(outer_tlist);
	}

	/* extract the supplied tuple and load variables */
	if (!bms_is_empty(outer_refs_any))
	{
		for (i=0; i > FirstLowInvalidHeapAttributeNumber; i--)
		{
			k = i - FirstLowInvalidHeapAttributeNumber;
			if (bms_is_member(k, outer_refs_any))
				elog(ERROR, "Bug? system column or whole-row is referenced");
		}

		appendStringInfoString(
			&tbody,
			"  /* extract the given htup and load variables */\n"
			"  EXTRACT_HEAP_TUPLE_BEGIN(addr,kds_src,htup);\n");
		for (i=1; i <= nattrs; i++)
		{
			bool	referenced = false;

			k = i - FirstLowInvalidHeapAttributeNumber;
			if (bms_is_member(k, outer_refs_any))
			{
				devtype_info   *dtype;

				/* data type of the outer relation input stream */
				if (outer_tlist == NIL)
				{
					Form_pg_attribute attr = tupleDescAttr(outer_desc, i-1);
					
					dtype = pgstrom_devtype_lookup_and_track(attr->atttypid,
															 context);
					if (!dtype)
						elog(ERROR, "device type lookup failed: %s",
							 format_type_be(attr->atttypid));
				}
				else
				{
					TargetEntry	   *tle = list_nth(outer_tlist, i-1);
					Oid				type_oid = exprType((Node *)tle->expr);

					dtype = pgstrom_devtype_lookup_and_track(type_oid,
															 context);
					if (!dtype)
						elog(ERROR, "device type lookup failed: %s",
							 format_type_be(type_oid));
				}

				foreach (lc, tlist_alt)
				{
					TargetEntry *tle = lfirst(lc);
					Var		   *varnode;

					if (tle->resjunk)
						continue;
					if (!IsA(tle->expr, Var))
						continue;

					varnode = (Var *) tle->expr;
					if (varnode->varno != INDEX_VAR ||
						varnode->varattno < 1 ||
						varnode->varattno > nattrs)
						elog(ERROR, "Bug? unexpected varnode: %s",
							 nodeToString(varnode));
					if (varnode->varattno != i)
						continue;

					/* row */
					appendStringInfo(
						&temp,
						"  pg_datum_ref(kcxt, temp.%s_v, addr);\n"
						"  pg_datum_store(kcxt, temp.%s_v,\n"
						"                 dst_dclass[%d],\n"
						"                 dst_values[%d]);\n",
						dtype->type_name,
						dtype->type_name,
						tle->resno - 1,
						tle->resno - 1);

					/* slot */
					appendStringInfo(
						&sbody,
						"  dst_dclass[%d] = src_dclass[%d];\n"
						"  dst_values[%d] = src_values[%d];\n",
						tle->resno-1, i-1,
						tle->resno-1, i-1);

					/* arrow */
					appendStringInfo(
						&abody,
						"  pg_datum_ref_arrow(kcxt,temp.%s_v,kds_src,%d,src_index);\n"
						"  pg_datum_store(kcxt, temp.%s_v,\n"
						"                 dst_dclass[%d],\n"
						"                 dst_values[%d]);\n",
						dtype->type_name, i-1,
						dtype->type_name,
						tle->resno-1,
						tle->resno-1);
					/* column */
					appendStringInfo(
						&cbody,
						"  addr = kern_get_datum_column(kds,extra,%d,rowid);\n"
						"  if (!addr)\n"
						"    dst_dclass[%d] = DATUM_CLASS__NULL;\n"
						"  else\n"
						"  {\n"
						"    dst_dclass[%d] = DATUM_CLASS__NORMAL;\n"
						"    dst_values[%d] = %s(addr);\n"
						"  }\n",
						i-1, tle->resno-1, tle->resno-1, tle->resno-1,
						dtype->type_byval
						? (dtype->type_length == 1 ? "READ_INT8_PTR"  :
						   dtype->type_length == 2 ? "READ_INT16_PTR" :
						   dtype->type_length == 4 ? "READ_INT32_PTR" :
						   dtype->type_length == 8 ? "READ_INT64_PTR" : "NO_SUCH_TYPLEN")
						: "PointerGetDatum");
					referenced = true;
				}

				/*
				 * KVAR_x must be set up if variables are referenced by
				 * expressions.
				 */
				if (bms_is_member(k, outer_refs_expr))
				{
					appendStringInfo(
						&decl,
						"  pg_%s_t KVAR_%u;\n",
						dtype->type_name, i);
					/* row */
					appendStringInfo(
						&temp,
						"  pg_datum_ref(kcxt, KVAR_%u, addr);\n", i);
					/* slot */
					appendStringInfo(
						&sbody,
						"  pg_datum_ref_slot(kcxt,KVAR_%u,\n"
						"                    src_dclass[%d],\n"
						"                    src_values[%d]);\n",
						i, i-1, i-1);
					/* arrow */
					if (referenced)
					{
						appendStringInfo(
							&abody,
							"  KVAR_%u = temp.%s_v;\n",
							i, dtype->type_name);
					}
					else
					{
						appendStringInfo(
							&abody,
							"  pg_datum_ref_arrow(kcxt,KVAR_%u,kds_src,%d,src_index);\n",
							i, i-1);
					}
					/* column */
					if (!referenced)
						appendStringInfo(
							&cbody,
							"  addr = kern_get_datum_column(kds,extra,%d,rowid);\n",
							i-1);
					appendStringInfo(
						&cbody,
						"  pg_datum_ref(kcxt, KVAR_%u, addr);\n", i);
				}
				context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
				type_oid_list = list_append_unique_oid(type_oid_list,
													   dtype->type_oid);
				appendStringInfoString(&tbody, temp.data);
                resetStringInfo(&temp);
			}
			appendStringInfoString(
				&temp,
				"  EXTRACT_HEAP_TUPLE_NEXT(addr,kds_src);\n");
		}
		appendStringInfoString(
			&tbody,
			"  EXTRACT_HEAP_TUPLE_END();\n");
	}

	/*
	 * Execute expression and store the value on dst_values/dst_isnull
	 */
	resetStringInfo(&temp);
	foreach (lc, tlist_alt)
	{
		TargetEntry	   *tle = lfirst(lc);
		Expr		   *expr;
		devtype_info   *dtype;
		const char	   *null_const_value = NULL;
		const char	   *projection_label = NULL;

		if (tle->resjunk)
			continue;
		if (IsA(tle->expr, Var))
			continue;	/* should be already loaded */
		if (is_altfunc_expression((Node *)tle->expr))
		{
			FuncExpr   *f = (FuncExpr *) tle->expr;

			expr = codegen_projection_partial_funcion(f,
													  context,
													  &null_const_value);
			projection_label = "aggfunc-arg";
		}
		else if (tle->ressortgroupref)
		{
			expr = tle->expr;
			null_const_value = "0";
			projection_label = "grouping-key";
		}
		else
			elog(ERROR, "Bug? unexpected expression: %s",
                 nodeToString(tle->expr));

		dtype = pgstrom_devtype_lookup_and_track(exprType((Node *)expr),
												 context);
		if (!dtype)
			elog(ERROR, "device type lookup failed: %s",
				 format_type_be(exprType((Node *)expr)));
		appendStringInfo(
			&temp,
			"\n"
			"  /* initial attribute %d (%s) */\n"
			"  temp.%s_v = %s;\n",
			tle->resno, projection_label,
			dtype->type_name,
			pgstrom_codegen_expression((Node *)expr, context));

		appendStringInfo(
			&temp,
			"  pg_datum_store(kcxt, temp.%s_v,\n"
			"                 dst_dclass[%d],\n"
			"                 dst_values[%d]);\n",
			dtype->type_name,
			tle->resno-1,
			tle->resno-1);
		if (null_const_value)
			appendStringInfo(
				&temp,
				"  if (temp.%s_v.isnull)\n"
				"    dst_values[%d] = %s;\n",
				dtype->type_name,
				tle->resno-1,
				null_const_value);
		context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
	}
	appendStringInfoString(&tbody, temp.data);
	appendStringInfoString(&sbody, temp.data);
	appendStringInfoString(&abody, temp.data);
	appendStringInfoString(&cbody, temp.data);

	/* const/params and temporary variable */
	pgstrom_codegen_param_declarations(&decl, context);
	pgstrom_union_type_declarations(&decl, "temp", type_oid_list);

	/* writeout kernel functions */
	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_projection_row(kern_context *kcxt,\n"
		"                         kern_data_store *kds_src,\n"
		"                         HeapTupleHeaderData *htup,\n"
		"                         cl_char *dst_dclass,\n"
		"                         Datum   *dst_values)\n"
		"{\n"
		"%s%s\n%s"
		"}\n\n"
		"#ifdef GPUPREAGG_COMBINED_JOIN\n"
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_projection_slot(kern_context *kcxt,\n"
		"                          cl_char *src_dclass,\n"
		"                          Datum   *src_values,\n"
		"                          cl_char *dst_dclass,\n"
		"                          Datum   *dst_values)\n"
		"{\n"
		"%s%s\n%s"
		"}\n"
		"#endif /* GPUPREAGG_COMBINED_JOIN */\n\n"
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_projection_arrow(kern_context *kcxt,\n"
		"                           kern_data_store *kds_src,\n"
		"                           cl_uint src_index,\n"
		"                           cl_char *dst_dclass,\n"
		"                           Datum   *dst_values)\n"
		"{\n"
		"%s%s\n%s"
		"}\n\n"
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_projection_column(kern_context *kcxt,\n"
		"                            kern_data_store *kds,\n"
		"                            kern_data_extra *extra,\n"
		"                            cl_uint rowid,\n"
		"                            cl_char *dst_dclass,\n"
		"                            Datum   *dst_values)\n"
		"{\n"
		"%s%s\n%s"
		"}\n\n",
		decl.data, context->decl_temp.data,
		tbody.data,
		decl.data, context->decl_temp.data,
		sbody.data,
		decl.data, context->decl_temp.data,
		abody.data,
		decl.data, context->decl_temp.data,
		cbody.data);

	if (outer_rel)
		table_close(outer_rel, NoLock);

	pfree(decl.data);
	pfree(tbody.data);
	pfree(sbody.data);
	pfree(abody.data);
	pfree(temp.data);
}

/*
 * gpupreagg_codegen_hashvalue - code generator for
 *
 * DEVICE_FUNCTION(cl_uint)
 * gpupreagg_hashvalue(kern_context *kcxt,
 *                     cl_uint *crc32_table,
 *                     cl_uint hash_value,
 *                     cl_bool *slot_isnull,
 *                     Datum *slot_values);
 */
static void
gpupreagg_codegen_hashvalue(StringInfo kern,
							codegen_context *context,
							List *tlist_dev)
{
	StringInfoData	decl;
	StringInfoData	body;
	List		   *type_oid_list = NIL;
	ListCell	   *lc;
	bool			is_first_key = true;

	initStringInfo(&decl);
	initStringInfo(&body);
	context->param_refs = NULL;

	appendStringInfoString(
		&decl,
		"  cl_uint      hash = 0xffffffffU;\n");

	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		Oid				type_oid;
		devtype_info   *dtype;

		if (tle->resjunk || !tle->ressortgroupref)
			continue;

		type_oid = exprType((Node *)tle->expr);
		dtype = pgstrom_devtype_lookup_and_track(type_oid, context);
		if (!dtype || !OidIsValid(dtype->type_eqfunc))
			elog(ERROR, "Bug? type (%s) is not supported",
				 format_type_be(type_oid));
		/* load variable */
		appendStringInfo(
			&body,
			"  pg_datum_ref_slot(kcxt,temp.%s_v,\n"
			"                    slot_dclass[%d],\n"
			"                    slot_values[%d]);\n",
			dtype->type_name,
			tle->resno - 1,
			tle->resno - 1);
		/*
		 * update hash value
		 *
		 * NOTE: In case when GROUP BY has multiple keys and identical values
		 * may appear on some of them, we should not merge hash values without
		 * randomization, because (X xor Y) xor Y == X.
		 * We put a simple randomization using magic number (0x9e370001) here,
		 * so it enables to generate different hash value, even if key1 and
		 * key2 has same value.
		 */
		if (!is_first_key)
		{
			appendStringInfo(
				&body,
				"  hash = ((cl_ulong)hash * 0x9e370001UL) >> 32;\n");
		}
		appendStringInfo(
			&body,
			"  hash ^= pg_comp_hash(kcxt, temp.%s_v);\n",
			dtype->type_name);
		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
		is_first_key = false;
	}
	pgstrom_union_type_declarations(&decl, "temp", type_oid_list);

	/* no constants should appear */
	Assert(bms_is_empty(context->param_refs));
	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(cl_uint)\n"
		"gpupreagg_hashvalue(kern_context *kcxt,\n"
		"                    cl_char *slot_dclass,\n"
		"                    Datum   *slot_values)\n"
		"{\n"
		"%s\n%s"
		"  return hash;\n"
		"}\n\n", decl.data, body.data);

	pfree(decl.data);
	pfree(body.data);
}

/*
 * gpupreagg_codegen_keymatch - code generator for
 *
 *
 * DEVICE_FUNCTION(cl_bool)
 * gpupreagg_keymatch(kern_context *kcxt,
 *                    kern_data_store *x_kds, size_t x_index,
 *                    kern_data_store *y_kds, size_t y_index);
 */
static void
gpupreagg_codegen_keymatch(StringInfo kern,
						   codegen_context *context,
						   List *tlist_dev)
{
	StringInfoData	decl;
	StringInfoData	body;
	List		   *type_oid_list = NIL;
	ListCell	   *lc;

	initStringInfo(&decl);
	initStringInfo(&body);
	context->param_refs = NULL;

	appendStringInfoString(
		&decl,
		"  cl_char     *x_dclass = KERN_DATA_STORE_DCLASS(x_kds, x_index);\n"
		"  cl_char     *y_dclass = KERN_DATA_STORE_DCLASS(y_kds, y_index);\n"
		"  Datum       *x_values = KERN_DATA_STORE_VALUES(x_kds, x_index);\n"
		"  Datum       *y_values = KERN_DATA_STORE_VALUES(y_kds, y_index);\n");

	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		Oid				type_oid;
		Oid				coll_oid;
		devtype_info   *dtype;
		devfunc_info   *dfunc;
		devtype_info   *darg1;
		devtype_info   *darg2;
		char		   *cast_darg1 = NULL;
		char		   *cast_darg2 = NULL;

		if (tle->resjunk || !tle->ressortgroupref)
			continue;

		/* find the function to compare this data-type */
		type_oid = exprType((Node *)tle->expr);
		coll_oid = exprCollation((Node *)tle->expr);
		dtype = pgstrom_devtype_lookup_and_track(type_oid, context);
		if (!dtype)
			elog(ERROR, "Bug? type (%s) is not supported at GPU",
				 format_type_be(type_oid));
		dfunc = pgstrom_devfunc_lookup_type_equal(dtype, coll_oid);
		if (!dfunc)
			elog(ERROR, "Bug? type (%s) has no device equality function",
				 format_type_be(type_oid));
		pgstrom_devfunc_track(context, dfunc);
		darg1 = linitial(dfunc->func_args);
		darg2 = lsecond(dfunc->func_args);
		if (dtype->type_oid != darg1->type_oid)
		{
			if (!pgstrom_devtype_can_relabel(dtype->type_oid,
											 darg1->type_oid))
				elog(ERROR, "Bug? no binary compatible cast for %s -> %s",
					 format_type_be(dtype->type_oid),
					 format_type_be(darg1->type_oid));
			cast_darg1 = psprintf("to_%s", darg1->type_name);
		}
		if (dtype->type_oid != darg2->type_oid)
		{
			if (!pgstrom_devtype_can_relabel(dtype->type_oid,
											 darg2->type_oid))
				elog(ERROR, "Bug? no binary compatible cast for %s -> %s",
					 format_type_be(dtype->type_oid),
					 format_type_be(darg2->type_oid));
			cast_darg2 = psprintf("to_%s", darg2->type_name);
		}

		/*
		 * Load the key values, then compare
		 *
		 * Please pay attention that key comparison function may take
		 * arguments in different type, but binary compatible.
		 * Union data structure temp_x/temp_y implicitly convert binary
		 * compatible types, so we don't inject PG_RELABEL operator here.
		 */
		appendStringInfo(
			&body,
			"  pg_datum_ref_slot(kcxt, x_temp.%s_v,\n"
			"                    x_dclass[%d], x_values[%d]);\n"
			"  pg_datum_ref_slot(kcxt, y_temp.%s_v,\n"
			"                    y_dclass[%d], y_values[%d]);\n"
			"  if (!x_temp.%s_v.isnull && !y_temp.%s_v.isnull)\n"
			"  {\n"
			"    if (!EVAL(pgfn_%s(kcxt, %s(x_temp.%s_v), %s(y_temp.%s_v))))\n"
			"      return false;\n"
			"  }\n"
			"  else if ((x_temp.%s_v.isnull && !y_temp.%s_v.isnull) ||\n"
			"           (!x_temp.%s_v.isnull && y_temp.%s_v.isnull))\n"
			"    return false;\n"
			"\n",
			dtype->type_name,
			tle->resno-1, tle->resno-1,
			dtype->type_name,
            tle->resno-1, tle->resno-1,
			dtype->type_name, dtype->type_name,
			dfunc->func_devname,
			cast_darg1 ? cast_darg1 : "", dtype->type_name,
			cast_darg2 ? cast_darg2 : "", dtype->type_name,
			dtype->type_name, dtype->type_name,
			dtype->type_name, dtype->type_name);

		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
		if (cast_darg1)
			pfree(cast_darg1);
		if (cast_darg2)
			pfree(cast_darg2);
	}
	/* declaration of temporary variable */
	pgstrom_union_type_declarations(&decl, "x_temp", type_oid_list);
	pgstrom_union_type_declarations(&decl, "y_temp", type_oid_list);
	/* no constant values should be referenced */
	Assert(bms_is_empty(context->param_refs));

	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(cl_bool)\n"
		"gpupreagg_keymatch(kern_context *kcxt,\n"
		"                   kern_data_store *x_kds, size_t x_index,\n"
		"                   kern_data_store *y_kds, size_t y_index)\n"
		"{\n"
		"%s\n%s"
		"  return true;\n"
		"}\n\n", decl.data, body.data);
	pfree(decl.data);
	pfree(body.data);
}

/*
 * gpupreagg_codegen_common_calc
 *
 * common portion of the gpupreagg_xxxx_calc() kernels
 */
static const char *
gpupreagg_codegen_common_calc(TargetEntry *tle,
							  codegen_context *context,
							  bool is_atomic_ops)
{
	FuncExpr	   *f = (FuncExpr *)tle->expr;
	char		   *func_name;
	devtype_info   *dtype;
	const char	   *aggcalc_ops;
	const char	   *aggcalc_type;
	static char		sbuffer[128];

	/* expression should be one of partial functions */
	if (!IsA(f, FuncExpr))
		elog(ERROR, "Bug? not a partial function expression: %s",
			 nodeToString(f));
	func_name = get_func_name(f->funcid);
	if (strcmp(func_name, "pmin") == 0)
		aggcalc_ops = "min";
	else if (strcmp(func_name, "pmax") == 0)
		aggcalc_ops = "max";
	else if (strcmp(func_name, "nrows") == 0 ||
			 strcmp(func_name, "psum") == 0 ||
			 strcmp(func_name, "psum_x2") == 0 ||
			 strcmp(func_name, "pcov_x") == 0 ||
			 strcmp(func_name, "pcov_y") == 0 ||
			 strcmp(func_name, "pcov_x2") == 0 ||
			 strcmp(func_name, "pcov_y2") == 0 ||
			 strcmp(func_name, "pcov_xy") == 0)
		aggcalc_ops = "add";
	else
		elog(ERROR, "Bug? unexpected partial function expression: %s",
			 nodeToString(f));
	pfree(func_name);

	dtype = pgstrom_devtype_lookup_and_track(f->funcresulttype, context);
	if (!dtype)
		elog(ERROR, "failed on device type lookup: %s",
			 format_type_be(f->funcresulttype));

	switch (dtype->type_oid)
	{
		case INT2OID:
			aggcalc_type = "short";
			break;
		case INT4OID:
		case DATEOID:
			aggcalc_type = "int";
			break;
		case INT8OID:
		case CASHOID:
		case TIMEOID:
		case TIMESTAMPOID:
		case TIMESTAMPTZOID:
			aggcalc_type = "long";
			break;
		case FLOAT4OID:
			aggcalc_type = "float";
			break;
		case FLOAT8OID:
			aggcalc_type = "double";
			break;
		default:
			elog(ERROR, "Bug? %s is not expected to use for GpuPreAgg",
				 format_type_be(dtype->type_oid));
	}
	snprintf(sbuffer, sizeof(sbuffer),
			 "aggcalc_%s_%s_%s",
			 is_atomic_ops ? "atomic" : "normal",
			 aggcalc_ops,
			 aggcalc_type);
	return sbuffer;
}

/*
 * gpupreagg_codegen_local_calc - code generator for local calculation
 */
static void
gpupreagg_codegen_local_calc(StringInfo kern,
							 codegen_context *context,
							 List *tlist_dev)
{
	ListCell   *lc;

	appendStringInfoString(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_local_calc(cl_int attnum,\n"
		"                     cl_char *p_acm_dclass,\n"
		"                     Datum   *p_acm_datum,\n"
		"                     cl_char  new_dclass,\n"
		"                     Datum    new_datum)\n"
		"{\n"
		"  switch (attnum)\n"
		"  {\n");
	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		const char	   *label;

		/* only partial aggregate function's arguments */
		if (tle->resjunk || !is_altfunc_expression((Node *)tle->expr))
			continue;

		label = gpupreagg_codegen_common_calc(tle, context, true);
		appendStringInfo(
			kern,
			"  case %d:\n"
			"    %s(p_acm_dclass,p_acm_datum,new_dclass,new_datum);\n"
			"    break;\n",
			tle->resno - 1,
			label);
	}
	appendStringInfoString(
		kern,
		"  default:\n"
		"    break;\n"
		"  }\n"
		"}\n\n");
}

/*
 * gpupreagg_codegen_global_calc - code generator for global calculation
 */
static void
gpupreagg_codegen_global_calc(StringInfo kern,
							  codegen_context *context,
							  List *tlist_dev)
{
	ListCell   *lc;

	appendStringInfoString(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_global_calc(cl_char *dst_dclass,\n"
		"                      Datum   *dst_values,\n"
		"                      cl_char *src_dclass,\n"
		"                      Datum   *src_values)\n"
		"{\n");
	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		const char	   *label;

		/* only partial aggregate function's arguments */
		if (tle->resjunk || !is_altfunc_expression((Node *)tle->expr))
			continue;

		label = gpupreagg_codegen_common_calc(tle, context, true);
		appendStringInfo(
			kern,
			"  %s(dst_dclass+%d, dst_values+%d, src_dclass[%d], src_values[%d]);\n",
			label,
			tle->resno - 1,
			tle->resno - 1,
			tle->resno - 1,
			tle->resno - 1);
	}
	appendStringInfoString(
		kern,
		"}\n\n");
}

/*
 * gpupreagg_codegen_nogroup_calc - code generator for nogroup calculation
 */
static void
gpupreagg_codegen_nogroup_calc(StringInfo kern,
							   codegen_context *context,
							   List *tlist_dev)
{
	ListCell   *lc;

	appendStringInfoString(
        kern,
		"DEVICE_FUNCTION(void)\n"
		"gpupreagg_nogroup_calc(cl_int attnum,\n"
		"                       cl_char *p_acm_dclass,\n"
		"                       Datum   *p_acm_datum,\n"
		"                       cl_char  new_dclass,\n"
		"                       Datum    new_datum)\n"
		"{\n"
		"  switch (attnum)\n"
		"  {\n");
	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		const char	   *label;

		/* only partial aggregate function's arguments */
		if (tle->resjunk || !is_altfunc_expression((Node *)tle->expr))
			continue;
		label = gpupreagg_codegen_common_calc(tle, context, false);
		appendStringInfo(
			kern,
			"  case %d:\n"
			"    %s(p_acm_dclass, p_acm_datum, new_dclass, new_datum);\n"
			"    break;\n",
			tle->resno - 1,
			label);
	}
	appendStringInfoString(
		kern,
		"  default:\n"
		"    break;\n"
		"  }\n"
		"}\n\n");
}

/*
 * gpupreagg_codegen - entrypoint of code-generator for GpuPreAgg
 */
static char *
gpupreagg_codegen(codegen_context *context,
				  CustomScan *cscan,
				  List *tlist_dev,
				  List *outer_tlist,
				  GpuPreAggInfo *gpa_info,
				  Bitmapset *pfunc_bitmap)
{
	StringInfoData	kern;
	StringInfoData	body;
	Size			length;
	bytea		   *kparam_0;
	cl_char		   *attr_is_preagg;
	List		   *tlist_alt;
	List		   *tlist_fallback = NIL;
	ListCell	   *lc;
	Bitmapset	   *outer_refs_any = NULL;
	Bitmapset	   *outer_refs_expr = NULL;
	size_t			varlena_bufsz = 0;
	int				nfields = list_length(tlist_dev);
	int				i = 0;

	initStringInfo(&kern);
	initStringInfo(&body);
	/*
	 * System constants of GpuPreAgg:
	 * KPARAM_0 is an array of cl_char to inform which field is grouping
	 * keys, or target of (partial) aggregate function.
	 */
	length = sizeof(cl_char) * nfields;
	kparam_0 = palloc0(length + VARHDRSZ);
	SET_VARSIZE(kparam_0, length + VARHDRSZ);
	attr_is_preagg = (cl_char *)VARDATA(kparam_0);
	foreach (lc, tlist_dev)
	{
		attr_is_preagg[i] = (bms_is_member(i, pfunc_bitmap) ? 1 : 0);
		i++;
	}
	context->used_params = list_make1(makeConst(BYTEAOID,
												-1,
												InvalidOid,
												-1,
												PointerGetDatum(kparam_0),
												false,
												false));
	pgstrom_devtype_lookup_and_track(BYTEAOID, context);

	/* gpuscan_quals_eval */
	codegen_gpuscan_quals(&body, context, "gpupreagg",
						  cscan->scan.scanrelid,
						  gpa_info->outer_quals);

	/*
	 * gpupreagg_projection_(row|slot)
	 *
	 * pick up columns which are referenced by the initial projection,
	 * then constructs an alternative tlist that contains Var-node with
     * INDEX_VAR + resno, for convenience of the later stages.
	 */
	tlist_alt = make_tlist_device_projection(tlist_dev,
											 cscan->scan.scanrelid,
											 outer_tlist,
											 &outer_refs_any,
											 &outer_refs_expr);
	Assert(list_length(tlist_alt) == nfields);
	Assert(bms_is_subset(outer_refs_expr, outer_refs_any));

	gpupreagg_codegen_projection_row(&body,
									 context,
									 tlist_alt,
									 outer_refs_any,
									 outer_refs_expr,
									 cscan->scan.scanrelid,
									 outer_tlist);
	varlena_bufsz = (context->varlena_bufsz +
					 MAXALIGN(sizeof(cl_char) * nfields) +	/* tup_values */
					 MAXALIGN(sizeof(Datum)   * nfields) +	/* tup_isnull */
					 MAXALIGN(sizeof(cl_int)  * nfields));	/* tup_extra */

	/* remove junk entries for tlist_fallback */
	foreach (lc, tlist_alt)
	{
		TargetEntry *tle = lfirst(lc);

		if (!tle->resjunk)
			tlist_fallback = lappend(tlist_fallback, tle);
	}
	gpa_info->tlist_fallback = tlist_fallback;
	/* gpupreagg_hashvalue */
	context->varlena_bufsz = 0;
	gpupreagg_codegen_hashvalue(&body, context, tlist_dev);
	varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);

	/* gpupreagg_keymatch */
	context->varlena_bufsz = 0;
	gpupreagg_codegen_keymatch(&body, context, tlist_dev);
	varlena_bufsz = Max(varlena_bufsz, context->varlena_bufsz);

	/* gpupreagg_local_calc */
	gpupreagg_codegen_local_calc(&body, context, tlist_dev);
	/* gpupreagg_global_calc */
	gpupreagg_codegen_global_calc(&body, context, tlist_dev);
	/* gpupreagg_nogroup_calc */
	gpupreagg_codegen_nogroup_calc(&body, context, tlist_dev);
	/* merge above kernel functions */
	appendStringInfoString(&kern, body.data);
	pfree(body.data);

	gpa_info->varlena_bufsz = varlena_bufsz;

	return kern.data;
}

/*
 * fixup_gpupreagg_outer_quals
 *
 * Var nodes in @outer_quals were transformed to INDEX_VAR + resno form
 * through the planner stage, however, executor assumes @outer_quals shall
 * be executed towards the raw-tuples fetched from the outer relation.
 * So, we need to adjust its varno/varattno to reference the original
 * column on the raw-tuple.
 */
static Node *
fixup_gpupreagg_outer_quals(Node *node, List *tlist_dev)
{
	if (!node)
		return NULL;
	if (IsA(node, Var))
	{
		TargetEntry	   *tle;
		Var			   *varnode = (Var *) node;

		if (varnode->varno != INDEX_VAR ||
			varnode->varattno <= 0 ||
			varnode->varattno > list_length(tlist_dev))
			elog(ERROR, "Bug? unexpected Var-node in outer-quals: %s",
				 nodeToString(varnode));
		tle = list_nth(tlist_dev, varnode->varattno - 1);
		if (!IsA(tle->expr, Var))
			elog(ERROR,
				 "Bug? Var-node of outer quals references an expression: %s",
				 nodeToString(varnode));
		return (Node *) copyObject(tle->expr);
	}
	return expression_tree_mutator(node,
								   fixup_gpupreagg_outer_quals,
								   tlist_dev);
}

/*
 * gpupreagg_post_planner
 */
void
gpupreagg_post_planner(PlannedStmt *pstmt, CustomScan *cscan)
{
	GpuPreAggInfo  *gpa_info = deform_gpupreagg_info(cscan);

	gpa_info->outer_quals = (List *)
		fixup_gpupreagg_outer_quals((Node *)gpa_info->outer_quals,
									cscan->custom_scan_tlist);

	form_gpupreagg_info(cscan, gpa_info);
}

/*
 * assign_gpupreagg_session_info
 */
void
assign_gpupreagg_session_info(StringInfo buf, GpuTaskState *gts)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gts;
	CustomScan	   *cscan __attribute__((unused))
		= (CustomScan *) gpas->gts.css.ss.ps.plan;

	Assert(pgstrom_plan_is_gpupreagg(&cscan->scan.plan));
	/*
	 * definition of GPUPREAGG_COMBINED_JOIN disables a dummy definition
	 * of gpupreagg_projection_slot() in cuda_gpujoin.h, and switch to
	 * use the auto-generated one for initial projection of GpuPreAgg.
	 */
	if (gpas->combined_gpujoin)
		appendStringInfo(buf, "#define GPUPREAGG_COMBINED_JOIN 1\n");
}

/*
 * CreateGpuPreAggScanState - constructor of GpuPreAggState
 */
static Node *
CreateGpuPreAggScanState(CustomScan *cscan)
{
	/*
	 * NOTE: Per-query memory context should not be used for GpuPreAggState,
	 * because some of fields may be referenced by the worker threads which
	 * shall no be terminated on error (by the resource-owner cleanup handler
	 * at least), so these memory structure must be kept as long as the
	 * worker threads can live. Likely, CurTransactionContext is a best choice.
	 */
	GpuPreAggState *gpas = MemoryContextAllocZero(CurTransactionContext,
												  sizeof(GpuPreAggState));
	/* Set tag and executor callbacks */
	NodeSetTag(gpas, T_CustomScanState);
	gpas->gts.css.flags = cscan->flags;
	gpas->gts.css.methods = &gpupreagg_exec_methods;

	return (Node *) gpas;
}

/*
 * ExecInitGpuPreAgg
 */
static void
ExecInitGpuPreAgg(CustomScanState *node, EState *estate, int eflags)
{
	Relation		scan_rel = node->ss.ss_currentRelation;
	ExprContext	   *econtext = node->ss.ps.ps_ExprContext;
	GpuPreAggState *gpas = (GpuPreAggState *) node;
	CustomScan	   *cscan = (CustomScan *) node->ss.ps.plan;
	GpuPreAggInfo  *gpa_info = deform_gpupreagg_info(cscan);
	List		   *tlist_dev = cscan->custom_scan_tlist;
	ListCell	   *lc	__attribute__((unused));
	TupleDesc		gpreagg_tupdesc;
	TupleDesc		outer_tupdesc;
	StringInfoData	kern_define;
	ProgramId		program_id;
	size_t			length;
	bool			explain_only = ((eflags & EXEC_FLAG_EXPLAIN_ONLY) != 0);

	Assert(scan_rel ? outerPlan(node) == NULL : outerPlan(cscan) != NULL);
	/* activate a GpuContext for CUDA kernel execution */
	gpas->gts.gcontext = AllocGpuContext(gpa_info->optimal_gpu, false, false);

	/* setup common GpuTaskState fields */
	pgstromInitGpuTaskState(&gpas->gts,
							gpas->gts.gcontext,
							GpuTaskKind_GpuPreAgg,
							gpa_info->outer_refs,
							gpa_info->used_params,
							gpa_info->optimal_gpu,
							gpa_info->outer_nrows_per_block,
							eflags);
	gpas->gts.cb_next_task       = gpupreagg_next_task;
	gpas->gts.cb_terminator_task = gpupreagg_terminator_task;
	gpas->gts.cb_next_tuple      = gpupreagg_next_tuple;
	gpas->gts.cb_process_task    = gpupreagg_process_task;
	gpas->gts.cb_release_task    = gpupreagg_release_task;
	gpas->num_group_keys	= gpa_info->num_group_keys;

	/* initialization of the outer relation */
	if (outerPlan(cscan))
	{
		PlanState  *outer_ps;

		Assert(!scan_rel);
		Assert(!gpa_info->outer_quals );
		outer_ps = ExecInitNode(outerPlan(cscan), estate, eflags);
		if (enable_pullup_outer_join &&
			pgstrom_planstate_is_gpujoin(outer_ps) &&
			!outer_ps->ps_ProjInfo)
		{
			gpas->combined_gpujoin = true;
		}
		outerPlanState(gpas) = outer_ps;
		/* GpuPreAgg don't need re-initialization of projection info */
		outer_tupdesc = planStateResultTupleDesc(outer_ps);
		/* should not have any usage of BRIN-index */
		Assert(!OidIsValid(gpa_info->index_oid));
	}
	else
	{
		Assert(scan_rel != NULL);
		gpas->outer_quals = ExecInitQual(gpa_info->outer_quals,
										 &gpas->gts.css.ss.ps);
		outer_tupdesc = RelationGetDescr(scan_rel);
		pgstromExecInitBrinIndexMap(&gpas->gts,
									gpa_info->index_oid,
									gpa_info->index_conds,
									gpa_info->index_quals);
	}

	/*
	 * Initialization the stuff for CPU fallback.
	 *
	 * Projection from the outer-relation to the custom_scan_tlist is a job
	 * of CPU fallback. It is equivalent to the initial device projection.
	 */
	gpreagg_tupdesc = ExecCleanTypeFromTL(tlist_dev);
	gpas->gpreagg_slot = MakeSingleTupleTableSlot(gpreagg_tupdesc,
												  &TTSOpsVirtual);
	//XXX - tlist_dev and tlist_fallback are compatible; needs Assert()?

	gpas->outer_slot = MakeSingleTupleTableSlot(outer_tupdesc,
												&TTSOpsHeapTuple);
	gpas->outer_proj = ExecBuildProjectionInfo(gpa_info->tlist_fallback,
											   econtext,
											   gpas->gpreagg_slot,
											   &gpas->gts.css.ss.ps,
											   outer_tupdesc);
	/* Template of kds_slot */
	length = KDS_calculateHeadSize(gpreagg_tupdesc);
	gpas->kds_slot_head = MemoryContextAllocZero(CurTransactionContext,
												 length);
	init_kernel_data_store(gpas->kds_slot_head,
						   gpreagg_tupdesc,
						   INT_MAX,		/* to be set individually */
						   KDS_FORMAT_SLOT,
						   INT_MAX);	/* to be set individually */

	/* Save the plan-time estimations */
	gpas->plan_nrows_per_chunk =
		(gpa_info->plan_nchunks > 0
		 ? gpa_info->outer_nrows / gpa_info->plan_nchunks
		 : gpa_info->outer_nrows);
    gpas->plan_nrows_in		= gpa_info->outer_nrows;
	gpas->plan_ngroups		= gpa_info->plan_ngroups;
	gpas->plan_extra_sz		= gpa_info->plan_extra_sz;

	/* Get CUDA program and async build if any */
	if (gpas->combined_gpujoin)
	{
		program_id = GpuJoinCreateCombinedProgram(outerPlanState(gpas),
												  &gpas->gts,
												  gpa_info->extra_flags,
												  gpa_info->varlena_bufsz,
												  gpa_info->kern_source,
												  explain_only);
	}
	else
	{
		initStringInfo(&kern_define);
		pgstrom_build_session_info(&kern_define,
								   &gpas->gts,
								   gpa_info->extra_flags);
		program_id = pgstrom_create_cuda_program(gpas->gts.gcontext,
												 gpa_info->extra_flags,
												 gpa_info->varlena_bufsz,
												 gpa_info->kern_source,
												 kern_define.data,
												 false,
												 explain_only);
		pfree(kern_define.data);
	}
	gpas->gts.program_id = program_id;
}

/*
 * ExecReCheckGpuPreAgg
 */
static bool
ExecReCheckGpuPreAgg(CustomScanState *node, TupleTableSlot *slot)
{
	/*
	 * GpuPreAgg shall be never located under the LockRows, so we don't
	 * expect that we need to have valid EPQ recheck here.
	 */
	return true;
}

/*
 * ExecGpuPreAgg
 */
static TupleTableSlot *
ExecGpuPreAgg(CustomScanState *node)
{
	GpuPreAggState *gpas = (GpuPreAggState *) node;

	ActivateGpuContext(gpas->gts.gcontext);
	if (!gpas->gpa_sstate)
		createGpuPreAggSharedState(gpas, NULL, NULL);
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) pgstromExecGpuTaskState,
					(ExecScanRecheckMtd) ExecReCheckGpuPreAgg);
}

/*
 * ExecEndGpuPreAgg
 */
static void
ExecEndGpuPreAgg(CustomScanState *node)
{
	GpuPreAggState *gpas = (GpuPreAggState *) node;
	GpuTaskRuntimeStat *gt_rtstat = (GpuTaskRuntimeStat *) gpas->gpa_rtstat;
	GpuContext	   *gcontext = gpas->gts.gcontext;
	CUresult		rc;

	/* wait for completion of any asynchronous GpuTask */
	if (gpas->ev_init_fhash)
	{
		GPUCONTEXT_PUSH(gcontext);
		rc = cuEventRecord(gpas->ev_init_fhash,
						   CU_STREAM_PER_THREAD);
		GPUCONTEXT_POP(gcontext);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuEventRecord: %s", errorText(rc));
	}
    SynchronizeGpuContext(gpas->gts.gcontext);
	/* close index related stuff if any */
	pgstromExecEndBrinIndexMap(&gpas->gts);
	/* clean up subtree, if any */
	if (outerPlanState(node))
		ExecEndNode(outerPlanState(node));

	/* release final buffer / hashslot */
	if (gpas->pds_final)
		PDS_release(gpas->pds_final);
	if (gpas->m_fhash)
		gpuMemFree(gcontext, gpas->m_fhash);

	/* release any other resources */
	if (gpas->gpreagg_slot)
		ExecDropSingleTupleTableSlot(gpas->gpreagg_slot);
	if (gpas->outer_slot)
		ExecDropSingleTupleTableSlot(gpas->outer_slot);
	releaseGpuPreAggSharedState(gpas);
	pgstromReleaseGpuTaskState(&gpas->gts, gt_rtstat);
}

/*
 * ExecReScanGpuPreAgg
 */
static void
ExecReScanGpuPreAgg(CustomScanState *node)
{
	GpuPreAggState	   *gpas = (GpuPreAggState *) node;

	/* wait for completion of any asynchronous GpuTask */
	SynchronizeGpuContext(gpas->gts.gcontext);
	/* also rescan subtree, if any */
	if (outerPlanState(node))
		ExecEndNode(outerPlanState(node));
	/* reset shared state */
	resetGpuPreAggSharedState(gpas);
	/* common rescan handling */
	pgstromRescanGpuTaskState(&gpas->gts);
	/* reset other stuff */
	gpas->terminator_done = false;
}

/*
 * ExecGpuPreAggEstimateDSM
 */
static Size
ExecGpuPreAggEstimateDSM(CustomScanState *node, ParallelContext *pcxt)
{
	return (MAXALIGN(sizeof(GpuPreAggSharedState)) +
			pgstromSizeOfBrinIndexMap((GpuTaskState *) node) +
			pgstromEstimateDSMGpuTaskState((GpuTaskState *)node, pcxt));
}

/*
 * ExecGpuPreAggInitDSM
 */
static void
ExecGpuPreAggInitDSM(CustomScanState *node,
					 ParallelContext *pcxt,
					 void *coordinate)
{
	GpuPreAggState *gpas = (GpuPreAggState *) node;

	/* save ParallelContext */
	gpas->gts.pcxt = pcxt;
	on_dsm_detach(pcxt->seg,
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gpas->gts.gcontext));
	/* allocation of shared state */
	createGpuPreAggSharedState(gpas, pcxt, coordinate);
	coordinate = (char *)coordinate + gpas->gpa_sstate->ss_length;
	if (gpas->gts.outer_index_state)
	{
		gpas->gts.outer_index_map = (Bitmapset *)coordinate;
		gpas->gts.outer_index_map->nwords = -1;	/* uninitialized */
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gpas->gts));
	}
	pgstromInitDSMGpuTaskState(&gpas->gts, pcxt, coordinate);
}

/*
 * ExecGpuPreAggInitWorker
 */
static void
ExecGpuPreAggInitWorker(CustomScanState *node,
						shm_toc *toc,
						void *coordinate)
{
	GpuPreAggState		   *gpas = (GpuPreAggState *) node;
	GpuPreAggSharedState   *gpa_sstate = coordinate;

	gpas->gpa_sstate = gpa_sstate;
	gpas->gpa_rtstat = &gpas->gpa_sstate->gpa_rtstat;
	on_dsm_detach(dsm_find_mapping(gpa_sstate->ss_handle),
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gpas->gts.gcontext));
	coordinate = (char *)coordinate + gpa_sstate->ss_length;
	if (gpas->gts.outer_index_state)
	{
		gpas->gts.outer_index_map = (Bitmapset *)coordinate;
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gpas->gts));
	}
	pgstromInitWorkerGpuTaskState(&gpas->gts, coordinate);
}

/*
 * ExecGpuPreAggReInitializeDSM
 */
static void
ExecGpuPreAggReInitializeDSM(CustomScanState *node,
							 ParallelContext *pcxt, void *coordinate)
{
	pgstromReInitializeDSMGpuTaskState((GpuTaskState *) node);
}

/*
 * ExecShutdownGpuPreAgg
 */
static void
ExecShutdownGpuPreAgg(CustomScanState *node)
{
	GpuPreAggState	   *gpas = (GpuPreAggState *) node;
	GpuPreAggRuntimeStat *gpa_rtstat_old = gpas->gpa_rtstat;
	GpuPreAggRuntimeStat *gpa_rtstat_new;

	/*
	 * If this GpuPreAgg node is located under the inner side of
	 * another GpuJoin, it should not be called under the background
	 * worker context, however, ExecShutdown walks down the node.
	 */
	if (!gpa_rtstat_old)
		return;
	/* parallel worker put runtime-stat on ExecEnd handler */
	if (IsParallelWorker())
		mergeGpuTaskRuntimeStatParallelWorker(&gpas->gts, &gpa_rtstat_old->c);
	else
	{
		EState	   *estate = gpas->gts.css.ss.ps.state;

		gpa_rtstat_new = MemoryContextAlloc(estate->es_query_cxt,
											sizeof(GpuPreAggRuntimeStat));
		memcpy(gpa_rtstat_new,
			   gpa_rtstat_old,
			   sizeof(GpuPreAggRuntimeStat));
		gpas->gpa_rtstat = gpa_rtstat_new;
	}
}

/*
 * ExplainGpuPreAgg
 */
static void
ExplainGpuPreAgg(CustomScanState *node, List *ancestors, ExplainState *es)
{
	GpuPreAggState		   *gpas = (GpuPreAggState *) node;
	GpuPreAggRuntimeStat   *gpa_rtstat = gpas->gpa_rtstat;
	CustomScan			   *cscan = (CustomScan *) node->ss.ps.plan;
	GpuPreAggInfo		   *gpa_info = deform_gpupreagg_info(cscan);
	List				   *dcontext;
	List				   *gpu_proj = NIL;
	ListCell			   *lc;
	const char			   *policy;
	char				   *exprstr;

	/* shows reduction policy */
	if (gpas->num_group_keys == 0)
		policy = "NoGroup";
	else
		policy = "Local";
	ExplainPropertyText("Reduction", policy, es);

	if (gpa_rtstat)
		mergeGpuTaskRuntimeStat(&gpas->gts, &gpa_rtstat->c);

	/* Set up deparsing context */
	dcontext = set_deparse_context_planstate(es->deparse_cxt,
                                            (Node *)&gpas->gts.css.ss.ps,
                                            ancestors);
	/* Show device projection (verbose only) */
	if (es->verbose)
	{
		foreach (lc, cscan->custom_scan_tlist)
			gpu_proj = lappend(gpu_proj, ((TargetEntry *) lfirst(lc))->expr);
		if (gpu_proj != NIL)
		{
			exprstr = deparse_expression((Node *)gpu_proj, dcontext,
										 es->verbose, false);
			ExplainPropertyText("GPU Projection", exprstr, es);
		}
	}
	pgstromExplainOuterScan(&gpas->gts,
							dcontext, ancestors, es,
							gpa_info->outer_quals,
							gpa_info->outer_startup_cost,
							gpa_info->outer_total_cost,
							gpa_info->outer_nrows,
							gpa_info->outer_width);
	/* combined GpuJoin + GpuPreAgg? */
	if (gpas->combined_gpujoin)
		ExplainPropertyText("Combined GpuJoin", "enabled", es);
	else if (es->format != EXPLAIN_FORMAT_TEXT)
		ExplainPropertyText("Combined GpuJoin", "disabled", es);
	/* other common fields */
	pgstromExplainGpuTaskState(&gpas->gts, es);
	/* other run-time statistics, if any */
	if (gpa_rtstat)
	{
		uint64		fallback_count
			= pg_atomic_read_u64(&gpa_rtstat->c.fallback_count);

		if (fallback_count > 0)
			ExplainPropertyInteger("Num of CPU fallback rows",
								   NULL, fallback_count, es);
	}
}

/*
 * createGpuPreAggSharedState
 */
static void
createGpuPreAggSharedState(GpuPreAggState *gpas,
						   ParallelContext *pcxt,
						   void *dsm_addr)
{
	EState	   *estate = gpas->gts.css.ss.ps.state;
	GpuPreAggSharedState *gpa_sstate;
	GpuPreAggRuntimeStat *gpa_rtstat;
	size_t		ss_length = MAXALIGN(sizeof(GpuPreAggSharedState));

	if (dsm_addr)
		gpa_sstate = dsm_addr;
	else
		gpa_sstate = MemoryContextAlloc(estate->es_query_cxt, ss_length);
	memset(gpa_sstate, 0, ss_length);
	gpa_sstate->ss_handle = (pcxt ? dsm_segment_handle(pcxt->seg) : UINT_MAX);
	gpa_sstate->ss_length = ss_length;

	gpa_rtstat = &gpa_sstate->gpa_rtstat;
	SpinLockInit(&gpa_rtstat->c.lock);

	gpas->gpa_sstate = gpa_sstate;
	gpas->gpa_rtstat = gpa_rtstat;
}

/*
 * releaseGpuPreAggSharedState
 */
static void
releaseGpuPreAggSharedState(GpuPreAggState *gpas)
{
	/* to be moved to shutdown handler?? */
}

/*
 * resetGpuPreAggSharedState
 */
static void
resetGpuPreAggSharedState(GpuPreAggState *gpas)
{
	/* nothing to do */
}

/*
 * gpupreagg_alloc_final_buffer
 */
static void
gpupreagg_alloc_final_buffer(GpuPreAggState *gpas)
{
	GpuContext	   *gcontext = gpas->gts.gcontext;
	TupleTableSlot *gpa_slot = gpas->gpreagg_slot;
	TupleDesc		gpa_tupdesc = gpa_slot->tts_tupleDescriptor;
	pgstrom_data_store *pds_final;
	size_t			f_hashsize;
	size_t			f_hashlimit;
	CUdeviceptr		m_fhash;
	CUresult		rc;

	if (gpas->pds_final)
		return;

	/* final buffer allocation */
	pds_final = PDS_create_slot(gcontext,
								gpa_tupdesc,
								0xffff8000UL);	/* 4GB - 32KB */
	/* final hash-slot allocation */
	f_hashlimit = (size_t)((double)pds_final->kds.nrooms * 1.33);
	if (gpas->plan_ngroups < 400000)
		f_hashsize = 4 * gpas->plan_ngroups;
	else if (gpas->plan_ngroups < 1200000)
		f_hashsize = 3 * gpas->plan_ngroups;
	else if (gpas->plan_ngroups < 4000000)
		f_hashsize = 2 * gpas->plan_ngroups;
	else if (gpas->plan_ngroups < 10000000)
		f_hashsize = (double)gpas->plan_ngroups * 1.25;
	else
		f_hashsize = gpas->plan_ngroups;

	/* 2MB: minimum guarantee */
	if (offsetof(kern_global_hashslot,
				 hash_slot[f_hashsize]) < (1UL << 21))
	{
		f_hashsize = ((1UL << 21) - offsetof(kern_global_hashslot,
											 hash_slot[0]))
			/ sizeof(pagg_hashslot);
	}

	/*
	 * Hash table allocation up to @f_hashlimit items, however, it initially
	 * uses only @f_hashsize slot. If needs, GPU kernel extends the final
	 * hash table on demand.
	 */
	rc = gpuMemAllocManaged(gcontext,
							&m_fhash,
							offsetof(kern_global_hashslot,
									 hash_slot[f_hashlimit]),
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on gpuMemAllocManaged: %s", errorText(rc));
	gpas->pds_final		= pds_final;
	gpas->m_fhash		= m_fhash;
	gpas->ev_init_fhash	= NULL;
	gpas->f_hashsize	= f_hashsize;
	gpas->f_hashlimit	= f_hashlimit;
}

/*
 * gpupreagg_create_task - constructor of GpuPreAggTask
 */
static GpuTask *
gpupreagg_create_task(GpuPreAggState *gpas,
					  pgstrom_data_store *pds_src,
					  CUdeviceptr m_kmrels,
					  int outer_depth)
{
	GpuContext	   *gcontext = gpas->gts.gcontext;
	//TupleTableSlot *gpa_slot = gpas->gpreagg_slot;
	//TupleDesc		gpa_tupdesc = gpa_slot->tts_tupleDescriptor;
	GpuPreAggTask  *gpreagg;
	bool			with_nvme_strom = false;
	cl_uint			nrows_per_block = 0;
	kern_data_store *kds_slot = gpas->kds_slot_head;
	size_t			unitsz;
	size_t			kds_slot_nrooms;
	size_t			kds_slot_length;
	CUdeviceptr		m_deviceptr;
	CUresult		rc;
	cl_int			sm_count;
	Size			head_sz;
	Size			suspend_sz = 0;
	Size			row_inval_sz = 0;
	Size			kgjoin_len = 0;

	/* allocation of the final-buffer on demand */
	if (!gpas->pds_final)
		gpupreagg_alloc_final_buffer(gpas);

	/* rough estimation of the result buffer */
	if (pds_src)
	{
		cl_uint		__nrooms = pds_src->kds.nitems;

		if (pds_src->kds.format == KDS_FORMAT_BLOCK)
		{
			struct NVMEScanState *nvme_sstate;

			nvme_sstate = gpas->combined_gpujoin
				? ((GpuTaskState *)outerPlanState(gpas))->nvme_sstate
				: gpas->gts.nvme_sstate;

			Assert(nvme_sstate != NULL);
			Assert(pds_src->filedesc.rawfd >= 0 || pds_src->nblocks_uncached == 0);
			with_nvme_strom = (pds_src->nblocks_uncached > 0);
			nrows_per_block = nvme_sstate->nrows_per_block;
			/*
			 * It is arguable whether 150% of nrows_per_block * nitems; which
			 * means number of blocks in KDS_FORMAT_BLOCK, is adeque
			 * estimation, or not.
			 * Suspend/Resume like GpuJoin may make sense for the future
			 * improvement.
			 */
			__nrooms = 1.5 * (double)(__nrooms * nrows_per_block);
		}
		else if (pds_src->kds.format == KDS_FORMAT_ARROW &&
				 pds_src->iovec != NULL)
		{
			with_nvme_strom = true;
		}
		/* Extra buffer for suspend resume */
		sm_count = devAttrs[gcontext->cuda_dindex].MULTIPROCESSOR_COUNT;
		suspend_sz = STROMALIGN(sizeof(gpuscanSuspendContext) *
								GPUKERNEL_MAX_SM_MULTIPLICITY * sm_count);

		unitsz = MAXALIGN((sizeof(Datum) + sizeof(char)) * kds_slot->ncols);
		kds_slot_length = (KERN_DATA_STORE_HEAD_LENGTH(kds_slot) +
						   unitsz * __nrooms);
		kds_slot_length = Max(kds_slot_length, 16<<20);
	}
	else
	{
		/* combined RIGHT OUTER JOIN or terminator task */
		unitsz = MAXALIGN((sizeof(Datum) + sizeof(char)) * kds_slot->ncols);
		kds_slot_length = pgstrom_chunk_size();
	}
	kds_slot_nrooms = (kds_slot_length -
					   KERN_DATA_STORE_HEAD_LENGTH(kds_slot)) / unitsz;
	/* buffer of row-invalidation-map */
	row_inval_sz = STROMALIGN(sizeof(cl_char) * kds_slot_nrooms);

	/* allocation of GpuPreAggTask */
	head_sz = STROMALIGN(offsetof(GpuPreAggTask, kern.kparams) +
						 gpas->gts.kern_params->length);
	if (gpas->combined_gpujoin)
	{
		GpuTaskState   *outer_gts = (GpuTaskState *) outerPlanState(gpas);
		kgjoin_len = GpuJoinSetupTask(NULL, outer_gts, pds_src);
	}

	rc = gpuMemAllocManaged(gcontext,
							&m_deviceptr,
							head_sz + suspend_sz + row_inval_sz + kgjoin_len,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on gpuMemAllocManaged: %s", errorText(rc));
	gpreagg = (GpuPreAggTask *)m_deviceptr;
	memset(gpreagg, 0, head_sz + suspend_sz + row_inval_sz);

	pgstromInitGpuTask(&gpas->gts, &gpreagg->task);
	gpreagg->with_nvme_strom = with_nvme_strom;
	gpreagg->pds_src = pds_src;
	gpreagg->kds_slot = NULL;
	gpreagg->kds_slot_nrooms = kds_slot_nrooms;
	gpreagg->kds_slot_length = kds_slot_length;
	if (gpas->combined_gpujoin)
	{
		GpuTaskState   *outer_gts = (GpuTaskState *) outerPlanState(gpas);
		gpreagg->kgjoin = (kern_gpujoin *)
			((char *)gpreagg + head_sz + suspend_sz + row_inval_sz);
		GpuJoinSetupTask(gpreagg->kgjoin, outer_gts, pds_src);
		gpreagg->m_kmrels = m_kmrels;
		gpreagg->outer_depth = outer_depth;
	}
	else
	{
		Assert(m_kmrels == 0UL);
	}
	/* if any grouping keys, determine the reduction policy later */
	gpreagg->kern.num_group_keys = gpas->num_group_keys;
	gpreagg->kern.hash_size = kds_slot_nrooms; //deprecated?
	gpreagg->kern.suspend_size = suspend_sz;
	gpreagg->kern.row_inval_map_size = row_inval_sz;
	/* kern_parambuf */
	memcpy(KERN_GPUPREAGG_PARAMBUF(&gpreagg->kern),
		   gpas->gts.kern_params,
		   gpas->gts.kern_params->length);

	return &gpreagg->task;
}

/*
 * gpupreagg_next_task
 *
 * callback to construct a new GpuPreAggTask task object based on
 * the input data stream that is scanned.
 */
static GpuTask *
gpupreagg_next_task(GpuTaskState *gts)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gts;
	GpuContext	   *gcontext = gpas->gts.gcontext;
	GpuTask		   *gtask = NULL;
	pgstrom_data_store *pds = NULL;
	CUdeviceptr		m_kmrels = 0UL;

	if (gpas->combined_gpujoin)
	{
		GpuTaskState   *outer_gts = (GpuTaskState *) outerPlanState(gpas);

		if (!GpuJoinInnerPreload(outer_gts, &m_kmrels))
			return NULL;	/* an empty results */
		pds = GpuJoinExecOuterScanChunk(outer_gts);
	}
	else if (gpas->gts.css.ss.ss_currentRelation)
	{
		if (gpas->gts.af_state)
			pds = ExecScanChunkArrowFdw(&gpas->gts);
		else if (gpas->gts.gs_state)
			pds = ExecScanChunkGpuStore(&gpas->gts);
		else
			pds = pgstromExecScanChunk(&gpas->gts);
	}
	else
	{
		PlanState	   *outer_ps = outerPlanState(gpas);
		TupleDesc		tupdesc = ExecGetResultType(outer_ps);
		TupleTableSlot *slot;

		while (true)
		{
			if (gpas->gts.scan_overflow)
			{
				if (gpas->gts.scan_overflow == (void *)(~0UL))
					break;
				slot = gpas->gts.scan_overflow;
				gpas->gts.scan_overflow = NULL;
			}
			else
			{
				slot = ExecProcNode(outer_ps);
				if (TupIsNull(slot))
				{
					gpas->gts.scan_overflow = (void *)(~0UL);
					break;
				}
			}

			/* create a new data-store on demand */
			if (!pds)
			{
				pds = PDS_create_row(gcontext,
									 tupdesc,
									 pgstrom_chunk_size());
			}

			if (!PDS_insert_tuple(pds, slot))
			{
				gpas->gts.scan_overflow = slot;
				break;
			}
		}
	}
	if (pds)
		gtask = gpupreagg_create_task(gpas, pds, m_kmrels, -1);
	return gtask;
}

/*
 * gpupreagg_terminator_task
 */
static GpuTask *
gpupreagg_terminator_task(GpuTaskState *gts, cl_bool *task_is_ready)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gts;

	if (gpas->terminator_done)
		return NULL;

	/*
	 * Do we need to kick RIGHT OUTER JOIN + GpuPreAgg task if combined mode.
	 */
	if (gpas->combined_gpujoin)
	{
		GpuTaskState   *outer_gts = (GpuTaskState *)outerPlanState(gpas);
		CUdeviceptr		m_kmrels = 0UL;
		cl_int			outer_depth;

		/* Has RIGHT/FULL OUTER JOIN? */
		outer_depth = gpujoinNextRightOuterJoinIfAny(outer_gts);
		if (outer_depth > 0 &&
			GpuJoinInnerPreload(outer_gts, &m_kmrels))
			return gpupreagg_create_task(gpas, NULL, m_kmrels, outer_depth);
	}
	/* setup a terminator task */
	gpas->terminator_done = true;
	*task_is_ready = true;
	return gpupreagg_create_task(gpas, NULL, 0UL, -1);
}

/*
 * gpupreagg_next_tuple_fallback
 */
static TupleTableSlot *
gpupreagg_next_tuple_fallback(GpuPreAggState *gpas, GpuPreAggTask *gpreagg)
{
	GpuPreAggRuntimeStat *gpa_rtstat = gpas->gpa_rtstat;
	ExprContext		   *econtext = gpas->gts.css.ss.ps.ps_ExprContext;
	ExprDoneCond		is_done	__attribute__((unused));
	TupleTableSlot	   *slot;
	bool				retval;

	for (;;)
	{
		if (gpreagg->kds_slot)
		{
			/* CPU fallback with partial results */
			kern_data_store *kds_slot = gpreagg->kds_slot;
			cl_char	   *ri_map;
			cl_uint		row_index;

			ri_map = KERN_GPUPREAGG_ROW_INVALIDATION_MAP(&gpreagg->kern);
			row_index = gpas->gts.curr_index++;
			if (row_index >= kds_slot->nitems)
				slot = NULL;
			else
			{
				if (ri_map[row_index])
					continue;
				slot = gpas->gpreagg_slot;
				if (!KDS_fetch_tuple_slot(slot, kds_slot, row_index))
					continue;
			}
			break;
		}
		else if (gpas->combined_gpujoin)
		{
			GpuTaskState   *outer_gts
				= (GpuTaskState *)outerPlanState(gpas);

			slot = gpujoinNextTupleFallback(outer_gts,
											gpreagg->kgjoin,
											gpreagg->pds_src,
											Max(gpreagg->outer_depth, 0));
			if (TupIsNull(slot))
				return NULL;
			/* Run CPU Projection of GpuJoin, instead */
			if (outer_gts->css.ss.ps.ps_ProjInfo)
			{
				outer_gts->css.ss.ps.ps_ExprContext->ecxt_scantuple = slot;
				slot = ExecProject(outer_gts->css.ss.ps.ps_ProjInfo);
			}
			econtext->ecxt_scantuple = slot;
		}
		else
		{
			pgstrom_data_store *pds_src = gpreagg->pds_src;
			/* fetch a tuple from the data-store */
			ExecClearTuple(gpas->outer_slot);
			if (!gpreagg->pds_src ||
				!PDS_fetch_tuple(gpas->outer_slot,
								 pds_src,
								 &gpas->gts))
				return NULL;

			econtext->ecxt_scantuple = gpas->outer_slot;
		}
		pg_atomic_add_fetch_u64(&gpa_rtstat->c.source_nitems, 1L);

		/* filter out the tuple, if any outer quals */
		retval = ExecQual(gpas->outer_quals, econtext);
		if (!retval)
		{
			pg_atomic_add_fetch_u64(&gpa_rtstat->c.nitems_filtered, 1L);
			continue;
		}
		/* makes a projection from the outer-scan to the pseudo-tlist */
		slot = ExecProject(gpas->outer_proj);
		break;
	}
	pg_atomic_add_fetch_u64(&gpa_rtstat->c.fallback_count, 1);
	return slot;
}

/*
 * gpupreagg_next_tuple
 */
static TupleTableSlot *
gpupreagg_next_tuple(GpuTaskState *gts)
{
	GpuPreAggState	   *gpas = (GpuPreAggState *) gts;
	GpuPreAggTask	   *gpreagg = (GpuPreAggTask *) gpas->gts.curr_task;
	pgstrom_data_store *pds_final = gpas->pds_final;
	TupleTableSlot	   *slot = NULL;

	if (gpreagg->task.cpu_fallback)
	{
		slot = gpupreagg_next_tuple_fallback(gpas, gpreagg);
	}
	else if (gpas->gts.curr_index < pds_final->kds.nitems)
	{
		slot = gpas->gpreagg_slot;
		ExecClearTuple(slot);
		PDS_fetch_tuple(slot, pds_final, &gpas->gts);
	}
	return slot;
}

/*
 * gpupreagg_init_final_hash
 */
static void
gpupreagg_init_final_hash(GpuPreAggTask *gpreagg,
						  CUmodule cuda_module)
{
	GpuPreAggState *gpas = (GpuPreAggState *)gpreagg->task.gts;
	CUfunction	kern_init_fhash;
	CUevent		ev_init_fhash;
	CUresult	rc;
	cl_int		grid_sz;
	cl_int		block_sz;
	void	   *kern_args[3];

	pthreadMutexLock(&gpas->f_mutex);
	STROM_TRY();
	{
		if (!gpas->ev_init_fhash)
		{
			rc = cuModuleGetFunction(&kern_init_fhash,
									 cuda_module,
									 "gpupreagg_init_final_hash");
			if (rc != CUDA_SUCCESS)
				werror("failed on cuModuleGetFunction: %s", errorText(rc));

			rc = cuEventCreate(&ev_init_fhash,
							   CU_EVENT_BLOCKING_SYNC);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuEventCreate: %s", errorText(rc));

			rc = gpuOptimalBlockSize(&grid_sz,
									 &block_sz,
									 kern_init_fhash,
									 CU_DEVICE_PER_THREAD,
									 0, 0);
			if (rc != CUDA_SUCCESS)
				werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
			grid_sz = Min(grid_sz, (gpas->f_hashsize +
									block_sz - 1) / block_sz);
			kern_args[0] = &gpas->m_fhash;
			kern_args[1] = &gpas->f_hashsize;
			kern_args[2] = &gpas->f_hashlimit;
			rc = cuLaunchKernel(kern_init_fhash,
								grid_sz, 1, 1,
								block_sz, 1, 1,
								0,
								CU_STREAM_PER_THREAD,
								kern_args,
								NULL);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuLaunchKernel: %s", errorText(rc));

			rc = cuEventRecord(ev_init_fhash,
							   CU_STREAM_PER_THREAD);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuEventRecord: %s", errorText(rc));

			gpas->ev_init_fhash = ev_init_fhash;

			rc = cuStreamSynchronize(CU_STREAM_PER_THREAD);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuStreamSynchronize: %s", errorText(rc));
		}
	}
	STROM_CATCH();
	{
		pthreadMutexUnlock(&gpas->f_mutex);
		STROM_RE_THROW();
	}
	STROM_END_TRY();
	pthreadMutexUnlock(&gpas->f_mutex);
	/* Point of synchronization */
	rc = cuStreamWaitEvent(CU_STREAM_PER_THREAD,
						   gpas->ev_init_fhash,
						   0);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuStreamWaitEvent: %s", errorText(rc));
}

/*
 * gpupreaggUpdateRunTimeStat
 */
static void
gpupreaggUpdateRunTimeStat(GpuTaskState *gts, kern_gpupreagg *kgpreagg)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gts;
	GpuPreAggRuntimeStat *gpa_rtstat = gpas->gpa_rtstat;

	pg_atomic_add_fetch_u64(&gpa_rtstat->c.source_nitems,
							(int64)kgpreagg->nitems_real);
	pg_atomic_add_fetch_u64(&gpa_rtstat->c.nitems_filtered,
							(int64)kgpreagg->nitems_filtered);
	//TODO: other statistics
}

/*
 * gpupreagg_throw_partial_result
 */
static void
gpupreagg_throw_partial_result(GpuPreAggTask *gpreagg,
							   kern_data_store *kds_slot)
{
	GpuContext	   *gcontext = GpuWorkerCurrentContext;
	GpuTaskState   *gts = gpreagg->task.gts;
	GpuPreAggTask  *gresp;		/* responder task */
    size_t          length;
    CUresult        rc;

	/* async prefetch kds_slot; which should be on the device memory */
	rc = cuMemPrefetchAsync((CUdeviceptr) kds_slot,
							gpreagg->kds_slot_length,
							CU_DEVICE_CPU,
							CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemPrefetchAsync: %s", errorText(rc));

	/* setup responder task with supplied @kds_slot */
	length = STROMALIGN(offsetof(GpuPreAggTask, kern.kparams) +
						gpreagg->kern.kparams.length) +
		STROMALIGN(sizeof(cl_char) * gpreagg->kds_slot_nrooms);
	rc = gpuMemAllocManaged(gcontext,
							(CUdeviceptr *)&gresp,
							length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));
	memset(gresp, 0, offsetof(GpuPreAggTask, kern.kparams));
	memcpy(&gresp->kern.kparams,
		   &gpreagg->kern.kparams,
		   gpreagg->kern.kparams.length);
	gresp->task.task_kind	= gpreagg->task.task_kind;
    gresp->task.program_id	= gpreagg->task.program_id;
	gresp->task.cpu_fallback= true;
    gresp->task.gts			= gts;
	gresp->pds_src			= PDS_retain(gpreagg->pds_src);
	gresp->kds_slot			= kds_slot;
	gresp->kds_slot_nrooms	= gpreagg->kds_slot_nrooms;
	gresp->kds_slot_length	= gpreagg->kds_slot_length;
	gresp->kern.row_inval_map_size = gpreagg->kern.row_inval_map_size;
	memcpy(KERN_GPUPREAGG_ROW_INVALIDATION_MAP(&gresp->kern),
		   KERN_GPUPREAGG_ROW_INVALIDATION_MAP(&gpreagg->kern),
		   gresp->kern.row_inval_map_size);

	/* Back GpuTask to GTS */
	pthreadMutexLock(&gcontext->worker_mutex);
	dlist_push_tail(&gts->ready_tasks,
					&gresp->task.chain);
	gts->num_ready_tasks++;
	pthreadMutexUnlock(&gcontext->worker_mutex);

	SetLatch(MyLatch);
}

/*
 * gpupreagg_process_reduction_task
 *
 * main logic to kick GpuPreAgg kernel function.
 */
static int
gpupreagg_process_reduction_task(GpuPreAggTask *gpreagg,
								 CUmodule cuda_module)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gpreagg->task.gts;
	GpuContext	   *gcontext = gpas->gts.gcontext;
	pgstrom_data_store *pds_final = gpas->pds_final;
	pgstrom_data_store *pds_src = gpreagg->pds_src;
	const char	   *kfunc_setup;
	CUfunction		kern_setup;
	CUfunction		kern_reduction;
	CUdeviceptr		m_gpreagg = (CUdeviceptr)&gpreagg->kern;
	CUdeviceptr		m_nullptr = 0UL;
	CUdeviceptr		m_kds_src = 0UL;
	CUdeviceptr		m_kds_extra = 0UL;
	CUdeviceptr		m_kds_slot = 0UL;
	CUdeviceptr		m_kds_final = (CUdeviceptr)&pds_final->kds;
	CUdeviceptr		m_fhash = gpas->m_fhash;
	bool			m_kds_src_release = false;
	cl_int			grid_sz;
	cl_int			block_sz;
	void		   *last_suspend = NULL;
	void		   *kern_args[6];
	void		   *temp;
	CUresult		rc;
	int				retval = 1;

	/*
	 * Ensure the final buffer & hashslot are ready to use
	 */
	gpupreagg_init_final_hash(gpreagg, cuda_module);

	/*
	 * Lookup kernel functions
	 */
	switch (pds_src->kds.format)
	{
		case KDS_FORMAT_ROW:
			kfunc_setup = "kern_gpupreagg_setup_row";
			break;
		case KDS_FORMAT_BLOCK:
			kfunc_setup = "kern_gpupreagg_setup_block";
			break;
		case KDS_FORMAT_ARROW:
			kfunc_setup = "kern_gpupreagg_setup_arrow";
			break;
		case KDS_FORMAT_COLUMN:
			kfunc_setup = "kern_gpupreagg_setup_column";
			break;
		default:
			werror("GpuPreAgg: unknown PDS format: %d", pds_src->kds.format);
	}
	rc = cuModuleGetFunction(&kern_setup,
							 cuda_module,
							 kfunc_setup);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	rc = cuModuleGetFunction(&kern_reduction,
							 cuda_module,
							 gpreagg->kern.num_group_keys == 0
							 ? "kern_gpupreagg_nogroup_reduction"
							 : "kern_gpupreagg_groupby_reduction");
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	/*
	 * Device memory allocation for short term
	 */

	/* kds_src */
	if (gpreagg->with_nvme_strom)
	{
		size_t	required = GPUMEMALIGN(pds_src->kds.length);

		Assert(pds_src->kds.format == KDS_FORMAT_BLOCK ||
			   pds_src->kds.format == KDS_FORMAT_ARROW);
		rc = gpuMemAllocIOMap(gcontext,
							  &m_kds_src,
							  required);
		if (rc == CUDA_SUCCESS)
			m_kds_src_release = true;
		else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		{
			gpreagg->with_nvme_strom = false;
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
				pds_src = PDS_fillup_arrow(gpreagg->pds_src);
				PDS_release(gpreagg->pds_src);
				gpreagg->pds_src = pds_src;
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

	/* kds_slot */
	rc = gpuMemAllocManaged(gcontext,
							&m_kds_slot,
							gpreagg->kds_slot_length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		goto out_of_resource;
	else if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));

	memcpy((void *)m_kds_slot, gpas->kds_slot_head,
		   KERN_DATA_STORE_HEAD_LENGTH(gpas->kds_slot_head));
	((kern_data_store *)m_kds_slot)->length = gpreagg->kds_slot_length;
	((kern_data_store *)m_kds_slot)->nrooms = gpreagg->kds_slot_nrooms;

	/*
	 * OK, kick a series of GpuPreAgg invocations
	 */

	/* source data to be reduced */
	if (gpreagg->with_nvme_strom)
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

	/*
	 * Launch:
	 * gpupreagg_setup_XXXX(kern_gpupreagg *kgpreagg,
	 *                      kern_data_store *kds_src,
	 *                      kern_data_store *kds_slot)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_setup,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
	gpreagg->kern.grid_sz = grid_sz;
	gpreagg->kern.block_sz = block_sz;
resume_kernel:
	/* make kds_slot empty */
	((kern_data_store *)m_kds_slot)->nitems = 0;
	((kern_data_store *)m_kds_slot)->usage = 0;

	kern_args[0] = &m_gpreagg;
	kern_args[1] = &m_kds_src;
	kern_args[2] = &m_kds_extra;
	kern_args[3] = &m_kds_slot;
	rc = cuLaunchKernel(kern_setup,
						gpreagg->kern.grid_sz, 1, 1,
						gpreagg->kern.block_sz, 1, 1,
						sizeof(cl_int) * 1024,	/* for StairlikeSum */
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuLaunchKernel: %s", errorText(rc));

	/*
	 * Launch:
	 * KERNEL_FUNCTION(void)
	 * gpupreagg_XXXX_reduction(kern_gpupreagg *kgpreagg,
	 *                          kern_errorbuf *kgjoin_errorbuf,
	 *                          kern_data_store *kds_slot,
	 *                          kern_data_store *kds_final,
	 *                          kern_global_hashslot *f_hash)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_reduction,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
	kern_args[0] = &m_gpreagg;
	kern_args[1] = &m_nullptr;
	kern_args[2] = &m_kds_slot;
	kern_args[3] = &m_kds_final;
	kern_args[4] = &m_fhash;
	rc = cuLaunchKernel(kern_reduction,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * 1024,	/* for StairlikeSum */
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

	/*
	 * XXX - Even though we speculatively allocate large virtual device
	 * memory, GPU kernel may raise NoDataSpace error.
	 * In this case, we need working device memory.
	 * For pds_final, all we need to do is pre-allocation of very large
	 * virtual device memory with 64bit offset support.
	 * In case of final hash table, we have to re-organize hash table
	 * again, because hash table must be initialized to (0,-1), thus, it
	 * leads page-fault and physical memory allocation. We cannot pre-allocate
	 * too large memory.
	 */

	/*
     * Clear the error code if CPU fallback case.
     * Elsewhere, update run-time statistics.
     */
	memcpy(&gpreagg->task.kerror,
		   &gpreagg->kern.kerror, sizeof(kern_errorbuf));
	if (gpreagg->task.kerror.errcode == ERRCODE_STROM_SUCCESS)
	{
		if (gpreagg->kern.suspend_count > 0)
		{
			CHECK_WORKER_TERMINATION();
			gpupreagg_reset_kernel_task(&gpreagg->kern, true);

			Assert(gpreagg->kern.suspend_size > 0);
			if (!last_suspend)
				last_suspend = alloca(gpreagg->kern.suspend_size);
			temp = KERN_GPUPREAGG_SUSPEND_CONTEXT(&gpreagg->kern, 0);
			memcpy(last_suspend, temp, gpreagg->kern.suspend_size);
			goto resume_kernel;
		}
		gpupreaggUpdateRunTimeStat(gpreagg->task.gts, &gpreagg->kern);
		retval = -1;
	}
	else if (pgstrom_cpu_fallback_enabled &&
			 (gpreagg->task.kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
	{
		memset(&gpreagg->task.kerror, 0, sizeof(kern_errorbuf));
		gpreagg->task.cpu_fallback = true;

		if (!gpreagg->kern.setup_slot_done)
		{
			/*
			 * gpupreagg_setup_xxxx reported CpuReCheck error.
			 * So, here is no partial results, and CPU fallback routine
			 * can generate alternative rows from pds_src.
			 */
			if (pds_src->kds.format == KDS_FORMAT_BLOCK &&
				pds_src->nblocks_uncached > 0)
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
				gpreagg->pds_src = PDS_writeback_arrow(pds_src, m_kds_src);
			}
			/* restore the point where suspended most recently */
			gpreagg->kern.resume_context = (last_suspend != NULL);
			if (last_suspend)
			{
				temp = KERN_GPUPREAGG_SUSPEND_CONTEXT(&gpreagg->kern, 0);
				memcpy(temp, last_suspend, gpreagg->kern.suspend_size);
			}
		}
		else if (gpreagg->kern.suspend_count > 0)
		{
			/*
			 * gpupreagg_setup_xxxx successfully setup kds_slot, however,
			 * reduction kernel reported CpuReCheck error, and GPU kernel
			 * is suspended.
			 */
			kern_data_store	   *kds_slot
				= (kern_data_store *) m_kds_slot;

			CHECK_WORKER_TERMINATION();
			m_kds_slot = (CUdeviceptr) KDS_clone(gcontext, kds_slot);
			gpupreagg_throw_partial_result(gpreagg, kds_slot);

			/* save the suspend status at this point, then resume */
			gpupreagg_reset_kernel_task(&gpreagg->kern, true);
			if (!last_suspend)
				last_suspend = alloca(gpreagg->kern.suspend_size);
			temp = KERN_GPUPREAGG_SUSPEND_CONTEXT(&gpreagg->kern, 0);
			memcpy(last_suspend, temp, gpreagg->kern.suspend_size);
			goto resume_kernel;
		}
		else
		{
			/*
			 * gpupreagg_setup_xxxx successfully setup kds_slot, however,
			 * reduction kernel reported CpuReCheck error. Fortunatelly,
			 * no need to resume the kernel any more.
			 * So, CPU fallback routine runs on kds_slot
			 */
			rc = cuMemPrefetchAsync(m_kds_slot,
									gpreagg->kds_slot_length,
									CU_DEVICE_CPU,
									CU_STREAM_PER_THREAD);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
			gpreagg->kds_slot = (kern_data_store *) m_kds_slot;
			m_kds_slot = 0UL;
		}
		retval = 0;
	}
	else
	{
		/* raise an error */
		gpreagg->task.kerror.errcode &= ~ERRCODE_FLAGS_CPU_FALLBACK;
		retval = 0;
	}
out_of_resource:
	if (m_kds_src_release)
		gpuMemFree(gcontext, m_kds_src);
	if (m_kds_slot != 0UL)
		gpuMemFree(gcontext, m_kds_slot);
	return retval;
}

/*
 * gpupreagg_process_combined_task
 *
 * It runs a combined GpuJoin+GpuPreAgg task.
 */
static int
gpupreagg_process_combined_task(GpuPreAggTask *gpreagg, CUmodule cuda_module)
{
	GpuPreAggState *gpas = (GpuPreAggState *) gpreagg->task.gts;
	GpuContext	   *gcontext = gpas->gts.gcontext;
	pgstrom_data_store *pds_final = gpas->pds_final;
	pgstrom_data_store *pds_src = gpreagg->pds_src;
	kern_gpujoin   *kgjoin = gpreagg->kgjoin;
	CUfunction		kern_gpujoin_main;
	CUfunction		kern_gpupreagg_reduction;
	CUdeviceptr		m_gpreagg = (CUdeviceptr)&gpreagg->kern;
	CUdeviceptr		m_kgjoin = (CUdeviceptr)kgjoin;
	CUdeviceptr		m_kmrels = gpreagg->m_kmrels;
	CUdeviceptr		m_kds_src = 0UL;
	CUdeviceptr		m_kds_extra = 0UL;
	CUdeviceptr		m_kds_slot = 0UL;
	CUdeviceptr		m_kds_final = (CUdeviceptr)&pds_final->kds;
	CUdeviceptr		m_fhash = gpas->m_fhash;
	CUdeviceptr		m_kparams = ((CUdeviceptr)&gpreagg->kern +
								 offsetof(kern_gpupreagg, kparams));
	CUresult		rc;
	bool			m_kds_src_release = false;
	cl_int			grid_sz;
	cl_int			block_sz;
	void		   *kern_args[10];
	void		   *last_suspend = NULL;
	void		   *temp;
	int				retval = 1;

	/*
	 * Ensure the final buffer & hashslot are ready to use
	 */
	gpupreagg_init_final_hash(gpreagg, cuda_module);

	/*
	 * Lookup kernel functions
	 *
	 * XXX - needs to kick RIGHT OUTER JOIN
	 */
	rc = cuModuleGetFunction(&kern_gpujoin_main,
							 cuda_module,
							 pds_src != NULL
							 ? "kern_gpujoin_main"
							 : "kern_gpujoin_right_outer");
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	rc = cuModuleGetFunction(&kern_gpupreagg_reduction,
							 cuda_module,
							 gpreagg->kern.num_group_keys == 0
							 ? "kern_gpupreagg_nogroup_reduction"
							 : "kern_gpupreagg_groupby_reduction");
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction: %s", errorText(rc));

	/* allocation of kds_src */
	if (!pds_src)
		m_kds_src = 0UL;
	else if (gpreagg->with_nvme_strom)
	{
		size_t	required = GPUMEMALIGN(pds_src->kds.length);

		Assert(pds_src->kds.format == KDS_FORMAT_BLOCK ||
			   pds_src->kds.format == KDS_FORMAT_ARROW);
		rc = gpuMemAllocIOMap(gcontext,
							  &m_kds_src,
							  required);
		if (rc == CUDA_SUCCESS)
			m_kds_src_release = true;
		else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		{
			gpreagg->with_nvme_strom = false;
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
				pds_src = PDS_fillup_arrow(gpreagg->pds_src);
				PDS_release(gpreagg->pds_src);
				gpreagg->pds_src = pds_src;
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
	 * allocation of kds_slot
	 */
	rc = gpuMemAllocManaged(gcontext,
							&m_kds_slot,
							gpreagg->kds_slot_length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		goto out_of_resource;
	else if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));

	memcpy((kern_data_store *)m_kds_slot, gpas->kds_slot_head,
		   KERN_DATA_STORE_HEAD_LENGTH(gpas->kds_slot_head));
	((kern_data_store *)m_kds_slot)->length = gpreagg->kds_slot_length;
	((kern_data_store *)m_kds_slot)->nrooms = gpreagg->kds_slot_nrooms;

	/*
	 * OK, kick a series of GpuPreAgg invocations
	 */
	if (pds_src)
	{
		if (gpreagg->with_nvme_strom)
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
				werror("failed on cuMemcpyHtoDAsync: %s", errorText(rc));
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
	}
resume_kernel:
	/* make kds_slot empty again */
	((kern_data_store *)m_kds_slot)->nitems = 0;
	((kern_data_store *)m_kds_slot)->usage = 0;

	/*
	 * Launch:
	 * KERNEL_FUNCTION(void)
	 * gpujoin_main(kern_gpujoin *kgjoin,
	 *              kern_multirels *kmrels,
	 *              kern_data_store *kds_src,
	 *              kern_data_extra *kds_extra,
	 *              kern_data_store *kds_slot,
	 *              kern_parambuf *kparams_gpreagg)
	 * OR
	 *
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
							 0, sizeof(int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
	gpreagg->kern.grid_sz = grid_sz;
	gpreagg->kern.block_sz = block_sz;

	kern_args[0] = &m_kgjoin;
	kern_args[1] = &m_kmrels;
	if (pds_src != NULL)
	{
		kern_args[2] = &m_kds_src;
		kern_args[3] = &m_kds_extra;
		kern_args[4] = &m_kds_slot;
		kern_args[5] = &m_kparams;
	}
	else
	{
		kern_args[2] = &gpreagg->outer_depth;
		kern_args[3] = &m_kds_slot;
		kern_args[4] = &m_kparams;
	}
	rc = cuLaunchKernel(kern_gpujoin_main,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * block_sz,
						CU_STREAM_PER_THREAD,
						kern_args,
						NULL);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuLaunchKernel: %s", errorText(rc));

	/*
	 * Launch:
	 * KERNEL_FUNCTION(void)
	 * gpupreagg_XXXX_reduction(kern_gpupreagg *kgpreagg,
	 *                          kern_errorbuf *kgjoin_errorbuf,
	 *                          kern_data_store *kds_slot,
	 *                          kern_data_store *kds_final,
	 *                          kern_global_hashslot *f_hash)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_gpupreagg_reduction,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));

	kern_args[0] = &m_gpreagg;
	kern_args[1] = &m_kgjoin;
	kern_args[2] = &m_kds_slot;
	kern_args[3] = &m_kds_final;
	kern_args[4] = &m_fhash;
	rc = cuLaunchKernel(kern_gpupreagg_reduction,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * block_sz,	/* for StairlikeSum */
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

	if (kgjoin->kerror.errcode != ERRCODE_STROM_SUCCESS)
	{
		if (pgstrom_cpu_fallback_enabled &&
			(kgjoin->kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
		{
			/*
			 * CPU fallback without partial results - If GpuJoin reported
			 * CpuReCheck error, obviously, it didn't touch the final buffer.
			 * So, CPU fallback routine will generate results based on the
			 * source buffer.
			 */
			memset(&kgjoin->kerror, 0, sizeof(kern_errorbuf));
			gpreagg->task.cpu_fallback = true;

			if (pds_src &&
				pds_src->kds.format == KDS_FORMAT_BLOCK &&
				pds_src->nblocks_uncached > 0)
			{
				rc = cuMemcpyDtoH(&pds_src->kds,
								  m_kds_src,
								  pds_src->kds.length);
				if (rc != CUDA_SUCCESS)
					werror("failed on cuMemcpyDtoH: %s", errorText(rc));
				pds_src->nblocks_uncached = 0;
			}
			else if (pds_src &&
					 pds_src->kds.format == KDS_FORMAT_ARROW &&
					 pds_src->iovec != NULL)
			{
				gpreagg->pds_src = PDS_writeback_arrow(pds_src, m_kds_src);
			}

			/* restore the suspend context if any */
			kgjoin->resume_context = (last_suspend != NULL);
			if (last_suspend)
			{
				memcpy(KERN_GPUJOIN_SUSPEND_CONTEXT(kgjoin, 0),
					   last_suspend,
					   kgjoin->suspend_size);
			}
		}
		memcpy(&gpreagg->task.kerror,
			   &kgjoin->kerror, sizeof(kern_errorbuf));
		retval = 0;
	}
	else if (gpreagg->kern.kerror.errcode != ERRCODE_STROM_SUCCESS)
	{
		if (pgstrom_cpu_fallback_enabled &&
			(gpreagg->kern.kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
		{
			/*
			 * CPU fallback with partial results
			 *
			 * If GpuPreAgg reported CpuReCheck error, it means kds_slot
			 * is successfully built; but a part of them might be already
			 * merged to the final buffer.
			 * CPU fallback routine will run on the kds_slot with row-
			 * invalidation-map
			 */
			memset(&gpreagg->kern.kerror, 0, sizeof(kern_errorbuf));

			Assert(gpreagg->kern.suspend_count == 0);
			if (kgjoin->suspend_count > 0)
			{
				kern_data_store	   *kds_slot
					= (kern_data_store *) m_kds_slot;

				CHECK_WORKER_TERMINATION();
				m_kds_slot = (CUdeviceptr) KDS_clone(gcontext, kds_slot);
				gpupreagg_throw_partial_result(gpreagg, kds_slot);

				/* save the suspend status at this point, then resume */
				gpujoin_reset_kernel_task(kgjoin, true);
				gpupreagg_reset_kernel_task(&gpreagg->kern, false);

				if (!last_suspend)
					last_suspend = alloca(kgjoin->suspend_size);
				temp = KERN_GPUJOIN_SUSPEND_CONTEXT(kgjoin, 0);
				memcpy(last_suspend, temp, kgjoin->suspend_size);
				goto resume_kernel;
			}
			else
			{
				rc = cuMemPrefetchAsync(m_kds_slot,
										gpreagg->kds_slot_length,
										CU_DEVICE_CPU,
										CU_STREAM_PER_THREAD);
				if (rc != CUDA_SUCCESS)
					werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
				gpreagg->task.cpu_fallback = true;
				gpreagg->kds_slot = (kern_data_store *) m_kds_slot;
				m_kds_slot = 0UL;
				retval = 0;
			}
		}
		memcpy(&gpreagg->task.kerror,
			   &gpreagg->kern.kerror, sizeof(kern_errorbuf));
	}
	else
	{
		GpuTaskState   *gjs = (GpuTaskState *)
			outerPlanState(gpreagg->task.gts);
		/*
		 * GpuPreAgg-side has no code path that can cause suspend/resume.
		 * Only GpuJoin-side can break GPU kernel execution.
		 */
		Assert(gpreagg->kern.suspend_count == 0);
		if (kgjoin->suspend_count > 0)
		{
			CHECK_WORKER_TERMINATION();
			gpujoin_reset_kernel_task(kgjoin, true);
			gpupreagg_reset_kernel_task(&gpreagg->kern, false);
			if (!last_suspend)
				last_suspend = alloca(kgjoin->suspend_size);
			memcpy(last_suspend,
				   KERN_GPUJOIN_SUSPEND_CONTEXT(kgjoin, 0),
				   kgjoin->suspend_size);
			goto resume_kernel;
		}
		gpujoinUpdateRunTimeStat(gjs, gpreagg->kgjoin);
        gpupreaggUpdateRunTimeStat(gpreagg->task.gts, &gpreagg->kern);
		retval = -1;
	}
out_of_resource:
	if (m_kds_src_release)
		gpuMemFree(gcontext, m_kds_src);
	if (m_kds_slot)
		gpuMemFree(gcontext, m_kds_slot);
	return retval;
}

/*
 * gpupreagg_process_task
 */
static int
gpupreagg_process_task(GpuTask *gtask, CUmodule cuda_module)
{
	GpuPreAggTask  *gpreagg = (GpuPreAggTask *) gtask;
	pgstrom_data_store *pds_src = gpreagg->pds_src;
	volatile bool	gstore_mapped = false;
	int				retval;
	CUresult		rc;

	STROM_TRY();
	{
		if (pds_src->kds.format == KDS_FORMAT_COLUMN)
		{
			rc = gpuStoreMapDeviceMemory(GpuWorkerCurrentContext, pds_src);
			if (rc != CUDA_SUCCESS)
				werror("failed on gstoreFdwMapDeviceMemory: %s", errorText(rc));
			gstore_mapped = true;
		}
		if (!gpreagg->kgjoin)
			retval = gpupreagg_process_reduction_task(gpreagg, cuda_module);
		else
			retval = gpupreagg_process_combined_task(gpreagg, cuda_module);
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

/*
 * gpupreagg_release_task
 */
static void
gpupreagg_release_task(GpuTask *gtask)
{
	GpuPreAggTask  *gpreagg = (GpuPreAggTask *)gtask;
	GpuContext	   *gcontext = gtask->gts->gcontext;

	if (gpreagg->pds_src)
		PDS_release(gpreagg->pds_src);
	if (gpreagg->kds_slot)
		gpuMemFree(gcontext, (CUdeviceptr)gpreagg->kds_slot);
	gpuMemFree(gcontext, (CUdeviceptr)gpreagg);
}

/*
 * entrypoint of GpuPreAgg
 */
void
pgstrom_init_gpupreagg(void)
{
	/* enable_gpupreagg parameter */
	DefineCustomBoolVariable("pg_strom.enable_gpupreagg",
							 "Enables the use of GPU preprocessed aggregate",
							 NULL,
							 &enable_gpupreagg,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* pg_strom.pullup_outer_join */
	DefineCustomBoolVariable("pg_strom.pullup_outer_join",
							 "Enables to pull up GpuJoin under GpuPreAgg",
							 NULL,
							 &enable_pullup_outer_join,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
#if PG_VERSION_NUM >= 110000
	/* pg_strom.enable_partitionwise_gpupreagg */
	DefineCustomBoolVariable("pg_strom.enable_partitionwise_gpupreagg",
							 "(EXPERIMENTAL) Enables partition wise GpuPreAgg",
							 NULL,
							 &enable_partitionwise_gpupreagg,
							 true,
							 PGC_USERSET,
                             GUC_NOT_IN_SAMPLE,
                             NULL, NULL, NULL);
#else
	enable_partitionwise_gpupreagg = false;
#endif
	/* pg_strom.enable_numeric_aggfuncs */
	DefineCustomBoolVariable("pg_strom.enable_numeric_aggfuncs",
							 "Enables aggregate functions on numeric type",
							 NULL,
							 &enable_numeric_aggfuncs,
							 true,
							 PGC_USERSET,
							 GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* pg_strom.gpupreagg_reduction_threshold */
	DefineCustomRealVariable("pg_strom.gpupreagg_reduction_threshold",
							 "Minimus reduction ratio to use GpuPreAgg",
							 NULL,
							 &gpupreagg_reduction_threshold,
							 20.0,
							 1.0,
							 DBL_MAX,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* initialization of path method table */
	memset(&gpupreagg_path_methods, 0, sizeof(CustomPathMethods));
	gpupreagg_path_methods.CustomName          = "GpuPreAgg";
	gpupreagg_path_methods.PlanCustomPath      = PlanGpuPreAggPath;

	/* initialization of plan method table */
	memset(&gpupreagg_scan_methods, 0, sizeof(CustomScanMethods));
	gpupreagg_scan_methods.CustomName          = "GpuPreAgg";
	gpupreagg_scan_methods.CreateCustomScanState
		= CreateGpuPreAggScanState;
	RegisterCustomScanMethods(&gpupreagg_scan_methods);

	/* initialization of exec method table */
	memset(&gpupreagg_exec_methods, 0, sizeof(CustomExecMethods));
	gpupreagg_exec_methods.CustomName          = "GpuPreAgg";
   	gpupreagg_exec_methods.BeginCustomScan     = ExecInitGpuPreAgg;
	gpupreagg_exec_methods.ExecCustomScan      = ExecGpuPreAgg;
	gpupreagg_exec_methods.EndCustomScan       = ExecEndGpuPreAgg;
	gpupreagg_exec_methods.ReScanCustomScan    = ExecReScanGpuPreAgg;
	gpupreagg_exec_methods.EstimateDSMCustomScan = ExecGpuPreAggEstimateDSM;
    gpupreagg_exec_methods.InitializeDSMCustomScan = ExecGpuPreAggInitDSM;
    gpupreagg_exec_methods.InitializeWorkerCustomScan = ExecGpuPreAggInitWorker;
	gpupreagg_exec_methods.ReInitializeDSMCustomScan = ExecGpuPreAggReInitializeDSM;
	gpupreagg_exec_methods.ShutdownCustomScan  = ExecShutdownGpuPreAgg;
	gpupreagg_exec_methods.ExplainCustomScan   = ExplainGpuPreAgg;
	/* hook registration */
	create_upper_paths_next = create_upper_paths_hook;
	create_upper_paths_hook = gpupreagg_add_grouping_paths;
}
