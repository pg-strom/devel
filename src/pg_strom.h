/*
 * pg_strom.h
 *
 * Header file of pg_strom module
 * --
 * Copyright 2011-2020 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 * Copyright 2014-2020 (C) The PG-Strom Development Team
 *
 * This software is an extension of PostgreSQL; You can use, copy,
 * modify or distribute it under the terms of 'LICENSE' included
 * within this package.
 */
#ifndef PG_STROM_H
#define PG_STROM_H

#include "postgres.h"
#if PG_VERSION_NUM < 100000
#error Base PostgreSQL version must be v10 or later
#endif
#define PG_MAJOR_VERSION		(PG_VERSION_NUM / 100)
#define PG_MINOR_VERSION		(PG_VERSION_NUM % 100)

#include "access/brin.h"
#include "access/brin_revmap.h"
#include "access/generic_xlog.h"
#include "access/gist.h"
#include "access/hash.h"
#include "access/heapam.h"
#if PG_VERSION_NUM >= 130000
#include "access/heaptoast.h"
#endif
#include "access/htup_details.h"
#include "access/reloptions.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#if PG_VERSION_NUM < 130000
#include "access/tuptoaster.h"
#endif
#include "access/twophase.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/objectaccess.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_am.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_extension.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_statistic.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#if PG_VERSION_NUM < 110000
#include "catalog/pg_type_fn.h"
#else
#include "catalog/pg_type_d.h"
#endif
#include "catalog/pg_user_mapping.h"
#include "commands/dbcommands.h"
#include "commands/defrem.h"
#include "commands/event_trigger.h"
#include "commands/explain.h"
#include "commands/proclang.h"
#include "commands/tablespace.h"
#include "commands/trigger.h"
#include "commands/typecmds.h"
#include "commands/variable.h"
#include "common/base64.h"
#include "common/md5.h"
#include "executor/executor.h"
#include "executor/nodeAgg.h"
#include "executor/nodeIndexscan.h"
#include "executor/nodeCustom.h"
#include "executor/nodeSubplan.h"
#include "fmgr.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "funcapi.h"
#include "lib/ilist.h"
#include "lib/stringinfo.h"
#include "libpq/be-fsstubs.h"
#include "libpq/libpq-fs.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "nodes/execnodes.h"
#include "nodes/extensible.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "nodes/plannodes.h"
#include "nodes/primnodes.h"
#include "nodes/readfuncs.h"
#if PG_VERSION_NUM < 120000
#include "nodes/relation.h"
#endif
#if PG_VERSION_NUM >= 120000
#include "nodes/supportnodes.h"
#endif
#if PG_VERSION_NUM >= 120000
#include "optimizer/appendinfo.h"
#endif
#include "optimizer/clauses.h"
#include "optimizer/cost.h"
#if PG_VERSION_NUM >= 120000
#include "optimizer/optimizer.h"
#endif
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "optimizer/plancat.h"
#include "optimizer/planmain.h"
#include "optimizer/planner.h"
#include "optimizer/prep.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/tlist.h"
#if PG_VERSION_NUM < 120000
#include "optimizer/var.h"
#endif
#include "parser/parse_coerce.h"
#include "parser/parsetree.h"
#include "parser/parse_func.h"
#include "parser/parse_oper.h"
#include "parser/scansup.h"
#include "pgstat.h"
#include "port/atomics.h"
#include "postmaster/bgworker.h"
#include "postmaster/postmaster.h"
#include "storage/buf.h"
#include "storage/buf_internals.h"
#include "storage/ipc.h"
#include "storage/itemptr.h"
#include "storage/fd.h"
#include "storage/large_object.h"
#include "storage/latch.h"
#include "storage/lmgr.h"
#include "storage/lock.h"
#include "storage/pg_shmem.h"
#include "storage/predicate.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "storage/shmem.h"
#include "storage/smgr.h"
#include "storage/spin.h"
#include "utils/array.h"
#include "utils/arrayaccess.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "utils/cash.h"
#include "utils/catcache.h"
#include "utils/date.h"
#if PG_VERSION_NUM >= 120000
#include "utils/float.h"
#endif
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/inet.h"
#include "utils/int8.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/numeric.h"
#include "utils/pg_crc.h"
#include "utils/pg_locale.h"
#include "utils/rangetypes.h"
#include "utils/regproc.h"
#include "utils/rel.h"
#include "utils/resowner.h"
#include "utils/ruleutils.h"
#include "utils/selfuncs.h"
#include "utils/snapmgr.h"
#include "utils/spccache.h"
#include "utils/syscache.h"
#if PG_VERSION_NUM < 120000
#include "utils/tqual.h"
#endif
#include "utils/typcache.h"
#include "utils/uuid.h"
#include "utils/varbit.h"
#include "utils/varlena.h"

#define CUDA_API_PER_THREAD_DEFAULT_STREAM		1
#include <cuda.h>
#include <nvrtc.h>
#ifdef WITH_CUFILE
#include <cufile.h>
#endif
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <float.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/vfs.h>

#include "nvme_strom.h"
#include "arrow_defs.h"

/*
 * --------------------------------------------------------------------
 *
 * Configuration sections
 *
 * NOTE: We uses configuration of the host PostgreSQL system, instead of
 * own configure script, not to mismatch prerequisites for module build.
 * However, some (possible) configuration will lead unexpected behavior.
 * So, we put some checks to prevent unexpected host configurations.
 *
 * --------------------------------------------------------------------
 */
#if SIZEOF_DATUM != 8
#error PG-Strom expects 64bit platform
#endif
#if PG_VERSION_NUM < 130000
/*
 * At PG13, 2e4db241bfd3206bad8286f8ffc2db6bbdaefcdf removed
 * '--disable-float4-byval' configure flag, thus, float32 should be
 * always passed by value.
 */
#ifndef USE_FLOAT4_BYVAL
#error PG-Strom expects float32 is referenced by value, not reference
#endif
#endif /* VER < PG13*/
#ifndef USE_FLOAT8_BYVAL
#error PG-Strom expexts float64 is referenced by value, not reference
#endif
#ifndef HAVE_INT64_TIMESTAMP
#error PG-Strom expects timestamp has 64bit integer format
#endif
#include "cuda_common.h"
#include "pg_compat.h"

#define RESTRACK_HASHSIZE		53
typedef struct GpuContext
{
	dlist_node		chain;
	pg_atomic_uint32 refcnt;
	ResourceOwner	resowner;
	/* cuda resources per GpuContext */
	cl_int			cuda_dindex;
	CUdevice		cuda_device;
	CUcontext		cuda_context;
	/* resource management */
	slock_t			restrack_lock;
	dlist_head		restrack[RESTRACK_HASHSIZE];
	/* GPU device memory management */
	pthread_rwlock_t gm_rwlock;
	dlist_head		gm_normal_list;		/* list of device memory segments */
	dlist_head		gm_iomap_list;		/* list of I/O map memory segments */
	dlist_head		gm_managed_list;	/* list of managed memory segments */
	dlist_head		gm_hostmem_list;	/* list of Host memory segments */
	/* error information buffer */
	pg_atomic_uint32 error_level;
	int				error_code;
	const char	   *error_filename;
	int				error_lineno;
	const char	   *error_funcname;
	char			error_message[200];
	/* debug counter */
	pg_atomic_uint64 debug_count1;
	pg_atomic_uint64 debug_count2;
	pg_atomic_uint64 debug_count3;
	pg_atomic_uint64 debug_count4;
	/* management of the work-queue */
	bool			worker_is_running;
	pthread_mutex_t	worker_mutex;
	pthread_cond_t	worker_cond;
	pg_atomic_uint32 terminate_workers;
	dlist_head		pending_tasks;		/* list of GpuTask */
	cl_int			num_workers;
	pg_atomic_uint32 worker_index;
	pthread_t		worker_threads[FLEXIBLE_ARRAY_MEMBER];
} GpuContext;

/* Identifier of the Gpu Programs */
typedef cl_long					ProgramId;
#define INVALID_PROGRAM_ID		(-1L)

/*
 * GpuTask and related
 */
typedef enum {
	GpuTaskKind_GpuScan,
	GpuTaskKind_GpuJoin,
	GpuTaskKind_GpuPreAgg,
	GpuTaskKind_GpuSort,
	GpuTaskKind_PL_CUDA,
} GpuTaskKind;

typedef struct GpuTask				GpuTask;
typedef struct GpuTaskState			GpuTaskState;
typedef struct GpuTaskSharedState	GpuTaskSharedState;
typedef struct ArrowFdwState		ArrowFdwState;
typedef struct GpuStoreFdwState		GpuStoreFdwState;

/*
 * GpuTaskState
 *
 * A common structure of the state machine of GPU related tasks.
 */
struct NVMEScanState;
struct GpuTaskSharedState;

struct GpuTaskState
{
	CustomScanState	css;
	GpuContext	   *gcontext;
	GpuTaskKind		task_kind;		/* one of GpuTaskKind_* */
	ProgramId		program_id;		/* CUDA Program (to be acquired) */
	kern_parambuf  *kern_params;	/* Const/Param buffer */
	cl_int			optimal_gpu;	/* GPU preference on plan time */
	bool			scan_done;		/* True, if no more rows to read */

	/* fields for outer scan */
	Cost			outer_startup_cost;	/* copy from the outer path node */
	Cost			outer_total_cost;	/* copy from the outer path node */
	double			outer_plan_rows;	/* copy from the outer path node */
	int				outer_plan_width;	/* copy from the outer path node */
	cl_uint			outer_nrows_per_block;
	Bitmapset	   *outer_refs;		/* referenced outer attributes */
	Instrumentation	outer_instrument; /* runtime statistics, if any */
	TupleTableSlot *scan_overflow;	/* temporary buffer, if no space on PDS */
	/* BRIN index support on outer relation, if any */
	struct pgstromIndexState *outer_index_state;
	Bitmapset	   *outer_index_map;

	IndexScanDesc	outer_brin_index;	/* brin index of outer scan, if any */
	long			outer_brin_count;	/* # of blocks skipped by index */

	ArrowFdwState  *af_state;			/* for GpuTask on Arrow_Fdw */
	GpuStoreFdwState *gs_state;			/* for GpuTask on Gstore_Fdw */

	/*
	 * A state object for NVMe-Strom. If not NULL, GTS prefers BLOCK format
	 * as source data store. Then, SSD2GPU Direct SQL Execution will be kicked.
	 */
	struct NVMEScanState *nvme_sstate;
	long			nvme_count;			/* # of blocks loaded by SSD2GPU */

	/*
	 * fields to fetch rows from the current task
	 *
	 * NOTE: @curr_index is sufficient to point a particular row of KDS,
	 * if format is ROW, HASH and SLOT. However, BLOCK format has no direct
	 * pointer for each rows. It contains @nitems blocks and individual block
	 * contains uncertain number of rows. So, at BLOCK format, @curr_index
	 * is index of the current block, and @curr_lp_index is also index of
	 * the current line pointer.
	 * For all format, @curr_index == @nitems means no rows any more.
	 */
	cl_long			curr_index;		/* current position on the curr_task */
	cl_long			curr_lp_index;	/* index of LinePointer in a block */
	HeapTupleData	curr_tuple;		/* internal use of PDS_fetch() */
	struct GpuTask *curr_task;	/* a GpuTask currently processed */

	/* callbacks used by gputasks.c */
	GpuTask		 *(*cb_next_task)(GpuTaskState *gts);
	GpuTask		 *(*cb_terminator_task)(GpuTaskState *gts,
										cl_bool *task_is_ready);
	void		  (*cb_switch_task)(GpuTaskState *gts, GpuTask *gtask);
	TupleTableSlot *(*cb_next_tuple)(GpuTaskState *gts);
	int			  (*cb_process_task)(GpuTask *gtask,
									 CUmodule cuda_module);
	void		  (*cb_release_task)(GpuTask *gtask);
	/* list of GpuTasks (protexted with GpuContext->mutex) */
	dlist_head		ready_tasks;	/* list of tasks already processed */
	cl_uint			num_running_tasks;	/* # of running tasks */
	cl_uint			num_ready_tasks;	/* # of ready tasks */

	/* misc fields */
	cl_long			num_cpu_fallbacks;	/* # of CPU fallback chunks */
	uint64			debug_counter0;
	uint64			debug_counter1;
	uint64			debug_counter2;
	uint64			debug_counter3;

	/* co-operation with CPU parallel */
	GpuTaskSharedState *gtss;		/* DSM segment of GTS if any */
	ParallelContext	*pcxt;			/* Parallel context of PostgreSQL */
};

/*
 * GpuTaskSharedState
 */
struct GpuTaskSharedState
{
	/* for arrow_fdw file scan  */
	pg_atomic_uint32 af_rbatch_index;
	/* for gstore_fdw file scan (currently not used) */
	pg_atomic_uint64 gstore_read_pos;
	/* for block-based regular table scan */
	BlockNumber		pbs_nblocks;	/* # blocks in relation at start of scan */
	slock_t			pbs_mutex;		/* lock of the fields below */
	BlockNumber		pbs_startblock;	/* starting block number */
	BlockNumber		pbs_nallocated;	/* # of blocks allocated to workers */

	/* common parallel table scan descriptor */
	ParallelTableScanDescData phscan;
};

/*
 * GpuTaskRuntimeStat - common statistics
 */
typedef struct
{
	slock_t				lock;
	Instrumentation		outer_instrument;
	pg_atomic_uint64	source_nitems;
	pg_atomic_uint64	nitems_filtered;
	pg_atomic_uint64	nvme_count;
	pg_atomic_uint64	brin_count;
	pg_atomic_uint64	fallback_count;
	/* debug counter */
	pg_atomic_uint64	debug_counter0;
	pg_atomic_uint64	debug_counter1;
	pg_atomic_uint64	debug_counter2;
	pg_atomic_uint64	debug_counter3;
} GpuTaskRuntimeStat;

static inline void
mergeGpuTaskRuntimeStatParallelWorker(GpuTaskState *gts,
									  GpuTaskRuntimeStat *gt_rtstat)
{
	Assert(IsParallelWorker());
	if (!gt_rtstat)
		return;
	SpinLockAcquire(&gt_rtstat->lock);
	InstrAggNode(&gt_rtstat->outer_instrument,
				 &gts->outer_instrument);
	SpinLockRelease(&gt_rtstat->lock);
	pg_atomic_add_fetch_u64(&gt_rtstat->nvme_count, gts->nvme_count);
	pg_atomic_add_fetch_u64(&gt_rtstat->brin_count, gts->outer_brin_count);
	pg_atomic_add_fetch_u64(&gt_rtstat->fallback_count,
							gts->num_cpu_fallbacks);
	/* debug counter */
	if (gts->debug_counter0 != 0)
		pg_atomic_add_fetch_u64(&gt_rtstat->debug_counter0, gts->debug_counter0);
	if (gts->debug_counter1 != 0)
		pg_atomic_add_fetch_u64(&gt_rtstat->debug_counter1, gts->debug_counter1);
	if (gts->debug_counter2 != 0)
		pg_atomic_add_fetch_u64(&gt_rtstat->debug_counter2, gts->debug_counter2);
	if (gts->debug_counter3 != 0)
		pg_atomic_add_fetch_u64(&gt_rtstat->debug_counter3, gts->debug_counter3);
}

static inline void
mergeGpuTaskRuntimeStat(GpuTaskState *gts,
						GpuTaskRuntimeStat *gt_rtstat)
{
	InstrAggNode(&gts->outer_instrument,
				 &gt_rtstat->outer_instrument);
	gts->outer_instrument.tuplecount = (double)
		pg_atomic_read_u64(&gt_rtstat->source_nitems);
	gts->outer_instrument.nfiltered1 = (double)
		pg_atomic_read_u64(&gt_rtstat->nitems_filtered);
	gts->nvme_count += pg_atomic_read_u64(&gt_rtstat->nvme_count);
	gts->outer_brin_count += pg_atomic_read_u64(&gt_rtstat->brin_count);
	gts->num_cpu_fallbacks += pg_atomic_read_u64(&gt_rtstat->fallback_count);

	gts->debug_counter0 += pg_atomic_read_u64(&gt_rtstat->debug_counter0);
	gts->debug_counter1 += pg_atomic_read_u64(&gt_rtstat->debug_counter1);
	gts->debug_counter2 += pg_atomic_read_u64(&gt_rtstat->debug_counter2);
	gts->debug_counter3 += pg_atomic_read_u64(&gt_rtstat->debug_counter3);

	if (gts->css.ss.ps.instrument)
		memcpy(&gts->css.ss.ps.instrument->bufusage,
			   &gts->outer_instrument.bufusage,
			   sizeof(BufferUsage));
}

/*
 * GpuTask
 *
 * It is a unit of task to be sent GPU server. Thus, this object must be
 * allocated on the DMA buffer area.
 */
struct GpuTask
{
	kern_errorbuf	kerror;			/* error status of the task */
	dlist_node		chain;			/* link to the task state list */
	GpuTaskKind		task_kind;		/* same with GTS's one */
	ProgramId		program_id;		/* same with GTS's one */
	GpuTaskState   *gts;			/* GTS reference in the backend */
	bool			cpu_fallback;	/* true, if task needs CPU fallback */
};

/*
 * Type declarations for code generator
 */
#define DEVKERNEL_NEEDS_GPUSCAN			0x00000001	/* GpuScan */
#define DEVKERNEL_NEEDS_GPUJOIN			0x00000002	/* GpuJoin */
#define DEVKERNEL_NEEDS_GPUPREAGG		0x00000004	/* GpuPreAgg */
#define DEVKERNEL_NEEDS_GPUSORT			0x00000008	/* GpuSort */

#define DEVKERNEL_NEEDS_PRIMITIVE		0x00000100
#define DEVKERNEL_NEEDS_TIMELIB			0x00000200
#define DEVKERNEL_NEEDS_TEXTLIB			0x00000400
#define DEVKERNEL_NEEDS_JSONLIB			0x00000800
#define DEVKERNEL_NEEDS_MISCLIB			0x00001000
#define DEVKERNEL_NEEDS_RANGETYPE		0x00002000
#define DEVKERNEL_NEEDS_POSTGIS			0x00004000

#define DEVKERNEL_BUILD_DEBUG_INFO		0x80000000

struct devtype_info;
struct devfunc_info;
struct devcast_info;
struct codegen_context;

typedef cl_uint (*devtype_hashfunc_type)(struct devtype_info *dtype,
										 Datum datum);

typedef struct devtype_info {
	dlist_node	chain;
	cl_uint		hashvalue;
	Oid			type_oid;
	uint32		type_flags;
	int16		type_length;
	int16		type_align;
	bool		type_byval;
	bool		type_is_negative;
	const char *type_name;	/* name of device type; same of SQL's type */
	/* oid of type related functions */
	Oid			type_eqfunc;	/* function to check equality */
	Oid			type_cmpfunc;	/* function to compare two values */
	/* constant initializer cstring, if any */
	const char *max_const;
	const char *min_const;
	const char *zero_const;
	/*
	 * required size for extra buffer, if device type has special
	 * internal representation, or device type needs working buffer
	 * on device-side projection.
	 */
	int			extra_sz;
	/* type specific hash-function; to be compatible to device code */
	devtype_hashfunc_type hash_func;
	/* element type of array, if type is array */
	struct devtype_info *type_element;
	/* properties of sub-fields, if type is composite */
	int			comp_nfields;
	struct devtype_info *comp_subtypes[FLEXIBLE_ARRAY_MEMBER];
} devtype_info;

/*
 * Per-function callback to estimate maximum expected length of
 * the function result. -1, if cannot estimate it.
 * If device function may consume per-thread varlena buffer, it
 * should expand context->varlena_bufsz.
 */
typedef int (*devfunc_result_sz_type)(struct codegen_context *context,
									  struct devfunc_info *dfunc,
									  Expr **args, int *args_width);
typedef struct devfunc_info {
	dlist_node	chain;
	cl_uint		hashvalue;
	Oid			func_oid;		/* OID of the SQL function */
	Oid			func_collid;	/* OID of collation, if collation aware */
	bool		func_is_negative;	/* True, if not supported by GPU */
	bool		func_is_strict;		/* True, if NULL strict function */
	/* fields below are valid only if func_is_negative is false */
	int32		func_flags;		/* Extra flags of this function */
	List	   *func_args;		/* argument types by devtype_info */
	devtype_info *func_rettype;	/* result type by devtype_info */
	const char *func_sqlname;	/* name of the function in SQL side */
	const char *func_devname;	/* name of the function in device side */
	Cost		func_devcost;	/* relative cost to run function on GPU */
	devfunc_result_sz_type devfunc_result_sz; /* result width estimator */
} devfunc_info;

/*
 * Callback on CoerceViaIO (type cast using in/out handler).
 * In some special cases, device code can handle this class of type cast.
 */
typedef int (*devcast_coerceviaio_callback_f)(struct codegen_context *context,
											  struct devcast_info *dcast,
											  CoerceViaIO *node);

typedef struct devcast_info {
	dlist_node		chain;
	cl_uint			hashvalue;
	devtype_info   *src_type;
	devtype_info   *dst_type;
	char			castmethod;	/* one of COERCION_METHOD_* */
	devcast_coerceviaio_callback_f dcast_coerceviaio_callback;
} devcast_info;

/*
 * State structure of NVMe-Strom per GpuTaskState
 */
typedef struct GPUDirectFileDesc
{
	int				rawfd;
#ifdef WITH_CUFILE
	CUfileHandle_t	fhandle;
#endif
} GPUDirectFileDesc;

typedef struct NVMEScanState
{
	cl_uint			nrows_per_block;
	cl_uint			nblocks_per_chunk;
	BlockNumber		curr_segno;
	Buffer			curr_vmbuffer;
	BlockNumber		nr_segs;
	GPUDirectFileDesc files[FLEXIBLE_ARRAY_MEMBER];
} NVMEScanState;

/*
 * pgstrom_data_store - a data structure with various format to exchange
 * a data chunk between the host and CUDA server.
 */
typedef struct pgstrom_data_store
{
	/* GpuContext which owns this data store */
	GpuContext		   *gcontext;

	/* reference counter */
	pg_atomic_uint32	refcnt;

	/*
	 * NOTE: Extra information for KDS_FORMAT_BLOCK.
	 * @nblocks_uncached is number of PostgreSQL blocks, to be processed
	 * by NVMe-Strom. If @nblocks_uncached > 0, the tail of PDS shall be
	 * filled up by an array of strom_dma_chunk.
	 * @filedesc is file-descriptor of the underlying blocks.
	 *
	 * NOTE: Extra information for KDS_FORMAT_ARROW
	 * @iovec introduces pairs of destination offset, file offset and
	 * chunk length to be read (usually by SSD-to-GPU Direct SQL).
	 * If NULL, KDS is preliminary loaded by CPU and filesystem, and
	 * PDS is also allocated on managed memory area. So, worker don't
	 * need to kick DMA operations explicitly.
	 *
	 * NOTE: Extra information for KDS_FORMAT_COLUMN
	 * @gs_sstate points the GpuStoreShareState for reference IPC handle
	 * of the main/extra buffer on the device. This IPC handle is only
	 * valid under the read lock.
	 */
	cl_uint				nblocks_uncached;	/* for KDS_FORMAT_BLOCK */
	GPUDirectFileDesc	filedesc;
	strom_io_vector	   *iovec;				/* for KDS_FORMAT_ARROW */
	/* for KDS_FORMAT_COLUMN */
	void			   *gs_sstate;
	CUdeviceptr			m_kds_base;
	CUdeviceptr			m_kds_extra;
	/* data chunk in kernel portion */
	kern_data_store kds	__attribute__ ((aligned (STROMALIGN_LEN)));
} pgstrom_data_store;

/* --------------------------------------------------------------------
 *
 * PG-Strom GUC variables
 *
 * -------------------------------------------------------------------- */
extern bool		pgstrom_enabled;
extern bool		pgstrom_bulkexec_enabled;
extern bool		pgstrom_cpu_fallback_enabled;
extern bool		pgstrom_regression_test_mode;
extern int		pgstrom_max_async_tasks;
extern double	pgstrom_gpu_setup_cost;
extern double	pgstrom_gpu_dma_cost;
extern double	pgstrom_gpu_operator_cost;
extern Size		pgstrom_chunk_size(void);
extern long		PAGE_SIZE;
extern long		PAGE_MASK;
extern int		PAGE_SHIFT;
extern long		PHYS_PAGES;
#define PAGE_ALIGN(sz)		TYPEALIGN(PAGE_SIZE,(sz))

/* --------------------------------------------------------------------
 *
 * Function Declarations
 *
 * -------------------------------------------------------------------- */

/*
 * gpu_device.c
 */
typedef struct DevAttributes
{
	cl_int		NUMA_NODE_ID;
	cl_int		DEV_ID;
	char		DEV_NAME[256];
	char		DEV_BRAND[16];
	char		DEV_UUID[48];
	size_t		DEV_TOTAL_MEMSZ;
	size_t		DEV_BAR1_MEMSZ;
	bool		DEV_SUPPORT_GPUDIRECT;
#define DEV_ATTR(LABEL,a,b,c)		\
	cl_int		LABEL;
#include "device_attrs.h"
#undef DEV_ATTR
} DevAttributes;

extern DevAttributes   *devAttrs;
extern cl_int			numDevAttrs;
extern cl_uint			devBaselineMaxThreadsPerBlock;

extern void pgstrom_init_gpu_device(void);

#define GPUKERNEL_MAX_SM_MULTIPLICITY		4

extern CUresult gpuOccupancyMaxPotentialBlockSize(int *p_min_grid_sz,
												  int *p_max_block_sz,
												  CUfunction kern_function,
												  size_t dyn_shmem_per_block,
												  size_t dyn_shmem_per_thread);
extern CUresult gpuOptimalBlockSize(int *p_grid_sz,
									int *p_block_sz,
									CUfunction kern_function,
									CUdevice cuda_device,
									size_t dyn_shmem_per_block,
									size_t dyn_shmem_per_thread);
extern CUresult __gpuOptimalBlockSize(int *p_grid_sz,
									  int *p_block_sz,
									  CUfunction kern_function,
									  int cuda_dindex,
									  size_t dyn_shmem_per_block,
									  size_t dyn_shmem_per_thread);
/*
 * shmbuf.c
 */
extern MemoryContext	SharedMemoryContextCreate(const char *name);
extern void				pgstrom_init_shmbuf(void);
extern MemoryContext	TopSharedMemoryContext;

/*
 * gpu_mmgr.c
 */
extern CUresult __gpuMemAllocRaw(GpuContext *gcontext,
								 CUdeviceptr *p_devptr,
								 size_t bytesize,
								 const char *filename, int lineno);
extern CUresult __gpuMemAllocManagedRaw(GpuContext *gcontext,
										CUdeviceptr *p_devptr,
										size_t bytesize,
										int flags,
										const char *filename, int lineno);
extern CUresult __gpuMemAllocHostRaw(GpuContext *gcontext,
									 void **p_hostptr,
									 size_t bytesize,
									 const char *filename, int lineno);
extern CUresult __gpuMemAllocDev(GpuContext *gcontext,
								 CUdeviceptr *p_deviceptr,
								 size_t bytesize,
								 CUipcMemHandle *p_mhandle,
								 const char *filename, int lineno);
extern CUresult __gpuMemAlloc(GpuContext *gcontext,
							  CUdeviceptr *p_devptr,
							  size_t bytesize,
							  const char *filename, int lineno);
extern CUresult __gpuMemAllocManaged(GpuContext *gcontext,
									 CUdeviceptr *p_devptr,
									 size_t bytesize,
									 int flags,
									 const char *filename, int lineno);
extern CUresult __gpuMemAllocIOMap(GpuContext *gcontext,
								   CUdeviceptr *p_devptr,
								   size_t bytesize,
								   const char *filename, int lineno);
extern size_t	gpuMemAllocIOMapMaxLength(void);
extern CUresult __gpuMemAllocHost(GpuContext *gcontext,
								  void **p_hostptr,
								  size_t bytesize,
								  const char *filename, int lineno);
extern CUresult __gpuMemAllocPreserved(cl_int cuda_dindex,
									   CUipcMemHandle *ipc_mhandle,
									   ssize_t bytesize,
									   const char *filename, int lineno);
extern CUresult __gpuIpcOpenMemHandle(GpuContext *gcontext,
									  CUdeviceptr *p_deviceptr,
									  CUipcMemHandle m_handle,
									  unsigned int flags,
									  const char *filename, int lineno);
extern CUresult gpuMemFree(GpuContext *gcontext,
						   CUdeviceptr devptr);
extern CUresult gpuMemFreeHost(GpuContext *gcontext,
							   void *hostptr);
extern CUresult gpuMemFreePreserved(cl_int cuda_dindex,
									CUipcMemHandle m_handle);
extern CUresult gpuIpcCloseMemHandle(GpuContext *gcontext,
									 CUdeviceptr m_deviceptr);

#define gpuMemAllocRaw(a,b,c)				\
	__gpuMemAllocRaw((a),(b),(c),__FILE__,__LINE__)
#define gpuMemAllocManagedRaw(a,b,c,d)		\
	__gpuMemAllocManagedRaw((a),(b),(c),(d),__FILE__,__LINE__)
#define gpuMemAllocHostRaw(a,b,c)			\
	__gpuMemAllocHostRaw((a),(b),(c),__FILE__,__LINE__)
#define gpuMemAllocDev(a,b,c,d)				\
	__gpuMemAllocDev((a),(b),(c),(d),__FILE__,__LINE__)
#define gpuMemAlloc(a,b,c)					\
	__gpuMemAlloc((a),(b),(c),__FILE__,__LINE__)
#define gpuMemAllocManaged(a,b,c,d)			\
	__gpuMemAllocManaged((a),(b),(c),(d),__FILE__,__LINE__)
#define gpuMemAllocIOMap(a,b,c)				\
	__gpuMemAllocIOMap((a),(b),(c),__FILE__,__LINE__)
#define gpuMemAllocHost(a,b,c)				\
	__gpuMemAllocHost((a),(b),(c),__FILE__,__LINE__)
#define gpuMemAllocPreserved(a,b,c)						\
	__gpuMemAllocPreserved((a),(b),(c),__FILE__,__LINE__)
#define gpuIpcOpenMemHandle(a,b,c,d)		\
	__gpuIpcOpenMemHandle((a),(b),(c),(d),__FILE__,__LINE__)

extern void gpuMemReclaimSegment(GpuContext *gcontext);

extern void gpuMemCopyFromSSD(CUdeviceptr m_kds, pgstrom_data_store *pds);

extern void pgstrom_gpu_mmgr_init_gpucontext(GpuContext *gcontext);
extern void pgstrom_gpu_mmgr_cleanup_gpucontext(GpuContext *gcontext);
extern void pgstrom_init_gpu_mmgr(void);

/*
 * gpu_context.c
 */
extern int		pgstrom_max_async_tasks;		/* GUC */
extern __thread GpuContext	   *GpuWorkerCurrentContext;
extern __thread sigjmp_buf	   *GpuWorkerExceptionStack;
extern __thread int				GpuWorkerIndex;
#define CU_CONTEXT_PER_THREAD					\
	(GpuWorkerCurrentContext->cuda_context)
#define CU_DEVICE_PER_THREAD					\
	(GpuWorkerCurrentContext->cuda_device)
#define CU_DINDEX_PER_THREAD					\
	(GpuWorkerCurrentContext->cuda_dindex)

extern __thread CUevent			CU_EVENT_PER_THREAD;

extern void GpuContextWorkerReportError(int elevel,
										int errcode,
										const char *__filename, int lineno,
										const char *funcname,
										const char *fmt, ...)
	pg_attribute_printf(6,7);

static inline void
CHECK_FOR_GPUCONTEXT(GpuContext *gcontext)
{
	uint32		error_level = pg_atomic_read_u32(&gcontext->error_level);
	/*
	 * NOTE: The least bit of the error_level is a flag to indicate
	 * whether the error information is ready or not.
	 */
	if (error_level >= 2 * ERROR)
	{
		while ((error_level & 1) != 0)
		{
			pg_usleep(1000L);
			error_level = pg_atomic_read_u32(&gcontext->error_level);
		}
		ereport(error_level / 2,
				(errcode(gcontext->error_code),
				 errmsg("%s", gcontext->error_message),
				 (pgstrom_regression_test_mode ? 0 :
				  errdetail("GPU kernel location: %s:%d [%s]",
							gcontext->error_filename,
							gcontext->error_lineno,
							gcontext->error_funcname))));
	}
	CHECK_FOR_INTERRUPTS();
}
extern CUresult gpuInit(unsigned int flags);
extern GpuContext *AllocGpuContext(int cuda_dindex,
								   bool activate_context,
								   bool activate_workers);
extern void ActivateGpuContext(GpuContext *gcontext);
extern void ActivateGpuContextNoWorkers(GpuContext *gcontext);
extern GpuContext *GetGpuContext(GpuContext *gcontext);
extern void PutGpuContext(GpuContext *gcontext);
extern void SynchronizeGpuContext(GpuContext *gcontext);
extern void SynchronizeGpuContextOnDSMDetach(dsm_segment *seg, Datum arg);

#define GPUMEM_DEVICE_RAW_EXTRA		((void *)(~0L))
#define GPUMEM_HOST_RAW_EXTRA		((void *)(~1L))

extern bool trackCudaProgram(GpuContext *gcontext, ProgramId program_id,
							 const char *filename, int lineno);
extern void untrackCudaProgram(GpuContext *gcontext, ProgramId program_id);
extern bool trackGpuMem(GpuContext *gcontext, CUdeviceptr devptr, void *extra,
						const char *filename, int lineno);
extern void *lookupGpuMem(GpuContext *gcontext, CUdeviceptr devptr);
extern void *untrackGpuMem(GpuContext *gcontext, CUdeviceptr devptr);
extern bool trackGpuMemIPC(GpuContext *gcontext,
						   CUdeviceptr devptr, void *extra,
						   const char *filename, int lineno);
extern void *untrackGpuMemIPC(GpuContext *gcontext, CUdeviceptr devptr);
extern bool trackRawFileDesc(GpuContext *gcontext, GPUDirectFileDesc *fdesc,
							 const char *filename, int lineno);
extern void untrackRawFileDesc(GpuContext *gcontext, GPUDirectFileDesc *fdesc);
extern CUmodule __GpuContextLookupModule(GpuContext *gcontext,
										 ProgramId program_id,
										 const char *filename, int lineno);
#define GpuContextLookupModule(a,b)			\
	__GpuContextLookupModule((a),(b),__FILE__,__LINE__)

extern void pgstrom_init_gpu_context(void);

/*
 * Exception handling for work-queue of GpuContext
 */
#define STROM_TRY() \
	do { \
		ErrorContextCallback *saved_context_stack = error_context_stack; \
		sigjmp_buf *saved_exception_stack = (!GpuWorkerCurrentContext \
											 ? PG_exception_stack \
											 : GpuWorkerExceptionStack); \
		sigjmp_buf	local_sigjmp_buf; \
		if (sigsetjmp(local_sigjmp_buf, 0) == 0) \
		{ \
			if (!GpuWorkerCurrentContext)\
				PG_exception_stack = &local_sigjmp_buf; \
			else \
				GpuWorkerExceptionStack = &local_sigjmp_buf;

#define STROM_CATCH() \
		} \
		else \
		{ \
			if (!GpuWorkerCurrentContext) \
			{ \
				PG_exception_stack = saved_exception_stack;	\
				error_context_stack = saved_context_stack;	\
			} \
			else \
				GpuWorkerExceptionStack = saved_exception_stack

#define STROM_END_TRY()\
		} \
		if (!GpuWorkerCurrentContext) \
		{ \
			PG_exception_stack = saved_exception_stack; \
			error_context_stack = saved_context_stack; \
		} \
		else \
		{ \
			 GpuWorkerExceptionStack = saved_exception_stack; \
		} \
	} while(0)

#define STROM_RE_THROW() \
	do { \
		if (!GpuWorkerCurrentContext) \
			PG_RE_THROW(); \
		else \
			siglongjmp(*GpuWorkerExceptionStack, 1); \
	} while(0)

#define STROM_REPORT_ERROR(elevel,elabel,fmt,...)						\
	do {																\
		if (!GpuWorkerCurrentContext)									\
			elog((elevel), fmt, ##__VA_ARGS__);							\
		else if ((elevel) < ERROR)										\
		{																\
			if ((elevel) >= log_min_messages)							\
				fprintf(stderr, "%s: " fmt " (%s:%d)\n",				\
						(elabel), ##__VA_ARGS__,						\
						__FILE__, __LINE__);							\
		}																\
		else															\
		{																\
			GpuContextWorkerReportError((elevel),						\
										ERRCODE_INTERNAL_ERROR,			\
										__FILE__, __LINE__,				\
										PG_FUNCNAME_MACRO,				\
										fmt, ##__VA_ARGS__);			\
			pg_unreachable();											\
		}																\
	} while(0)

#define wlog(fmt,...)							\
	STROM_REPORT_ERROR(LOG,"Log",fmt,##__VA_ARGS__)
#define wnotice(fmt,...)						\
	STROM_REPORT_ERROR(NOTICE,"Notice",fmt,##__VA_ARGS__)
#define werror(fmt,...)							\
	STROM_REPORT_ERROR(ERROR,"Error",fmt,##__VA_ARGS__)
#define wfatal(fmt,...)							\
	STROM_REPORT_ERROR(FATAL,"Fatal",fmt,##__VA_ARGS__)
#define wpanic(fmt,...)							\
	STROM_REPORT_ERROR(PANIC,"Panic",fmt,##__VA_ARGS__)

static inline void
CHECK_WORKER_TERMINATION(void)
{
	if (pg_atomic_read_u32(&GpuWorkerCurrentContext->terminate_workers))
		werror("GpuContext worker termination");
}

#define GPUCONTEXT_PUSH(gcontext)										\
	do {																\
		CUresult	____rc;												\
																		\
		____rc = cuCtxPushCurrent((gcontext)->cuda_context);			\
		if (____rc != CUDA_SUCCESS)										\
			wfatal("failed on cuCtxPushCurrent: %s", errorText(____rc))

#define GPUCONTEXT_POP(gcontext)										\
		____rc = cuCtxPopCurrent(NULL);									\
		if (____rc != CUDA_SUCCESS)										\
			wfatal("failed on cuCtxPopCurrent: %s", errorText(____rc));	\
	} while(0)

/*
 * gpu_tasks.c
 */
extern kern_parambuf *construct_kern_parambuf(List *used_params,
											  ExprContext *econtext,
											  List *custom_scan_tlist);
extern void pgstromInitGpuTaskState(GpuTaskState *gts,
									GpuContext *gcontext,
									GpuTaskKind task_kind,
									List *outer_refs,
									List *used_params,
									cl_int optimal_gpu,
									cl_uint outer_nrows_per_block,
									cl_int eflags);
extern TupleTableSlot *pgstromExecGpuTaskState(GpuTaskState *gts);
extern void pgstromRescanGpuTaskState(GpuTaskState *gts);
extern void pgstromReleaseGpuTaskState(GpuTaskState *gts,
									   GpuTaskRuntimeStat *gt_rtstat);
extern void pgstromExplainGpuTaskState(GpuTaskState *gts, ExplainState *es);
extern Size pgstromEstimateDSMGpuTaskState(GpuTaskState *gts,
										   ParallelContext *pcxt);
extern void pgstromInitDSMGpuTaskState(GpuTaskState *gts,
									   ParallelContext *pcxt,
									   void *coordinate);
extern void pgstromInitWorkerGpuTaskState(GpuTaskState *gts,
										  void *coordinate);
extern void pgstromReInitializeDSMGpuTaskState(GpuTaskState *gts);

extern GpuTask *fetch_next_gputask(GpuTaskState *gts);

extern void pgstromInitGpuTask(GpuTaskState *gts, GpuTask *gtask);
extern void pgstrom_init_gputasks(void);

/*
 * nvme_strom.c
 */
extern Size	pgstrom_gpudirect_threshold(void);
extern int	GetOptimalGpuForFile(File fdesc);
extern int	GetOptimalGpuForRelation(PlannerInfo *root,
									 RelOptInfo *rel);
extern bool ScanPathWillUseNvmeStrom(PlannerInfo *root,
									 RelOptInfo *baserel);
extern bool RelationCanUseNvmeStrom(Relation relation);

extern void	gpuDirectFileDescOpen(GPUDirectFileDesc *gds_fdesc, File pg_fdesc);
extern void	gpuDirectFileDescOpenByPath(GPUDirectFileDesc *gds_fdesc,
										const char *pathname);
extern void	gpuDirectFileDescClose(const GPUDirectFileDesc *gds_fdesc);
extern CUresult gpuDirectMapGpuMemory(CUdeviceptr m_segment,
									  size_t m_segment_sz,
									  unsigned long *p_iomap_handle);
extern CUresult gpuDirectUnmapGpuMemory(CUdeviceptr m_segment,
										unsigned long iomap_handle);

extern void gpuDirectFileReadIOV(const GPUDirectFileDesc *gds_fdesc,
								 CUdeviceptr m_segment,
								 unsigned long iomap_handle,
								 off_t m_offset,
								 strom_io_vector *iovec);
extern void	pgstrom_init_gpu_direct(void);

/*
 * cuda_program.c
 */
extern ProgramId __pgstrom_create_cuda_program(GpuContext *gcontext,
											   cl_uint extra_flags,
											   cl_uint varlena_bufsz,
											   const char *kern_source,
											   const char *kern_define,
											   bool wait_for_build,
											   bool explain_only,
											   const char *filename,
											   int lineno);
#define pgstrom_create_cuda_program(a,b,c,d,e,f,g)				\
	__pgstrom_create_cuda_program((a),(b),(c),(d),(e),(f),(g),	\
								  __FILE__,__LINE__)
extern CUmodule pgstrom_load_cuda_program(ProgramId program_id);
extern void pgstrom_put_cuda_program(GpuContext *gcontext,
									 ProgramId program_id);
extern void pgstrom_build_session_info(StringInfo str,
									   GpuTaskState *gts,
									   cl_uint extra_flags);

extern char *pgstrom_cuda_source_string(ProgramId program_id);
extern const char *pgstrom_cuda_source_file(ProgramId program_id);
extern const char *pgstrom_cuda_binary_file(ProgramId program_id);
extern void pgstrom_init_cuda_program(void);

/*
 * codegen.c
 */
struct codegen_context {
	StringInfoData	str;
	StringInfoData	decl_temp;	/* declarations of temporary variables */
	int				decl_count;	/* # of temporary variabes in decl */
	PlannerInfo *root;		//not necessary?
	RelOptInfo	*baserel;	/* scope of Var-node, if any */
	List	   *used_params;/* list of Const/Param in use */
	List	   *used_vars;	/* list of Var in use */
	Bitmapset  *param_refs;	/* referenced parameters */
	const char *var_label;	/* prefix of var reference, if exist */
	const char *kds_label;	/* label to reference kds, if exist */
	List	   *pseudo_tlist;	/* pseudo tlist expression, if any */
	int			extra_flags;	/* external libraries to be included */
	int			varlena_bufsz;	/* required size of temporary varlena buffer */
	int			devcost;	/* relative device cost */
};
typedef struct codegen_context	codegen_context;

extern void pgstrom_codegen_typeoid_declarations(StringInfo buf);
extern devtype_info *pgstrom_devtype_lookup(Oid type_oid);
extern devtype_info *pgstrom_devtype_lookup_and_track(Oid type_oid,
											  codegen_context *context);
extern devfunc_info *pgstrom_devfunc_lookup(Oid func_oid,
											Oid func_rettype,
											List *func_args,
											Oid func_collid);
extern devfunc_info *pgstrom_devfunc_lookup_type_equal(devtype_info *dtype,
													   Oid type_collid);
extern devfunc_info *pgstrom_devfunc_lookup_type_compare(devtype_info *dtype,
														 Oid type_collid);
extern void pgstrom_devfunc_track(codegen_context *context,
								  devfunc_info *dfunc);
extern devcast_info *pgstrom_devcast_lookup(Oid src_type_oid,
											Oid dst_type_oid,
											char castmethod);
extern bool pgstrom_devtype_can_relabel(Oid src_type_oid,
										Oid dst_type_oid);
extern char *pgstrom_codegen_expression(Node *expr, codegen_context *context);
extern void pgstrom_codegen_param_declarations(StringInfo buf,
											   codegen_context *context);
extern void pgstrom_union_type_declarations(StringInfo buf,
											const char *name,
											List *type_oid_list);
extern bool __pgstrom_device_expression(PlannerInfo *root,
										RelOptInfo *baserel,
										Expr *expr,
										int *p_devcost,
										int *p_extra_sz,
										const char *filename, int lineno);
#define pgstrom_device_expression(a,b,c)				\
	__pgstrom_device_expression((a),(b),(c),NULL,NULL,	\
								__FILE__,__LINE__)
#define pgstrom_device_expression_devcost(a,b,c,d)		\
	__pgstrom_device_expression((a),(b),(c),(d),NULL,	\
								__FILE__,__LINE__)
#define pgstrom_device_expression_extrasz(a,b,c,d)		\
	__pgstrom_device_expression((a),(b),(c),NULL,(d),	\
								__FILE__,__LINE__)

extern void pgstrom_init_codegen_context(codegen_context *context,
										 PlannerInfo *root,
										 RelOptInfo *baserel);
extern void pgstrom_init_codegen(void);

/*
 * datastore.c
 */
extern cl_uint estimate_num_chunks(Path *pathnode);
extern bool KDS_fetch_tuple_row(TupleTableSlot *slot,
								kern_data_store *kds,
								HeapTuple tuple_buf,
								size_t row_index);
extern bool KDS_fetch_tuple_slot(TupleTableSlot *slot,
								 kern_data_store *kds,
								 size_t row_index);
extern Datum KDS_fetch_datum_column(kern_data_store *kds,
									kern_colmeta *cmeta,
									size_t row_index,
									bool *p_isnull);
extern void __KDS_store_datum_column(kern_data_store *kds,
									 kern_colmeta *cmeta,
									 size_t row_index,
									 Datum datum, bool isnull);
extern void  KDS_store_datum_column(kern_data_store *kds,
									kern_colmeta *cmeta,
									size_t row_index,
									Datum datum, bool isnull);
extern bool KDS_fetch_tuple_column(TupleTableSlot *slot,
								   kern_data_store *kds,
								   size_t row_index);
extern bool PDS_fetch_tuple(TupleTableSlot *slot,
							pgstrom_data_store *pds,
							GpuTaskState *gts);
extern kern_data_store *__KDS_clone(GpuContext *gcontext,
									kern_data_store *kds,
									const char *filename, int lineno);
extern pgstrom_data_store *__PDS_clone(pgstrom_data_store *pds,
									   const char *filename, int lineno);
extern pgstrom_data_store *PDS_retain(pgstrom_data_store *pds);
extern void PDS_release(pgstrom_data_store *pds);

extern size_t	KDS_calculateHeadSize(TupleDesc tupdesc);
extern bool		KDS_schemaIsCompatible(TupleDesc tupdesc,
									   kern_data_store *kds);
extern void init_kernel_data_store(kern_data_store *kds,
								   TupleDesc tupdesc,
								   Size length,
								   int format,
								   uint nrooms);

extern pgstrom_data_store *__PDS_create_row(GpuContext *gcontext,
											TupleDesc tupdesc,
											Size length,
											const char *fname, int lineno);
extern pgstrom_data_store *__PDS_create_hash(GpuContext *gcontext,
											 TupleDesc tupdesc,
											 Size length,
											 const char *fname, int lineno);
extern pgstrom_data_store *__PDS_create_slot(GpuContext *gcontext,
											 TupleDesc tupdesc,
											 size_t bytesize,
											 const char *filename, int lineno);
extern pgstrom_data_store *__PDS_create_block(GpuContext *gcontext,
											  TupleDesc tupdesc,
											  NVMEScanState *nvme_sstate,
											  const char *fname, int lineno);
#define PDS_create_row(a,b,c)					\
	__PDS_create_row((a),(b),(c),__FILE__,__LINE__)
#define PDS_create_hash(a,b,c)					\
	__PDS_create_hash((a),(b),(c),__FILE__,__LINE__)
#define PDS_create_slot(a,b,c)					\
	__PDS_create_slot((a),(b),(c),__FILE__,__LINE__)
#define PDS_create_block(a,b,c)					\
	__PDS_create_block((a),(b),(c),__FILE__,__LINE__)
#define KDS_clone(a,b)							\
	__KDS_clone((a),(b),__FILE__,__LINE__)
#define PDS_clone(a)							\
	__PDS_clone((a),__FILE__,__LINE__)

extern void KDS_dump_schema(kern_data_store *kds);

//XXX - to be gpu_task.c?
extern void PDS_init_heapscan_state(GpuTaskState *gts);
extern void PDS_end_heapscan_state(GpuTaskState *gts);
extern void PDS_fillup_blocks(pgstrom_data_store *pds);
extern void __PDS_fillup_arrow(pgstrom_data_store *pds_dst,
							   GpuContext *gcontext,
							   kern_data_store *kds_head,
							   int fdesc, strom_io_vector *iovec);
extern pgstrom_data_store *PDS_fillup_arrow(pgstrom_data_store *pds_src);
extern pgstrom_data_store *PDS_writeback_arrow(pgstrom_data_store *pds_src,
											   CUdeviceptr m_kds_src);
extern bool KDS_insert_tuple(kern_data_store *kds,
							 TupleTableSlot *slot);
#define PDS_insert_tuple(pds,slot)	KDS_insert_tuple(&(pds)->kds,slot)

extern bool KDS_insert_hashitem(kern_data_store *kds,
								TupleTableSlot *slot,
								cl_uint hash_value);
extern void pgstrom_init_datastore(void);

/*
 * relscan.c
 */
extern IndexOptInfo *pgstrom_tryfind_brinindex(PlannerInfo *root,
											   RelOptInfo *baserel,
											   List **p_indexConds,
											   List **p_indexQuals,
											   cl_long *p_indexNBlocks);
#define PGSTROM_RELSCAN_SSD2GPU			0x0001
#define PGSTROM_RELSCAN_BRIN_INDEX		0x0002
#define PGSTROM_RELSCAN_ARROW_FDW		0x0004
#define PGSTROM_RELSCAN_GSTORE_FDW		0x0008
extern int pgstrom_common_relscan_cost(PlannerInfo *root,
									   RelOptInfo *scan_rel,
									   List *scan_quals,
									   int parallel_workers,
									   IndexOptInfo *indexOpt,
									   List *indexQuals,
									   cl_long indexNBlocks,
									   double *p_parallel_divisor,
									   double *p_scan_ntuples,
									   double *p_scan_nchunks,
									   cl_uint *p_nrows_per_block,
									   Cost *p_startup_cost,
									   Cost *p_run_cost);
extern Bitmapset *pgstrom_pullup_outer_refs(PlannerInfo *root,
											RelOptInfo *base_rel,
											Bitmapset *referenced);
extern void pgstromExecInitBrinIndexMap(GpuTaskState *gts,
										Oid index_oid,
										List *index_conds,
										List *index_quals);
extern Size pgstromSizeOfBrinIndexMap(GpuTaskState *gts);
extern void pgstromExecGetBrinIndexMap(GpuTaskState *gts);
extern void pgstromExecEndBrinIndexMap(GpuTaskState *gts);
extern void pgstromExecRewindBrinIndexMap(GpuTaskState *gts);
extern void pgstromExplainBrinIndexMap(GpuTaskState *gts,
									   ExplainState *es,
									   List *dcontext);

extern pgstrom_data_store *pgstromExecScanChunk(GpuTaskState *gts);
extern void pgstromRewindScanChunk(GpuTaskState *gts);

extern void pgstromExplainOuterScan(GpuTaskState *gts,
									List *deparse_context,
									List *ancestors,
									ExplainState *es,
									List *outer_quals,
									Cost outer_startup_cost,
									Cost outer_total_cost,
									double outer_plan_rows,
									int outer_plan_width);

extern void pgstrom_init_relscan(void);

/*
 * gpuscan.c
 */
extern bool enable_gpuscan;		/* GUC */
extern Cost cost_for_dma_receive(RelOptInfo *rel, double ntuples);
extern void codegen_gpuscan_quals(StringInfo kern,
								  codegen_context *context,
								  const char *component,
								  Index scanrelid,
								  List *dev_quals_list);
extern bool pgstrom_pullup_outer_scan(PlannerInfo *root,
									  const Path *outer_path,
									  Index *p_outer_relid,
									  List **p_outer_quals,
									  cl_int *p_cuda_dindex,
									  IndexOptInfo **p_index_opt,
									  List **p_index_conds,
									  List **p_index_quals,
									  cl_long *p_index_nblocks);
extern bool pgstrom_path_is_gpuscan(const Path *path);
extern bool pgstrom_plan_is_gpuscan(const Plan *plan);
extern bool pgstrom_planstate_is_gpuscan(const PlanState *ps);
extern Path *pgstrom_copy_gpuscan_path(const Path *pathnode);
extern void assign_gpuscan_session_info(StringInfo buf, GpuTaskState *gts);
extern void pgstrom_init_gpuscan(void);

/*
 * gpujoin.c
 */
struct GpuJoinSharedState;
struct kern_gpujoin;

extern bool pgstrom_path_is_gpujoin(const Path *pathnode);
extern bool pgstrom_plan_is_gpujoin(const Plan *plannode);
extern bool pgstrom_planstate_is_gpujoin(const PlanState *ps);
extern Path *pgstrom_copy_gpujoin_path(const Path *pathnode);
extern cl_int gpujoin_get_optimal_gpu(const Path *pathnode);

#if PG_VERSION_NUM >= 110000
extern List *extract_partitionwise_pathlist(PlannerInfo *root,
											Path *outer_path,
											bool try_outer_parallel,
											bool try_inner_parallel,
											AppendPath **p_append_path,
											int *p_parallel_nworkers,
											Cost *p_discount_cost);
#endif
extern int	gpujoin_process_task(GpuTask *gtask, CUmodule cuda_module);
extern void	gpujoin_release_task(GpuTask *gtask);
extern void assign_gpujoin_session_info(StringInfo buf,
										GpuTaskState *gts);
extern void	pgstrom_init_gpujoin(void);

extern Size GpuJoinSetupTask(struct kern_gpujoin *kgjoin,
							 GpuTaskState *gts,
							 pgstrom_data_store *pds_src);
extern ProgramId GpuJoinCreateCombinedProgram(PlanState *node,
											  GpuTaskState *gpa_gts,
											  cl_uint gpa_extra_flags,
											  cl_uint gpa_varlena_bufsz,
											  const char *gpa_kern_source,
											  bool explain_only);
extern bool GpuJoinInnerPreload(GpuTaskState *gts, CUdeviceptr *p_m_kmrels);
extern void GpuJoinInnerUnload(GpuTaskState *gts, bool is_rescan);
extern pgstrom_data_store *GpuJoinExecOuterScanChunk(GpuTaskState *gts);
extern int  gpujoinNextRightOuterJoinIfAny(GpuTaskState *gts);
extern TupleTableSlot *gpujoinNextTupleFallback(GpuTaskState *gts,
												struct kern_gpujoin *kgjoin,
												pgstrom_data_store *pds_src,
												cl_int outer_depth);
extern void gpujoinUpdateRunTimeStat(GpuTaskState *gts,
									 struct kern_gpujoin *kgjoin);

/*
 * gpupreagg.c
 */
extern bool pgstrom_path_is_gpupreagg(const Path *pathnode);
extern bool pgstrom_plan_is_gpupreagg(const Plan *plan);
extern bool pgstrom_planstate_is_gpupreagg(const PlanState *ps);
extern Path *pgstrom_copy_gpupreagg_path(const Path *pathnode);
extern void gpupreagg_post_planner(PlannedStmt *pstmt, CustomScan *cscan);
extern void assign_gpupreagg_session_info(StringInfo buf,
										  GpuTaskState *gts);
extern void pgstrom_init_gpupreagg(void);

/*
 * arrow_fdw.c and arrow_read.c
 */
extern bool baseRelIsArrowFdw(RelOptInfo *baserel);
extern bool RelationIsArrowFdw(Relation frel);
extern cl_int GetOptimalGpuForArrowFdw(PlannerInfo *root,
									   RelOptInfo *baserel);
extern bool KDS_fetch_tuple_arrow(TupleTableSlot *slot,
								  kern_data_store *kds,
								  size_t row_index);

extern ArrowFdwState *ExecInitArrowFdw(GpuContext *gcontext,
									   Relation relation,
									   Bitmapset *outer_refs);
extern pgstrom_data_store *ExecScanChunkArrowFdw(GpuTaskState *gts);
extern void ExecReScanArrowFdw(ArrowFdwState *af_state);
extern void ExecEndArrowFdw(ArrowFdwState *af_state);
extern Size ExecEstimateDSMArrowFdw(ArrowFdwState *af_state);
extern void ExecInitDSMArrowFdw(ArrowFdwState *af_state,
								pg_atomic_uint32 *rbatch_index);
extern void ExecReInitDSMArrowFdw(ArrowFdwState *af_state);
extern void ExecInitWorkerArrowFdw(ArrowFdwState *af_state,
								   pg_atomic_uint32 *rbatch_index);
extern void ExecShutdownArrowFdw(ArrowFdwState *af_state);
extern void ExplainArrowFdw(ArrowFdwState *af_state,
							Relation frel, ExplainState *es);
extern void pgstrom_init_arrow_fdw(void);

/*
 * gpu_store.c
 */
extern bool relationHasGpuStore(Relation rel);
extern void pgstrom_init_gpu_store(void);

/*
 * gstore_fdw.c
 */
extern bool	baseRelIsGstoreFdw(RelOptInfo *baserel);
extern bool RelationIsGstoreFdw(Relation frel);
extern int	GetOptimalGpuForGstoreFdw(PlannerInfo *root,
									  RelOptInfo *baserel);
extern GpuStoreFdwState *ExecInitGstoreFdw(ScanState *ss, int eflags,
										   Bitmapset *outer_refs);
extern pgstrom_data_store *ExecScanChunkGstoreFdw(GpuTaskState *gts);
extern void ExecReScanGstoreFdw(GpuStoreFdwState *gstore_state);
extern void ExecEndGstoreFdw(GpuStoreFdwState *gstore_state);
extern Size ExecEstimateDSMGstoreFdw(GpuStoreFdwState *gstore_state);
extern void ExecInitDSMGstoreFdw(GpuStoreFdwState *gstore_state,
								 pg_atomic_uint64 *gstore_read_pos);
extern void ExecReInitDSMGstoreFdw(GpuStoreFdwState *gstore_state);
extern void ExecInitWorkerGstoreFdw(GpuStoreFdwState *gstore_state,
									pg_atomic_uint64 *gstore_read_pos);
extern void ExecShutdownGstoreFdw(GpuStoreFdwState *gstore_state);
extern void ExplainGstoreFdw(GpuStoreFdwState *af_state,
							 Relation frel, ExplainState *es);
extern CUresult gstoreFdwMapDeviceMemory(GpuContext *gcontext,
										 pgstrom_data_store *pds);
extern void gstoreFdwUnmapDeviceMemory(GpuContext *gcontext,
									   pgstrom_data_store *pds);

#define GSTORE_FDW_SYSATTR_OID		6116
extern void gstoreFdwBgWorkerBegin(int cuda_dindex);
extern bool gstoreFdwBgWorkerDispatch(int cuda_dindex);
extern bool gstoreFdwBgWorkerIdleTask(int cuda_dindex);
extern void gstoreFdwBgWorkerEnd(int cuda_dindex);
extern void pgstrom_init_gstore_fdw(void);

/*
 * misc.c
 */
extern Expr *make_flat_ands_explicit(List *andclauses);
extern AppendRelInfo **find_appinfos_by_relids_nofail(PlannerInfo *root,
													  Relids relids,
													  int *nappinfos);
extern double get_parallel_divisor(Path *path);
#if PG_VERSION_NUM < 110000
/* PG11 changed pg_proc definition */
extern char get_func_prokind(Oid funcid);
#define PROKIND_FUNCTION	'f'
#define PROKIND_AGGREGATE	'a'
#define PROKIND_WINDOW		'w'
#define PROKIND_PROCEDURE	'p'
#endif
extern int	get_relnatts(Oid relid);
extern Oid	get_function_oid(const char *func_name,
							 oidvector *func_args,
							 Oid namespace_oid,
							 bool missing_ok);
extern Oid	get_type_oid(const char *type_name,
						 Oid namespace_oid,
						 bool missing_ok);
extern char *get_type_name(Oid type_oid, bool missing_ok);
extern char *get_proc_library(HeapTuple protup);
extern char *bms_to_cstring(Bitmapset *x);
extern bool pathtree_has_gpupath(Path *node);
extern bool pathtree_has_parallel_aware(Path *node);
extern Path *pgstrom_copy_pathnode(const Path *pathnode);
extern const char *errorText(int errcode);

extern ssize_t	__readFile(int fdesc, void *buffer, size_t nbytes);
extern ssize_t	__writeFile(int fdesc, const void *buffer, size_t nbytes);
extern ssize_t	__readFileSignal(int fdesc, void *buffer, size_t nbytes,
								 bool interruptible);
extern ssize_t	__writeFileSignal(int fdesc, const void *buffer, size_t nbytes,
								  bool interruptible);
extern void	   *__mmapFile(void *addr, size_t length,
						   int prot, int flags, int fdesc, off_t offset);
extern int		__munmapFile(void *mmap_addr);
extern void	   *__mremapFile(void *mmap_addr, size_t new_size);

/*
 * nvrtc.c
 */
extern int		pgstrom_nvrtc_version(void);
extern void		pgstrom_init_nvrtc(void);

/*
 * cufile.c
 */
extern bool		cuFileDriverLoaded(void);
extern void		pgstrom_init_cufile(void);

/*
 * extra.c
 */
extern void		pgstrom_init_extra(void);

/*
 * float2.c
 */
#ifndef FLOAT2OID
#define FLOAT2OID		421
#endif

/*
 * main.c
 */
extern const Path *gpu_path_find_cheapest(PlannerInfo *root,
										  RelOptInfo *rel,
										  bool outer_parallel,
										  bool inner_parallel);
extern bool	gpu_path_remember(PlannerInfo *root,
							  RelOptInfo *rel,
							  bool outer_parallel,
							  bool inner_parallel,
							  const Path *gpu_path);

extern Path *pgstrom_create_dummy_path(PlannerInfo *root,
									   Path *subpath,
									   PathTarget *target);
extern void _PG_init(void);
extern const char *pgstrom_strerror(cl_int errcode);

extern void pgstrom_explain_expression(List *expr_list, const char *qlabel,
									   PlanState *planstate,
									   List *deparse_context,
									   List *ancestors, ExplainState *es,
									   bool force_prefix,
									   bool convert_to_and);
extern void show_scan_qual(List *qual, const char *qlabel,
						   PlanState *planstate, List *ancestors,
						   ExplainState *es);
extern void show_instrumentation_count(const char *qlabel, int which,
									   PlanState *planstate, ExplainState *es);

/* ----------------------------------------------------------------
 *
 * Miscellaneous static inline functions
 *
 * ---------------------------------------------------------------- */

/* looong label is not friendly for indent */
#define NumOfSystemAttrs	(-(1+FirstLowInvalidHeapAttributeNumber))

/* Max/Min macros that takes 3 or more arguments */
#define Max3(a,b,c)		((a) > (b) ? Max((a),(c)) : Max((b),(c)))
#define Max4(a,b,c,d)	Max(Max((a),(b)), Max((c),(d)))

#define Min3(a,b,c)		((a) > (b) ? Min((a),(c)) : Min((b),(c)))
#define Min4(a,b,c,d)	Min(Min((a),(b)), Min((c),(d)))

#ifndef SAMESIGN
#define SAMESIGN(a,b)	(((a) < 0) == ((b) < 0))
#endif
/*
 * int/float reinterpret functions
 */
static inline cl_double
long_as_double(cl_long ival)
{
	union {
		cl_long		ival;
		cl_double	fval;
	} datum;
	datum.ival = ival;
	return datum.fval;
}

static inline cl_long
double_as_long(cl_double fval)
{
	union {
		cl_long		ival;
		cl_double	fval;
	} datum;
	datum.fval = fval;
	return datum.ival;
}

static inline cl_float
int_as_float(cl_int ival)
{
	union {
		cl_int		ival;
		cl_float	fval;
	} datum;
	datum.ival = ival;
	return datum.fval;
}

static inline cl_int
float_as_int(cl_float fval)
{
	union {
		cl_int		ival;
		cl_float	fval;
	} datum;
	datum.fval = fval;
	return datum.ival;
}

/*
 * pmakeFloat - for convenient; makeFloat + psprintf
 */
static inline Value *
pmakeFloat(cl_double float_value)
{
	return makeFloat(psprintf("%.*e", DBL_DIG+3, float_value));
}

/*
 * get_prev_log2
 *
 * It returns N of the largest 2^N value that is smaller than or equal to
 * the supplied value.
 */
static inline int
get_prev_log2(Size size)
{
	int		shift = 0;

	if (size == 0 || size == 1)
		return 0;
	size >>= 1;
#if __GNUC__
	shift = sizeof(Size) * BITS_PER_BYTE - __builtin_clzl(size);
#else
#if SIZEOF_VOID_P == 8
	if ((size & 0xffffffff00000000UL) != 0)
	{
		size >>= 32;
		shift += 32;
	}
#endif
	if ((size & 0xffff0000UL) != 0)
	{
		size >>= 16;
		shift += 16;
	}
	if ((size & 0x0000ff00UL) != 0)
	{
		size >>= 8;
		shift += 8;
	}
	if ((size & 0x000000f0UL) != 0)
	{
		size >>= 4;
		shift += 4;
	}
	if ((size & 0x0000000cUL) != 0)
	{
		size >>= 2;
		shift += 2;
	}
	if ((size & 0x00000002UL) != 0)
	{
		size >>= 1;
		shift += 1;
	}
	if ((size & 0x00000001UL) != 0)
		shift += 1;
#endif	/* !__GNUC__ */
	return shift;
}

/*
 * get_next_log2
 *
 * It returns N of the least 2^N value that is larger than or equal to
 * the supplied value.
 */
static inline int
get_next_log2(Size size)
{
	int		shift = 0;

	if (size == 0 || size == 1)
		return 0;
	size--;
#ifdef __GNUC__
	shift = sizeof(Size) * BITS_PER_BYTE - __builtin_clzl(size);
#else
#if SIZEOF_VOID_P == 8
	if ((size & 0xffffffff00000000UL) != 0)
	{
		size >>= 32;
		shift += 32;
	}
#endif
	if ((size & 0xffff0000UL) != 0)
	{
		size >>= 16;
		shift += 16;
	}
	if ((size & 0x0000ff00UL) != 0)
	{
		size >>= 8;
		shift += 8;
	}
	if ((size & 0x000000f0UL) != 0)
	{
		size >>= 4;
		shift += 4;
	}
	if ((size & 0x0000000cUL) != 0)
	{
		size >>= 2;
		shift += 2;
	}
	if ((size & 0x00000002UL) != 0)
	{
		size >>= 1;
		shift += 1;
	}
	if ((size & 0x00000001UL) != 0)
		shift += 1;
#endif	/* !__GNUC__ */
	return shift;
}

/*
 * __trim - remove whitespace at the head/tail of cstring
 */
static inline char *
__trim(char *token)
{
	char   *tail = token + strlen(token) - 1;

	while (*token == ' ' || *token == '\t')
		token++;
	while (tail >= token && (*tail == ' ' || *tail == '\t'))
		*tail-- = '\0';
	return token;
}

/*
 * It translate an alignment character into width
 */
static inline int
typealign_get_width(char type_align)
{
	if (type_align == 'c')
		return sizeof(cl_char);
	else if (type_align == 's')
		return sizeof(cl_short);
	else if (type_align == 'i')
		return sizeof(cl_int);
	else if (type_align == 'd')
		return sizeof(cl_long);
	elog(ERROR, "unexpected type alignment: %c", type_align);
	return -1;	/* be compiler quiet */
}

#ifndef forfour
/* XXX - PG12 added forfour() macro */
#define forfour(lc1, list1, lc2, list2, lc3, list3, lc4, list4)		\
	for ((lc1) = list_head(list1), (lc2) = list_head(list2),		\
		 (lc3) = list_head(list3), (lc4) = list_head(list4);		\
		 (lc1) != NULL && (lc2) != NULL && (lc3) != NULL &&			\
		 (lc4) != NULL;												\
		 (lc1) = lnext(lc1), (lc2) = lnext(lc2), (lc3) = lnext(lc3),\
		 (lc4) = lnext(lc4))
#endif

/* XXX - PG10 added lfirst_node() and related */
#ifndef lfirst_node
#define lfirst_node(T,x)		((T *)lfirst(x))
#endif
#ifndef linitial_node
#define linitial_node(T,x)		((T *)linitial(x))
#endif
#ifndef lsecond_node
#define lsecond_node(T,x)		((T *)lsecond(x))
#endif
#ifndef lthird_node
#define lthird_node(T,x)		((T *)lthird(x))
#endif

/* lappend on the specified memory-context */
static inline List *
lappend_cxt(MemoryContext memcxt, List *list, void *datum)
{
	MemoryContext oldcxt = MemoryContextSwitchTo(memcxt);
	List   *r;

	r = lappend(list, datum);
	MemoryContextSwitchTo(oldcxt);

	return r;
}


static inline char *
format_numeric(cl_long value)
{
	if (value > 8000000000000L   || value < -8000000000000L)
		return psprintf("%.2fT", (double)value / 1000000000000.0);
	else if (value > 8000000000L || value < -8000000000L)
		return psprintf("%.2fG", (double)value / 1000000000.0);
	else if (value > 8000000L    || value < -8000000L)
		return psprintf("%.2fM", (double)value / 1000000.0);
	else if (value > 8000L       || value < -8000L)
		return psprintf("%.2fK", (double)value / 1000.0);
	else
		return psprintf("%ld", value);
}

static inline char *
format_bytesz(Size nbytes)
{
	if (nbytes > (Size)(1UL << 43))
		return psprintf("%.2fTB", (double)nbytes / (double)(1UL << 40));
	else if (nbytes > (double)(1UL << 33))
		return psprintf("%.2fGB", (double)nbytes / (double)(1UL << 30));
	else if (nbytes > (double)(1UL << 23))
		return psprintf("%.2fMB", (double)nbytes / (double)(1UL << 20));
	else if (nbytes > (double)(1UL << 13))
		return psprintf("%.2fKB", (double)nbytes / (double)(1UL << 10));
	return psprintf("%uB", (unsigned int)nbytes);
}

static inline char *
format_millisec(double milliseconds)
{
	if (milliseconds > 300000.0)    /* more then 5min */
		return psprintf("%.2fmin", milliseconds / 60000.0);
	else if (milliseconds > 8000.0) /* more than 8sec */
		return psprintf("%.2fsec", milliseconds / 1000.0);
	return psprintf("%.2fms", milliseconds);
}

static inline const char *
__basename(const char *filename)
{
	const char *pos = strrchr(filename, '/');

	return pos ? pos + 1 : filename;
}

/*
 * merge two dlist_head
 */
static inline void
dlist_append_tail(dlist_head *base, dlist_head *items)
{
	if (dlist_is_empty(items))
		return;
	items->head.next->prev = base->head.prev;
	items->head.prev->next = &base->head;
	base->head.prev->next = items->head.next;
	base->head.prev = items->head.prev;
}

/*
 * Some usuful memory allocation wrapper
 */
#define palloc_huge(sz)		MemoryContextAllocHuge(CurrentMemoryContext,(sz))
static inline void *
pmemdup(const void *src, Size sz)
{
	void   *dst = palloc(sz);

	memcpy(dst, src, sz);

	return dst;
}

/*
 * simple wrapper for pthread_mutex_lock
 */
static inline void
pthreadMutexInit(pthread_mutex_t *mutex, int pshared)
{
	pthread_mutexattr_t mattr;

	if ((errno = pthread_mutexattr_init(&mattr)) != 0)
		wfatal("failed on pthread_mutexattr_init: %m");
	if ((errno = pthread_mutexattr_setpshared(&mattr, pshared)) != 0)
		wfatal("failed on pthread_mutexattr_setpshared: %m");
	if ((errno = pthread_mutex_init(mutex, &mattr)) != 0)
		wfatal("failed on pthread_mutex_init: %m");
	if ((errno = pthread_mutexattr_destroy(&mattr)) != 0)
		wfatal("failed on pthread_mutexattr_destroy: %m");
}

static inline void
pthreadMutexLock(pthread_mutex_t *mutex)
{
	if ((errno = pthread_mutex_lock(mutex)) != 0)
		wfatal("failed on pthread_mutex_lock: %m");
}

static inline bool
pthreadMutexLockTimeout(pthread_mutex_t *mutex, cl_ulong timeout_ms)
{
	struct timespec	tm;

	if (clock_gettime(CLOCK_REALTIME, &tm) != 0)
		wfatal("failed on clock_gettime: %m");
	tm.tv_sec  += (timeout_ms / 1000);
	tm.tv_nsec += (timeout_ms % 1000) * 1000000;
	if (tm.tv_nsec >= 1000000000L)
	{
		tm.tv_sec += tm.tv_nsec / 1000000000L;
		tm.tv_nsec = tm.tv_nsec % 1000000000L;
	}

	errno = pthread_mutex_timedlock(mutex, &tm);
	if (errno == ETIMEDOUT)
		return false;
	else if (errno != 0)
		wfatal("failed on pthread_mutex_timedlock: %m");
	return true;
}

static inline void
pthreadMutexUnlock(pthread_mutex_t *mutex)
{
	if ((errno = pthread_mutex_unlock(mutex)) != 0)
		wfatal("failed on pthread_mutex_unlock: %m");
}

static inline void
pthreadRWLockInit(pthread_rwlock_t *rwlock)
{
	pthread_rwlockattr_t rwattr;

	if ((errno = pthread_rwlockattr_init(&rwattr)) != 0)
		wfatal("failed on pthread_rwlockattr_init: %m");
	if ((errno = pthread_rwlockattr_setpshared(&rwattr, 1)) != 0)
		wfatal("failed on pthread_rwlockattr_setpshared: %m");
    if ((errno = pthread_rwlock_init(rwlock, &rwattr)) != 0)
		wfatal("failed on pthread_rwlock_init: %m");
}

static inline void
pthreadRWLockReadLock(pthread_rwlock_t *rwlock)
{
	if ((errno = pthread_rwlock_rdlock(rwlock)) != 0)
		wfatal("failed on pthread_rwlock_rdlock: %m");
}

static inline void
pthreadRWLockWriteLock(pthread_rwlock_t *rwlock)
{
	if ((errno = pthread_rwlock_wrlock(rwlock)) != 0)
		wfatal("failed on pthread_rwlock_wrlock: %m");
}

static inline bool
pthreadRWLockWriteTryLock(pthread_rwlock_t *rwlock)
{
	if ((errno = pthread_rwlock_trywrlock(rwlock)) == 0)
		return true;
	if (errno != EBUSY)
		wfatal("failed on pthread_rwlock_trywrlock: %m");
	return false;
}

static inline void
pthreadRWLockUnlock(pthread_rwlock_t *rwlock)
{
	if ((errno = pthread_rwlock_unlock(rwlock)) != 0)
		wfatal("failed on pthread_rwlock_unlock: %m");
}

static inline void
pthreadCondInit(pthread_cond_t *cond, int pshared)
{
	pthread_condattr_t condattr;

	if ((errno = pthread_condattr_init(&condattr)) != 0)
		wfatal("failed on pthread_condattr_init: %m");
	if ((errno = pthread_condattr_setpshared(&condattr, pshared)) != 0)
		wfatal("failed on pthread_condattr_setpshared: %m");
	if ((errno = pthread_cond_init(cond, &condattr)) != 0)
		wfatal("failed on pthread_cond_init: %m");
	if ((errno = pthread_condattr_destroy(&condattr)) != 0)
		wfatal("failed on pthread_condattr_destroy: %m");
}

static inline void
pthreadCondWait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if ((errno = pthread_cond_wait(cond, mutex)) != 0)
		wfatal("failed on pthread_cond_wait: %m");
}

static inline bool
pthreadCondWaitTimeout(pthread_cond_t *cond, pthread_mutex_t *mutex,
					   long timeout_ms)
{
	struct timespec tm;

	clock_gettime(CLOCK_REALTIME, &tm);
	tm.tv_sec += timeout_ms / 1000;
	tm.tv_nsec += (timeout_ms % 1000) * 1000000;
	if (tm.tv_nsec > 1000000000)
	{
		tm.tv_sec += tm.tv_nsec / 1000000000;
		tm.tv_nsec = tm.tv_nsec % 1000000000;
	}

	errno = pthread_cond_timedwait(cond, mutex, &tm);
	if (errno == 0)
		return true;
	else if (errno == ETIMEDOUT)
		return false;
	wfatal("failed on pthread_cond_timedwait: %m");
}

static inline void
pthreadCondBroadcast(pthread_cond_t *cond)
{
	if ((errno = pthread_cond_broadcast(cond)) != 0)
		wfatal("failed on pthread_cond_broadcast: %m");
}

static inline void
pthreadCondSignal(pthread_cond_t *cond)
{
	if ((errno = pthread_cond_signal(cond)) != 0)
		wfatal("failed on pthread_cond_signal: %m");
}

/*
 * utility to calculate time diff
 */
#define TV_DIFF(tv2,tv1)								\
	(((double)(tv2.tv_sec  - tv1.tv_sec) * 1000000.0 +	\
	  (double)(tv2.tv_usec - tv1.tv_usec)) / 1000.0)
#define TP_DIFF(tp2,tp1)						\
	((tp2.tv_sec - tp1.tv_sec) * 1000000000UL +	(tp2.tv_nsec - tp1.tv_nsec))

/*
 * simple wrapper for permission checks
 */
static inline void
strom_proc_aclcheck(Oid func_oid, Oid user_id, AclMode mode)
{
	aclcheck_error(pg_proc_aclcheck(func_oid, user_id, mode),
#if PG_VERSION_NUM < 110000
				   ACL_KIND_PROC,
#else
				   OBJECT_FUNCTION,
#endif
				   format_procedure(func_oid));
}

static inline void
strom_foreign_table_aclcheck(Oid ftable_oid, Oid user_id, AclMode mode)
{
	aclcheck_error(pg_class_aclcheck(ftable_oid, user_id, mode),
#if PG_VERSION_NUM < 110000
				   ACL_KIND_CLASS,
#else
				   OBJECT_FOREIGN_TABLE,
#endif
				   get_rel_name(ftable_oid));
}

#endif	/* PG_STROM_H */
