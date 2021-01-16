/*
 * main.c
 *
 * Entrypoint of PG-Strom extension, and misc uncategolized functions.
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

PG_MODULE_MAGIC;

/*
 * miscellaneous GUC parameters
 */
bool		pgstrom_enabled;
bool		pgstrom_cpu_fallback_enabled;
bool		pgstrom_regression_test_mode;
static int	pgstrom_chunk_size_kb;

/* cost factors */
double		pgstrom_gpu_setup_cost;
double		pgstrom_gpu_dma_cost;
double		pgstrom_gpu_operator_cost;

/* misc static variables */
static HTAB				   *gpu_path_htable = NULL;
static planner_hook_type	planner_hook_next = NULL;
static CustomPathMethods	pgstrom_dummy_path_methods;
static CustomScanMethods	pgstrom_dummy_plan_methods;

/* misc variables */
long		PAGE_SIZE;
long		PAGE_MASK;
int			PAGE_SHIFT;
long		PHYS_PAGES;

/* pg_strom.chunk_size */
Size
pgstrom_chunk_size(void)
{
	return ((Size)pgstrom_chunk_size_kb) << 10;
}

static void
pgstrom_init_common_guc(void)
{
	/* turn on/off PG-Strom feature */
	DefineCustomBoolVariable("pg_strom.enabled",
							 "Enables the planner's use of PG-Strom",
							 NULL,
							 &pgstrom_enabled,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* turn on/off CPU fallback if GPU could not execute the query */
	DefineCustomBoolVariable("pg_strom.cpu_fallback",
							 "Enables CPU fallback if GPU required re-run",
							 NULL,
							 &pgstrom_cpu_fallback_enabled,
							 false,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* default length of pgstrom_data_store */
	DefineCustomIntVariable("pg_strom.chunk_size",
							"default size of pgstrom_data_store",
							NULL,
							&pgstrom_chunk_size_kb,
							65534,	/* almost 64MB */
							4096,
							MAX_KILOBYTES,
							PGC_INTERNAL,
							GUC_NOT_IN_SAMPLE | GUC_UNIT_KB,
							NULL, NULL, NULL);
	/* cost factor for Gpu setup */
	DefineCustomRealVariable("pg_strom.gpu_setup_cost",
							 "Cost to setup GPU device to run",
							 NULL,
							 &pgstrom_gpu_setup_cost,
							 4000 * DEFAULT_SEQ_PAGE_COST,
							 0,
							 DBL_MAX,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* cost factor for each Gpu task */
	DefineCustomRealVariable("pg_strom.gpu_dma_cost",
							 "Cost to send/recv data via DMA",
							 NULL,
							 &pgstrom_gpu_dma_cost,
							 10 * DEFAULT_SEQ_PAGE_COST,
							 0,
							 DBL_MAX,
                             PGC_USERSET,
                             GUC_NOT_IN_SAMPLE,
                             NULL, NULL, NULL);
	/* cost factor for Gpu operator */
	DefineCustomRealVariable("pg_strom.gpu_operator_cost",
							 "Cost of processing each operators by GPU",
							 NULL,
							 &pgstrom_gpu_operator_cost,
							 DEFAULT_CPU_OPERATOR_COST / 16.0,
							 0,
							 DBL_MAX,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* disables some platform specific EXPLAIN output */
	DefineCustomBoolVariable("pg_strom.regression_test_mode",
							 "Disables some platform specific output in EXPLAIN; that can lead undesired test failed but harmless",
							 NULL,
							 &pgstrom_regression_test_mode,
							 false,
							 PGC_USERSET,
							 GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
}

/*
 * GPU-aware path tracker
 *
 * motivation: add_path() and add_partial_path() keeps only cheapest paths.
 * Once some other dominates GpuXXX paths, it shall be wiped out, even if
 * it potentially has a chance for more optimization (e.g, GpuJoin outer
 * pull-up, GpuPreAgg + GpuJoin combined mode).
 * So, we preserve PG-Strom related Path-nodes for the later referenced.
 */
typedef struct
{
	PlannerInfo	   *root;
	Relids			relids;
	bool			outer_parallel;
	bool			inner_parallel;
	const Path	   *cheapest_gpu_path;
} gpu_path_entry;

static uint32
gpu_path_entry_hashvalue(const void *key, Size keysize)
{
	gpu_path_entry *gent = (gpu_path_entry *)key;
	uint32		hash;
	uint32		flags = 0;

	Assert(keysize == 0);
	hash = hash_uint32(((uintptr_t)gent->root & 0xffffffffUL) ^
					   ((uintptr_t)gent->root >> 32));
	if (gent->relids != NULL)
	{
		Bitmapset  *relids = gent->relids;
		
		hash ^= hash_any((unsigned char *)relids,
						 offsetof(Bitmapset, words[relids->nwords]));
	}
	if (gent->outer_parallel)
		flags |= 0x01;
	if (gent->inner_parallel)
		flags |= 0x02;
	hash ^= hash_uint32(flags);

	return hash;
}

static int
gpu_path_entry_compare(const void *key1, const void *key2, Size keysize)
{
	gpu_path_entry *gent1 = (gpu_path_entry *)key1;
	gpu_path_entry *gent2 = (gpu_path_entry *)key2;

	Assert(keysize == 0);

	if (gent1->root == gent2->root &&
		bms_equal(gent1->relids, gent2->relids) &&
		gent1->outer_parallel == gent2->outer_parallel &&
		gent1->inner_parallel == gent2->inner_parallel)
		return 0;
	/* not equal */
	return 1;
}

static void *
gpu_path_entry_keycopy(void *dest, const void *src, Size keysize)
{
	gpu_path_entry *dent = (gpu_path_entry *)dest;
	const gpu_path_entry *sent = (const gpu_path_entry *)src;

	Assert(keysize == 0);
	dent->root = sent->root;
	dent->relids = bms_copy(sent->relids);
	dent->outer_parallel = sent->outer_parallel;
	dent->inner_parallel = sent->inner_parallel;

	return dest;
}

const Path *
gpu_path_find_cheapest(PlannerInfo *root, RelOptInfo *rel,
					   bool outer_parallel,
					   bool inner_parallel)
{
	gpu_path_entry	hkey;
	gpu_path_entry *gent;

	memset(&hkey, 0, sizeof(gpu_path_entry));
	hkey.root = root;
	hkey.relids = rel->relids;
	hkey.outer_parallel = outer_parallel;
	hkey.inner_parallel = inner_parallel;

	gent = hash_search(gpu_path_htable, &hkey, HASH_FIND, NULL);
	if (!gent)
		return NULL;
	return gent->cheapest_gpu_path;
}

bool
gpu_path_remember(PlannerInfo *root, RelOptInfo *rel,
				  bool outer_parallel,
				  bool inner_parallel,
				  const Path *gpu_path)
{
	gpu_path_entry	hkey;
	gpu_path_entry *gent;
	bool			found;

	memset(&hkey, 0, sizeof(gpu_path_entry));
	hkey.root = root;
	hkey.relids = rel->relids;
	hkey.outer_parallel = outer_parallel;
	hkey.inner_parallel = inner_parallel;

	gent = hash_search(gpu_path_htable, &hkey, HASH_ENTER, &found);
	if (found)
	{
		/* new path is more expensive than prior one! */
		if (gent->cheapest_gpu_path->total_cost < gpu_path->total_cost)
			return false;
	}
	Assert(gent->root == root &&
		   bms_equal(gent->relids, rel->relids) &&
		   gent->outer_parallel == outer_parallel &&
		   gent->inner_parallel == inner_parallel);
	gent->cheapest_gpu_path = pgstrom_copy_pathnode(gpu_path);

	return true;
}

/*
 * pgstrom_create_dummy_path
 */
Path *
pgstrom_create_dummy_path(PlannerInfo *root,
						  Path *subpath,
						  PathTarget *target)
{
	CustomPath *cpath = makeNode(CustomPath);

	cpath->path.pathtype		= T_CustomScan;
	cpath->path.parent			= subpath->parent;
	cpath->path.pathtarget		= target;
	cpath->path.param_info		= NULL;
	cpath->path.parallel_aware	= subpath->parallel_aware;
	cpath->path.parallel_safe	= subpath->parallel_safe;
	cpath->path.parallel_workers = subpath->parallel_workers;
	cpath->path.pathkeys		= subpath->pathkeys;
	cpath->path.rows			= subpath->rows;
	cpath->path.startup_cost	= subpath->startup_cost;
	cpath->path.total_cost		= subpath->total_cost;

	cpath->custom_paths			= list_make1(subpath);
	cpath->methods      		= &pgstrom_dummy_path_methods;

	return &cpath->path;
}

/*
 * pgstrom_dummy_create_plan - PlanCustomPath callback
 */
static Plan *
pgstrom_dummy_create_plan(PlannerInfo *root,
						  RelOptInfo *rel,
						  CustomPath *best_path,
						  List *tlist,
						  List *clauses,
						  List *custom_plans)
{
	CustomScan *cscan = makeNode(CustomScan);

	Assert(list_length(custom_plans) == 1);
	cscan->scan.plan.parallel_aware = best_path->path.parallel_aware;
	cscan->scan.plan.targetlist = tlist;
	cscan->scan.plan.qual = NIL;
	cscan->scan.plan.lefttree = linitial(custom_plans);
	cscan->scan.scanrelid = 0;
	cscan->custom_scan_tlist = tlist;
	cscan->methods = &pgstrom_dummy_plan_methods;

	return &cscan->scan.plan;
}

/*
 * pgstrom_dummy_remove_plan
 */
static Plan *
pgstrom_dummy_remove_plan(PlannedStmt *pstmt, CustomScan *cscan)
{
	Plan	   *subplan = outerPlan(cscan);
	ListCell   *lc1;
	ListCell   *lc2;

	Assert(innerPlan(cscan) == NULL &&
		   cscan->custom_plans == NIL);
	Assert(list_length(cscan->scan.plan.targetlist) ==
		   list_length(subplan->targetlist));
	/*
	 * Push down the resource name to subplan
	 */
	forboth (lc1, cscan->scan.plan.targetlist,
			 lc2, subplan->targetlist)
	{
		TargetEntry	   *tle_1 = lfirst(lc1);
		TargetEntry	   *tle_2 = lfirst(lc2);

		if (exprType((Node *)tle_1->expr) != exprType((Node *)tle_2->expr))
			elog(ERROR, "Bug? dummy custom scan node has incompatible tlist");

		if (tle_2->resname != NULL &&
			(tle_1->resname == NULL ||
			 strcmp(tle_1->resname, tle_2->resname) != 0))
		{
			elog(DEBUG2,
				 "attribute %d of subplan: [%s] is over-written by [%s]",
				 tle_2->resno,
				 tle_2->resname,
				 tle_1->resname);
		}
		if (tle_1->resjunk != tle_2->resjunk)
			elog(DEBUG2,
				 "attribute %d of subplan: [%s] is marked as %s attribute",
				 tle_2->resno,
                 tle_2->resname,
				 tle_1->resjunk ? "junk" : "non-junk");

		tle_2->resname = tle_1->resname;
		tle_2->resjunk = tle_1->resjunk;
	}
	return outerPlan(cscan);
}

/*
 * pgstrom_dummy_create_scan_state - CreateCustomScanState callback
 */
static Node *
pgstrom_dummy_create_scan_state(CustomScan *cscan)
{
	elog(ERROR, "Bug? dummy custom scan node still remain on executor stage");
}

/*
 * pgstrom_post_planner
 *
 * remove 'dummy' custom scan node.
 */
static void
pgstrom_post_planner_recurse(PlannedStmt *pstmt, Plan **p_plan)
{
	Plan	   *plan = *p_plan;
	ListCell   *lc;

	Assert(plan != NULL);

	switch (nodeTag(plan))
	{
		case T_ModifyTable:
			{
				ModifyTable *splan = (ModifyTable *) plan;

				foreach (lc, splan->plans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;
			
		case T_Append:
			{
				Append	   *splan = (Append *) plan;

				foreach (lc, splan->appendplans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;

		case T_MergeAppend:
			{
				MergeAppend *splan = (MergeAppend *) plan;

				foreach (lc, splan->mergeplans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;

		case T_BitmapAnd:
			{
				BitmapAnd  *splan = (BitmapAnd *) plan;

				foreach (lc, splan->bitmapplans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;

		case T_BitmapOr:
			{
				BitmapOr   *splan = (BitmapOr *) plan;

				foreach (lc, splan->bitmapplans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;

		case T_SubqueryScan:
			{
				SubqueryScan *sscan = (SubqueryScan *) plan;

				pgstrom_post_planner_recurse(pstmt, &sscan->subplan);
			}
			break;

		case T_CustomScan:
			{
				CustomScan *cscan = (CustomScan *) plan;

				if (cscan->methods == &pgstrom_dummy_plan_methods)
				{
					*p_plan = pgstrom_dummy_remove_plan(pstmt, cscan);
					pgstrom_post_planner_recurse(pstmt, p_plan);
					return;
				}
				else if (pgstrom_plan_is_gpupreagg(&cscan->scan.plan))
					gpupreagg_post_planner(pstmt, cscan);

				foreach (lc, cscan->custom_plans)
					pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));
			}
			break;

		default:
			break;
	}

	if (plan->lefttree)
		pgstrom_post_planner_recurse(pstmt, &plan->lefttree);
	if (plan->righttree)
		pgstrom_post_planner_recurse(pstmt, &plan->righttree);
}

static PlannedStmt *
pgstrom_post_planner(Query *parse,
#if PG_VERSION_NUM >= 130000
					 const char *query_string,
#endif
					 int cursorOptions,
					 ParamListInfo boundParams)
{
	HTAB		   *gpu_path_htable_saved = gpu_path_htable;
	PlannedStmt	   *pstmt;
	ListCell	   *lc;

	PG_TRY();
	{
		HASHCTL		hctl;

		/* make hash-table to preserve GPU-aware path-nodes */
		memset(&hctl, 0, sizeof(HASHCTL));
		hctl.hcxt = CurrentMemoryContext;
		hctl.keysize = 0;
		hctl.entrysize = sizeof(gpu_path_entry);
		hctl.hash = gpu_path_entry_hashvalue;
		hctl.match = gpu_path_entry_compare;
		hctl.keycopy = gpu_path_entry_keycopy;
		gpu_path_htable = hash_create("GPU-aware Path-nodes table",
									  512,
									  &hctl,
									  HASH_CONTEXT |
									  HASH_ELEM |
									  HASH_FUNCTION |
									  HASH_COMPARE |
									  HASH_KEYCOPY);
		pstmt = planner_hook_next(parse,
#if PG_VERSION_NUM >= 130000
								  query_string,
#endif
								  cursorOptions,
								  boundParams);
	}
	PG_CATCH();
	{
		hash_destroy(gpu_path_htable);
		gpu_path_htable = gpu_path_htable_saved;
		PG_RE_THROW();
	}
	PG_END_TRY();
	hash_destroy(gpu_path_htable);
	gpu_path_htable = gpu_path_htable_saved;

	pgstrom_post_planner_recurse(pstmt, &pstmt->planTree);
	foreach (lc, pstmt->subplans)
		pgstrom_post_planner_recurse(pstmt, (Plan **)&lfirst(lc));

	return pstmt;
}

/*
 * _PG_init
 *
 * Main entrypoint of PG-Strom. It shall be invoked only once when postmaster
 * process is starting up, then it calls other sub-systems to initialize for
 * each ones.
 */
void
_PG_init(void)
{
	/*
	 * PG-Strom has to be loaded using shared_preload_libraries option
	 */
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
		errmsg("PG-Strom must be loaded via shared_preload_libraries")));

	/* load NVIDIA/HeteroDB related stuff, if any */
	pgstrom_init_nvrtc();
	pgstrom_init_cufile();
	pgstrom_init_extra();

	/* dump version number */
#ifdef PGSTROM_VERSION
	elog(LOG, "PG-Strom version %s built for PostgreSQL %s",
		 PGSTROM_VERSION, PG_MAJORVERSION);
#else
	elog(LOG, "PG-Strom built for PostgreSQL %s", PG_MAJORVERSION);
#endif
	/* init misc variables */
	PAGE_SIZE = sysconf(_SC_PAGESIZE);
	PAGE_MASK = PAGE_SIZE - 1;
	PAGE_SHIFT = get_next_log2(PAGE_SIZE);
	PHYS_PAGES = sysconf(_SC_PHYS_PAGES);

	/* init GPU/CUDA infrastracture */
	pgstrom_init_common_guc();
	pgstrom_init_shmbuf();
	pgstrom_init_gpu_device();
	pgstrom_init_gpu_mmgr();
	pgstrom_init_gpu_context();
	pgstrom_init_cuda_program();
	pgstrom_init_gpu_direct();
	pgstrom_init_codegen();

	/* init custom-scan providers/FDWs */
	pgstrom_init_gputasks();
	pgstrom_init_gpuscan();
	pgstrom_init_gpujoin();
	pgstrom_init_gpupreagg();
	pgstrom_init_relscan();
	pgstrom_init_arrow_fdw();
	pgstrom_init_gpu_store();

	/* dummy custom-scan node */
	memset(&pgstrom_dummy_path_methods, 0, sizeof(CustomPathMethods));
	pgstrom_dummy_path_methods.CustomName	= "Dummy";
	pgstrom_dummy_path_methods.PlanCustomPath
		= pgstrom_dummy_create_plan;

	memset(&pgstrom_dummy_plan_methods, 0, sizeof(CustomScanMethods));
	pgstrom_dummy_plan_methods.CustomName	= "Dummy";
	pgstrom_dummy_plan_methods.CreateCustomScanState
		= pgstrom_dummy_create_scan_state;

	/* planner hook registration */
	planner_hook_next = (planner_hook ? planner_hook : standard_planner);
	planner_hook = pgstrom_post_planner;
}
