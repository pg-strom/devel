/*
 * gpuscan.c
 *
 * Sequential scan accelerated by GPU processors
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
#include "cuda_gpuscan.h"

static set_rel_pathlist_hook_type	set_rel_pathlist_next;
static CustomPathMethods	gpuscan_path_methods;
static CustomScanMethods	gpuscan_plan_methods;
static CustomExecMethods	gpuscan_exec_methods;
bool						enable_gpuscan;		/* GUC */
static bool					enable_pullup_outer_scan;

/*
 * form/deform interface of private field of CustomScan(GpuScan)
 */
typedef struct {
	cl_int		optimal_gpu;	/* optimal GPU selection, or -1 */
	char	   *kern_source;	/* source of the CUDA kernel */
	cl_uint		extra_flags;	/* extra libraries to be included */
	cl_uint		varlena_bufsz;	/* buffer size of temporary varlena datum */
	cl_uint		proj_tuple_sz;	/* nbytes of the expected result tuple size */
	cl_uint		proj_extra_sz;	/* length of extra-buffer on kernel */
	cl_uint		nrows_per_block;/* estimated tuple density per block */
	List	   *outer_refs;		/* referenced outer attributes */
	List	   *used_params;
	List	   *dev_quals;		/* implicitly-ANDed device quals */
	Oid			index_oid;		/* OID of BRIN-index, if any */
	List	   *index_conds;	/* BRIN-index key conditions */
	List	   *index_quals;	/* original BRIN-index qualifier */
} GpuScanInfo;

static inline void
form_gpuscan_info(CustomScan *cscan, GpuScanInfo *gs_info)
{
	List	   *privs = NIL;
	List	   *exprs = NIL;

	privs = lappend(privs, makeInteger(gs_info->optimal_gpu));
	privs = lappend(privs, makeString(gs_info->kern_source));
	privs = lappend(privs, makeInteger(gs_info->extra_flags));
	privs = lappend(privs, makeInteger(gs_info->varlena_bufsz));
	privs = lappend(privs, makeInteger(gs_info->proj_tuple_sz));
	privs = lappend(privs, makeInteger(gs_info->proj_extra_sz));
	privs = lappend(privs, makeInteger(gs_info->nrows_per_block));
	privs = lappend(privs, gs_info->outer_refs);
	exprs = lappend(exprs, gs_info->used_params);
	exprs = lappend(exprs, gs_info->dev_quals);
	privs = lappend(privs, makeInteger(gs_info->index_oid));
	privs = lappend(privs, gs_info->index_conds);
	exprs = lappend(exprs, gs_info->index_quals);

	cscan->custom_private = privs;
	cscan->custom_exprs = exprs;
}

static inline GpuScanInfo *
deform_gpuscan_info(CustomScan *cscan)
{
	GpuScanInfo *gs_info = palloc0(sizeof(GpuScanInfo));
	List	   *privs = cscan->custom_private;
	List	   *exprs = cscan->custom_exprs;
	int			pindex = 0;
	int			eindex = 0;

	gs_info->optimal_gpu = intVal(list_nth(privs, pindex++));
	gs_info->kern_source = strVal(list_nth(privs, pindex++));
	gs_info->extra_flags = intVal(list_nth(privs, pindex++));
	gs_info->varlena_bufsz = intVal(list_nth(privs, pindex++));
	gs_info->proj_tuple_sz = intVal(list_nth(privs, pindex++));
	gs_info->proj_extra_sz = intVal(list_nth(privs, pindex++));
	gs_info->nrows_per_block = intVal(list_nth(privs, pindex++));
	gs_info->outer_refs = list_nth(privs, pindex++);
	gs_info->used_params = list_nth(exprs, eindex++);
	gs_info->dev_quals = list_nth(exprs, eindex++);
	gs_info->index_oid = intVal(list_nth(privs, pindex++));
	gs_info->index_conds = list_nth(privs, pindex++);
	gs_info->index_quals = list_nth(exprs, eindex++);

	return gs_info;
}

typedef struct {
	GpuTaskRuntimeStat	c;		/* common statistics */
} GpuScanRuntimeStat;

typedef struct {
	dsm_handle		ss_handle;		/* DSM handle of the SharedState */
	cl_uint			ss_length;		/* Length of the SharedState */
	GpuScanRuntimeStat gs_rtstat;
} GpuScanSharedState;

typedef struct {
	GpuTaskState	gts;
	GpuScanSharedState *gs_sstate;
	GpuScanRuntimeStat *gs_rtstat;
	ExprState	   *dev_quals;		/* quals to be run on the device */
	cl_uint			proj_tuple_sz;
	cl_uint			proj_extra_sz;
	/* resource for CPU fallback */
	cl_uint			fallback_group_id;
	cl_uint			fallback_local_id;
	TupleTableSlot *base_slot;
	ProjectionInfo *base_proj;
} GpuScanState;

typedef struct
{
	GpuTask				task;
	bool				with_nvme_strom;
	bool				with_projection;
	/* DMA buffers */
	pgstrom_data_store *pds_src;
	pgstrom_data_store *pds_dst;
	kern_gpuscan		kern;
} GpuScanTask;

/*
 * static functions
 */
static GpuTask  *gpuscan_next_task(GpuTaskState *gts);
static TupleTableSlot *gpuscan_next_tuple(GpuTaskState *gts);
static void gpuscan_switch_task(GpuTaskState *gts, GpuTask *gtask);
static int gpuscan_process_task(GpuTask *gtask, CUmodule cuda_module);
static void gpuscan_release_task(GpuTask *gtask);

static void createGpuScanSharedState(GpuScanState *gss,
									 ParallelContext *pcxt,
									 void *dsm_addr);
static void resetGpuScanSharedState(GpuScanState *gss);

/*
 * cost_for_dma_receive - cost estimation for DMA receive (GPU->host)
 */
Cost
cost_for_dma_receive(RelOptInfo *rel, double ntuples)
{
	PathTarget *reltarget = rel->reltarget;
	cl_int		nattrs = list_length(reltarget->exprs);
	cl_int		width_per_tuple;

	if (ntuples < 0.0)
		ntuples = rel->rows;
	width_per_tuple = offsetof(kern_tupitem, htup) +
		MAXALIGN(offsetof(HeapTupleHeaderData,
						  t_bits[BITMAPLEN(nattrs)])) +
		MAXALIGN(reltarget->width);
	return pgstrom_gpu_dma_cost *
		(((double)width_per_tuple * ntuples) / (double)pgstrom_chunk_size());
}

/*
 * create_gpuscan_path - constructor of CustomPath(GpuScan) node
 */
static Path *
create_gpuscan_path(PlannerInfo *root,
					RelOptInfo *baserel,
					List *dev_quals,
					List *host_quals,
					int parallel_nworkers,	/* for parallel-scan */
					IndexOptInfo *indexOpt,	/* for BRIN-index */
					List *indexConds,		/* for BRIN-index */
					List *indexQuals,		/* for BRIN-index */
					cl_long indexNBlocks)	/* for BRIN-index */
{
	GpuScanInfo	   *gs_info = palloc0(sizeof(GpuScanInfo));
	CustomPath	   *cpath;
	ParamPathInfo  *param_info;
	List		   *ppi_quals;
	Cost			startup_cost;
	Cost			run_cost;
	Cost			startup_delay;
	QualCost		qcost;
	double			parallel_divisor;
	double			scan_ntuples;
	double			scan_nchunks;
	double			cpu_per_tuple = 0.0;
	int				scan_mode;

	/* cost for disk i/o + GPU qualifiers */
	scan_mode = pgstrom_common_relscan_cost(root,
											baserel,
											extract_actual_clauses(dev_quals, false),
											parallel_nworkers,
											indexOpt,
											indexQuals,
											indexNBlocks,
											&parallel_divisor,
											&scan_ntuples,
											&scan_nchunks,
											&gs_info->nrows_per_block,
											&startup_cost,
											&run_cost);
	/* save the optimal GPU for the scan target */
	gs_info->optimal_gpu = GetOptimalGpuForRelation(root, baserel);
	/* save the BRIN-index if preferable to use */
	if ((scan_mode & PGSTROM_RELSCAN_BRIN_INDEX) != 0)
	{
		gs_info->index_oid = indexOpt->indexoid;
		gs_info->index_conds = indexConds;
		gs_info->index_quals = indexQuals;
	}

	param_info = get_baserel_parampathinfo(root, baserel,
										   baserel->lateral_relids);
	cpath = makeNode(CustomPath);
	cpath->path.pathtype = T_CustomScan;
	cpath->path.parent = baserel;
	cpath->path.pathtarget = baserel->reltarget;
	cpath->path.param_info = param_info;
	cpath->path.parallel_aware = parallel_nworkers > 0 ? true : false;
	cpath->path.parallel_safe = baserel->consider_parallel;
	cpath->path.parallel_workers = parallel_nworkers;
	cpath->path.rows = (param_info
						? param_info->ppi_rows
						: baserel->rows) / parallel_divisor;

	/* cost for DMA receive (GPU-->host) */
	if ((scan_mode & PGSTROM_RELSCAN_GPU_STORE) == 0)
		run_cost += cost_for_dma_receive(baserel, scan_ntuples);

	/* cost for CPU qualifiers */
	cost_qual_eval(&qcost, host_quals, root);
	startup_cost += qcost.startup;
	cpu_per_tuple += qcost.per_tuple;

	/* PPI costs (as a part of host quals, if any) */
	ppi_quals = (param_info ? param_info->ppi_clauses : NIL);
	cost_qual_eval(&qcost, ppi_quals, root);
	startup_cost += qcost.startup;
	cpu_per_tuple += qcost.per_tuple;
	run_cost += (cpu_per_tuple + cpu_tuple_cost) * scan_ntuples;

	/*
	 * Cost for projection
	 *
	 * MEMO: Even if GpuScan can run complicated projection on the device,
	 * expression on the target-list shall be assigned on the CustomPath node
	 * after the selection of the cheapest path, and its cost shall be
	 * discounted by the core logic (see apply_projection_to_path).
	 * In the previous implementation, we discounted the cost to be processed
	 * by GpuProjection, however, it leads unexpected optimizer behavior.
	 * Right now, we stop to discount the cost for GpuProjection.
	 * Probably, it needs API enhancement of CustomScan.
	 */
	startup_cost += baserel->reltarget->cost.startup;
	run_cost += baserel->reltarget->cost.per_tuple * scan_ntuples;

	/* Latency to get the first chunk */
	startup_delay = run_cost * (1.0 / scan_nchunks);

	cpath->path.startup_cost = startup_cost + startup_delay;
	cpath->path.total_cost = startup_cost + run_cost;
	cpath->path.pathkeys = NIL;	/* unsorted results */
	cpath->flags = 0;
	cpath->custom_paths = NIL;
	cpath->custom_private = list_make1(gs_info);
	cpath->methods = &gpuscan_path_methods;

	return &cpath->path;
}

/*
 * gpuscan_add_scan_path - entrypoint of the set_rel_pathlist_hook
 */
static void
gpuscan_add_scan_path(PlannerInfo *root,
					  RelOptInfo *baserel,
					  Index rtindex,
					  RangeTblEntry *rte)
{
	Path	   *pathnode;
	List	   *dev_quals = NIL;
	List	   *host_quals = NIL;
	IndexOptInfo *indexOpt;
	List	   *indexConds;
	List	   *indexQuals;
	cl_long		indexNBlocks;
	ListCell   *lc;

	/* call the secondary hook */
	if (set_rel_pathlist_next)
		set_rel_pathlist_next(root, baserel, rtindex, rte);

	/* nothing to do, if either PG-Strom or GpuScan is not enabled */
	if (!pgstrom_enabled || !enable_gpuscan)
		return;

	/* We already proved the relation empty, so nothing more to do */
	if (is_dummy_rel(baserel))
		return;

	/* It is the role of built-in Append node */
	if (rte->inh)
		return;
	/*
	 * GpuScan can run on only base relations or foreign table managed
	 * by arrow_fdw/gstore_fdw.
	 */
	if (rte->relkind == RELKIND_FOREIGN_TABLE)
	{
		if (!baseRelIsArrowFdw(baserel))
			return;
	}
	else if (rte->relkind != RELKIND_RELATION &&
			 rte->relkind != RELKIND_MATVIEW)
		return;

	/* Check whether the qualifier can run on GPU device */
	foreach (lc, baserel->baserestrictinfo)
	{
		RestrictInfo   *rinfo = lfirst(lc);

		if (pgstrom_device_expression(root, baserel, rinfo->clause))
			dev_quals = lappend(dev_quals, rinfo);
		else
			host_quals = lappend(host_quals, rinfo);
	}
	if (dev_quals == NIL)
		return;

	/* Check availability of GpuScan+BRIN Index */
	indexOpt = pgstrom_tryfind_brinindex(root, baserel,
										 &indexConds,
										 &indexQuals,
										 &indexNBlocks);

	/* add GpuScan path in single process */
	pathnode = create_gpuscan_path(root, baserel,
								   dev_quals,
								   host_quals,
								   0,
								   indexOpt,
								   indexConds,
								   indexQuals,
								   indexNBlocks);
	if (gpu_path_remember(root, baserel,
						  false, false,
						  pathnode))
		add_path(baserel, pathnode);

	/* If appropriate, consider parallel GpuScan */
	if (baserel->consider_parallel && baserel->lateral_relids == NULL)
	{
		int		parallel_nworkers
			= compute_parallel_worker(baserel,
									  baserel->pages, -1.0,
									  max_parallel_workers_per_gather);
		/*
		 * XXX - Do we need a something specific logic for GpuScan to adjust
		 * parallel_workers.
		 */
		if (parallel_nworkers <= 0)
			return;

		/* add GpuScan path performing on parallel workers */
		pathnode = create_gpuscan_path(root, baserel,
									   dev_quals,
									   host_quals,
									   parallel_nworkers,
									   indexOpt,
									   indexConds,
									   indexQuals,
									   indexNBlocks);
		if (gpu_path_remember(root, baserel,
							  true, false,
							  pathnode))
			add_partial_path(baserel, pathnode);
	}
}

/*
 * reorder_devqual_clauses
 */
static List *
reorder_devqual_clauses(PlannerInfo *root, List *dev_quals, List *dev_costs)
{
	ListCell   *lc1, *lc2;
	int			nitems;
	int			i, j, k;
	List	   *results = NIL;
	struct {
		Node   *qual;
		int		cost;
	}		   *items, temp;

	nitems = list_length(dev_quals);
	if (nitems <= 1)
		return dev_quals;
	items = palloc0(sizeof(*items) * nitems);

	i = 0;
	forboth (lc1, dev_quals,
			 lc2, dev_costs)
	{
		items[i].qual = lfirst(lc1);
		items[i].cost = lfirst_int(lc2);
		i++;
	}

	for (i=0; i < nitems; i++)
	{
		k = i;
		for (j=i+1; j < nitems; j++)
		{
			if (items[j].cost < items[k].cost)
				k = j;
		}
		if (i != k)
		{
			temp = items[i];
			items[i] = items[k];
			items[k] = temp;
		}
		results = lappend(results, items[i].qual);
	}
	pfree(items);

	return results;
}

/*
 * Code generator for GpuScan's qualifier
 */
void
codegen_gpuscan_quals(StringInfo kern, codegen_context *context,
					  const char *component,
					  Index scanrelid, List *dev_quals_list)
{
	devtype_info   *dtype;
	StringInfoData	tfunc;
	StringInfoData	afunc;
	StringInfoData  cfunc;
	StringInfoData	temp;
	Node		   *dev_quals;
	Var			   *var;
	char		   *expr_code = NULL;
	ListCell	   *lc;

	initStringInfo(&tfunc);
	initStringInfo(&afunc);
	initStringInfo(&cfunc);
	initStringInfo(&temp);

	if (scanrelid == 0 || dev_quals_list == NIL)
		goto output;
	/* Let's walk on the device expression tree */
	dev_quals = (Node *)make_flat_ands_explicit(dev_quals_list);
	expr_code = pgstrom_codegen_expression(dev_quals, context);
	/* Const/Param declarations */
	pgstrom_codegen_param_declarations(&tfunc, context);
	pgstrom_codegen_param_declarations(&afunc, context);
	pgstrom_codegen_param_declarations(&cfunc, context);
	/* Sanity check of used_vars */
	foreach (lc, context->used_vars)
	{
		var = lfirst(lc);
		if (var->varno != scanrelid)
			elog(ERROR, "unexpected var-node reference: %s expected %u",
				 nodeToString(var), scanrelid);
		if (var->varattno == 0)
			elog(ERROR, "cannot have whole-row reference on GPU expression");
		if (var->varattno < 0)
			elog(ERROR, "cannot have system column on GPU expression");
		dtype = pgstrom_devtype_lookup(var->vartype);
		if (!dtype)
			elog(ERROR, "failed to lookup device type: %s",
				 format_type_be(var->vartype));
	}

	/*
	 * Var declarations - if qualifier uses only one variables (like x > 0),
	 * the pg_xxxx_vref() service routine is more efficient because it may
	 * use attcacheoff to skip walking on tuple attributes.
	 */
	if (list_length(context->used_vars) <= 1)
	{
		foreach (lc, context->used_vars)
		{
			var = lfirst(lc);

			if (var->varattno <= 0)
				elog(ERROR, "Bug? system column appeared in expression");

			dtype = pgstrom_devtype_lookup(var->vartype);
			appendStringInfo(
				&tfunc,
				"  pg_%s_t %s_%u;\n\n"
				"  addr = kern_get_datum_tuple(kds->colmeta,htup,%u);\n"
				"  pg_datum_ref(kcxt,%s_%u,addr);\n",
				dtype->type_name,
				context->var_label, var->varattno,
				var->varattno - 1,
				context->var_label, var->varattno);
			appendStringInfo(
				&afunc,
				"  pg_%s_t %s_%u;\n\n"
				"  pg_datum_ref_arrow(kcxt,%s_%u,kds,%u,row_index);\n",
				dtype->type_name,
				context->var_label, var->varattno,
				context->var_label, var->varattno,
				var->varattno - 1);
			appendStringInfo(
				&cfunc,
				"  pg_%s_t %s_%u;\n\n"
				"  addr = kern_get_datum_column(kds,extra,%u,row_index);\n"
				"  pg_datum_ref(kcxt,%s_%u,addr);\n",
				dtype->type_name,
				context->var_label, var->varattno,
				var->varattno - 1,
				context->var_label, var->varattno);
		}
	}
	else
	{
		AttrNumber		anum, varattno_max = 0;

		/* declarations */
		/* note that no expression including system column reference are*/
		resetStringInfo(&temp);
		foreach (lc, context->used_vars)
		{
			var = lfirst(lc);
			Assert(var->varattno > 0);
			dtype = pgstrom_devtype_lookup(var->vartype);
			appendStringInfo(
				&temp,
				"  pg_%s_t %s_%u;\n",
				dtype->type_name,
				context->var_label, var->varattno);
			varattno_max = Max(varattno_max, var->varattno);
		}
		appendStringInfoString(&tfunc, temp.data);
		appendStringInfoString(&afunc, temp.data);
		appendStringInfoString(&cfunc, temp.data);

		appendStringInfoString(
			&tfunc,
			"  assert(htup != NULL);\n"
			"  EXTRACT_HEAP_TUPLE_BEGIN(addr,kds,htup);\n");
		for (anum=1; anum <= varattno_max; anum++)
		{
			foreach (lc, context->used_vars)
			{
				var = lfirst(lc);

				if (var->varattno == anum)
				{
					dtype = pgstrom_devtype_lookup(var->vartype);

					appendStringInfo(
						&tfunc,
						"  pg_datum_ref(kcxt,%s_%u,addr); // pg_%s_t\n",
						context->var_label, var->varattno,
						dtype->type_name);
					appendStringInfo(
						&afunc,
						"  pg_datum_ref_arrow(kcxt,%s_%u,kds,%u,row_index);\n",
						context->var_label, var->varattno,
						var->varattno - 1);
					appendStringInfo(
						&cfunc,
						"  addr = kern_get_datum_column(kds,extra,%u,row_index);\n"
						"  pg_datum_ref(kcxt,%s_%u,addr); // pg_%s_t\n",
						var->varattno - 1,
						context->var_label, var->varattno,
						dtype->type_name);
					break;	/* no need to read same value twice */
				}
			}

			if (anum < varattno_max)
				appendStringInfoString(
					&tfunc,
					"  EXTRACT_HEAP_TUPLE_NEXT(addr,kds);\n");
		}
		appendStringInfoString(
			&tfunc,
			"  EXTRACT_HEAP_TUPLE_END();\n");
	}
output:
	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(cl_bool)\n"
		"%s_quals_eval(kern_context *kcxt,\n"
		"                   kern_data_store *kds,\n"
		"                   ItemPointerData *t_self,\n"
		"                   HeapTupleHeaderData *htup)\n"
		"{\n"
		"  void *addr __attribute__((unused));\n"
		"%s%s\n"
		"  return %s;\n"
		"}\n\n"
		"DEVICE_FUNCTION(cl_bool)\n"
		"%s_quals_eval_arrow(kern_context *kcxt,\n"
		"                         kern_data_store *kds,\n"
		"                         cl_uint row_index)\n"
		"{\n"
		"  void *addr __attribute__((unused));\n"
		"%s%s\n"
		"  return %s;\n"
		"}\n\n"
		"DEVICE_FUNCTION(cl_bool)\n"
		"%s_quals_eval_column(kern_context *kcxt,\n"
		"                         kern_data_store *kds,\n"
		"                         kern_data_extra *extra,\n"
		"                         cl_uint row_index)\n"
		"{\n"
		"  void *addr __attribute__((unused));\n"
		"%s%s\n"
		"  return %s;\n"
		"}\n\n",
		component,
		context->decl_temp.data,
		tfunc.data,
		!expr_code ? "true" : psprintf("EVAL(%s)", expr_code),
		component,
		context->decl_temp.data,
		afunc.data,
		!expr_code ? "true" : psprintf("EVAL(%s)", expr_code),
		component,
		context->decl_temp.data,
		cfunc.data,
		!expr_code ? "true" : psprintf("EVAL(%s)", expr_code));
}

/*
 * Code generator for GpuScan's projection
 */
static void
codegen_gpuscan_projection(StringInfo kern,
						   codegen_context *context,
						   RelOptInfo *baserel,
						   Relation relation,
						   List *__tlist_dev,
						   Bitmapset *outer_refs)
{
	Index			scanrelid = baserel->relid;
	TupleDesc		tupdesc = RelationGetDescr(relation);
	List		   *tlist_dev = NIL;
	List		   *type_oid_list = NIL;
	AttrNumber	   *varremaps;
	Bitmapset	   *varattnos;
	ListCell	   *lc;
	int				prev;
	int				i, j, k;
	int				nfields;
	int				num_referenced = 0;
	devtype_info   *dtype;
	StringInfoData	decl;
	StringInfoData	tbody;
	StringInfoData	abody;
	StringInfoData	cbody;
	StringInfoData	temp;

	initStringInfo(&decl);
	initStringInfo(&tbody);
	initStringInfo(&abody);
	initStringInfo(&cbody);
	initStringInfo(&temp);

	/*
	 * step.1 - extract non-junk attributes
	 */
	foreach (lc, __tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);

		if (!tle->resjunk)
			tlist_dev = lappend(tlist_dev, tle);
	}

	/*
	 * step.2 - extend varlena-buffer for dclass/values array
	 */
	if (tlist_dev)
		nfields = list_length(tlist_dev);
	else
		nfields = RelationGetNumberOfAttributes(relation);
	context->varlena_bufsz += (MAXALIGN(sizeof(Datum) * nfields) +
							   MAXALIGN(sizeof(cl_char) * nfields));
	/*
	 * step.2 - setup of varremaps / varattnos
	 */
	varremaps = palloc0(sizeof(AttrNumber) * list_length(tlist_dev));
	varattnos = NULL;
	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);

		Assert(tle->resno > 0 && tle->resno <= list_length(tlist_dev));
		/*
		 * NOTE: If expression of TargetEntry is a simple Var-node,
		 * we can load the value into tup_values[]/tup_isnull[]
		 * array regardless of the data type. We have to track which
		 * column is the source of this TargetEntry.
		 * Elsewhere, we will construct device side expression using
		 * KVAR_xx variables.
		 */
		if (IsA(tle->expr, Var))
		{
			Var	   *var = (Var *) tle->expr;

			Assert(var->varno == scanrelid);
			Assert(var->varattno != InvalidAttrNumber);
			varremaps[tle->resno - 1] = var->varattno;
		}
		else
		{
			pull_varattnos((Node *)tle->expr, scanrelid, &varattnos);
		}
	}

	/*
	 * step.3 - declarations of KVAR_x for source of expressions
	 */
	prev = -1;
	while ((prev = bms_next_member(varattnos, prev)) >= 0)
	{
		Form_pg_attribute attr;
		AttrNumber		anum = prev + FirstLowInvalidHeapAttributeNumber;

		Assert(anum > 0);
		attr = tupleDescAttr(tupdesc, anum-1);

		dtype = pgstrom_devtype_lookup_and_track(attr->atttypid, context);
		if (!dtype)
			elog(ERROR, "Bug? failed to lookup device supported type: %s",
				 format_type_be(attr->atttypid));
		if (anum < 0)
			elog(ERROR, "Bug? system column appear in device expression");
		appendStringInfo(&decl, "  pg_%s_t KVAR_%u;\n",
						 dtype->type_name, anum);
	}

	/*
	 * step.4 - system attribute references if any
	 */
	for (i=FirstLowInvalidHeapAttributeNumber+1; i < 0; i++)
	{
		const FormData_pg_attribute *attr = SystemAttributeDefinition(i);

		for (j=0; j < list_length(tlist_dev); j++)
		{
			if (varremaps[j] != attr->attnum)
				continue;
			/* row&block */
			appendStringInfo(
				&tbody,
				"  pg_sysattr_%s_store(kcxt,kds_src,htup,t_self,\n"
				"                      tup_dclass[%d],\n"
				"                      tup_values[%d]);\n",
				NameStr(attr->attname), j, j);
			/* arrow */
			appendStringInfo(
				&abody,
				"  pg_sysattr_%s_fetch_arrow(kcxt,kds_src,index,\n"
				"                            tup_dclass[%d],\n"
				"                            tup_values[%d]);\n",
				NameStr(attr->attname), j, j);
			/* column */
			appendStringInfo(
				&cbody,
				"  pg_sysattr_%s_fetch_column(kcxt,kds_src,index,\n"
				"                             tup_dclass[%d],\n"
				"                             tup_values[%d]);\n",
				NameStr(attr->attname), j, j);

			context->varlena_bufsz += MAXALIGN(sizeof(ItemPointerData));
		}
	}

	/*
	 * step.4 - reference attributes for each
	 */
	resetStringInfo(&temp);
	appendStringInfoString(
		&temp,
		"  EXTRACT_HEAP_TUPLE_BEGIN(addr,kds_src,htup);\n");
	for (i=0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = tupleDescAttr(tupdesc, i);
		bool		referenced = false;

		dtype = pgstrom_devtype_lookup(attr->atttypid);
		k = attr->attnum - FirstLowInvalidHeapAttributeNumber;

		/* Put values on tup_values/tup_isnull if referenced */
		for (j=0; j < list_length(tlist_dev); j++)
		{
			if (varremaps[j] != attr->attnum)
				continue;

			/* tuple */
			if (attr->attbyval)
			{
				appendStringInfo(
					&temp,
					"  EXTRACT_HEAP_READ_%dBIT(addr,tup_dclass[%d],tup_values[%d]);\n",
					8 * attr->attlen, j, j);
			}
			else
			{
				appendStringInfo(
					&temp,
					"  EXTRACT_HEAP_READ_POINTER(addr,tup_dclass[%d],tup_values[%d]);\n",
					j, j);
			}

			/* arrow */
			if (!dtype)
			{
				appendStringInfo(
					&abody,
					"  tup_dclass[%d] = DATUM_CLASS__NULL;\n", j);
			}
			else
			{
				if (!referenced)
					appendStringInfo(
						&abody,
						"  pg_datum_ref_arrow(kcxt,temp.%s_v,kds_src,%u,index);\n",
						dtype->type_name, attr->attnum-1);
				appendStringInfo(
					&abody,
					"  pg_datum_store(kcxt, temp.%s_v,\n"
					"                 tup_dclass[%d],\n"
					"                 tup_values[%d]);\n",
					dtype->type_name, j, j);
				context->extra_flags |= dtype->type_flags;
				context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
				type_oid_list = list_append_unique_oid(type_oid_list,
													   dtype->type_oid);
			}

			/* column */
			if (!referenced)
				appendStringInfo(
					&cbody,
					"  addr = kern_get_datum_column(kds_src,kds_extra,%d,index);\n",
					attr->attnum-1);
			if (attr->attbyval)
			{
				appendStringInfo(
					&cbody,
					"  if (!addr)\n"
					"    tup_dclass[%d] = DATUM_CLASS__NULL;\n"
					"  else\n"
					"  {\n"
					"    tup_dclass[%d] = DATUM_CLASS__NORMAL;\n"
					"    tup_values[%d] = READ_INT%u_PTR(addr);\n"
					"  }\n", j, j, j, 8 * attr->attlen);
			}
			else
			{
				appendStringInfo(
					&cbody,
					"  if (!addr)\n"
					"    tup_dclass[%d] = DATUM_CLASS__NULL;\n"
					"  else\n"
					"  {\n"
					"    tup_dclass[%d] = DATUM_CLASS__NORMAL;\n"
					"    tup_values[%d] = PointerGetDatum(addr);\n"
					"  }\n", j, j, j);
			}
			referenced = true;
		}
		/* Load values to KVAR_xx */
		k = attr->attnum - FirstLowInvalidHeapAttributeNumber;
		if (bms_is_member(k, varattnos))
		{
			Assert(dtype != NULL);
			/* tuple */
			appendStringInfo(
				&temp,
				"  pg_datum_ref(kcxt,KVAR_%u,addr);\n",
				attr->attnum);
			/* arrow */
			if (!referenced)
			{
				appendStringInfo(
					&abody,
					"  pg_datum_ref_arrow(kcxt,KVAR_%u,kds_src,%u,index);\n",
					attr->attnum, attr->attnum - 1);
			}
			else
			{
				appendStringInfo(
					&abody,
					"  KVAR_%u = temp.%s_v;\n",
					attr->attnum, dtype->type_name);
			}
			/* column */
			if (!referenced)
				appendStringInfo(
					&cbody,
					"  addr = kern_get_datum_column(kds_src,kds_extra,%d,index);\n",
					attr->attnum - 1);
			appendStringInfo(
				&cbody,
				"  pg_datum_ref(kcxt,KVAR_%u,addr);\n", attr->attnum);

			type_oid_list = list_append_unique_oid(type_oid_list,
												   dtype->type_oid);
			referenced = true;
		}

		if (referenced)
		{
			appendStringInfoString(&tbody, temp.data);
			resetStringInfo(&temp);
			num_referenced++;
		}
		appendStringInfoString(
			&temp,
			"  EXTRACT_HEAP_TUPLE_NEXT(addr,kds_src);\n");
	}
	if (num_referenced)
		appendStringInfoString(
			&tbody,
			"  EXTRACT_HEAP_TUPLE_END();\n"
			"\n");
	/*
	 * step.5 - execution of expression node, then store the result.
	 */
	resetStringInfo(&context->decl_temp);
	resetStringInfo(&temp);
	foreach (lc, tlist_dev)
	{
		TargetEntry	   *tle = lfirst(lc);
		Oid				type_oid;

		/* host pointer should be already set */
		if (varremaps[tle->resno-1])
		{
			Assert(IsA(tle->expr, Var));
			continue;
		}

		type_oid = exprType((Node *)tle->expr);
		dtype = pgstrom_devtype_lookup(type_oid);
		if (!dtype)
			elog(ERROR, "Bug? device supported type is missing: %s",
				 format_type_be(type_oid));

		appendStringInfo(
			&temp,
			"  temp.%s_v = %s;\n"
			"  pg_datum_store(kcxt, temp.%s_v,\n"
			"                 tup_dclass[%d],\n"
			"                 tup_values[%d]);\n",
			dtype->type_name,
			pgstrom_codegen_expression((Node *)tle->expr, context),
			dtype->type_name,
			tle->resno - 1,
			tle->resno - 1);
		context->extra_flags |= dtype->type_flags;
		context->varlena_bufsz += MAXALIGN(dtype->extra_sz);
		type_oid_list = list_append_unique_oid(type_oid_list,
											   dtype->type_oid);
	}
	appendStringInfoString(&tbody, temp.data);
	appendStringInfoString(&abody, temp.data);
	appendStringInfoString(&cbody, temp.data);

	/* parameter references */
	pgstrom_codegen_param_declarations(&decl, context);

	/*
	 * step.6 - put decl/body on the function body
	 */
	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpuscan_projection_tuple(kern_context *kcxt,\n"
		"                         kern_data_store *kds_src,\n"
		"                         HeapTupleHeaderData *htup,\n"
		"                         ItemPointerData *t_self,\n"
		"                         cl_char *tup_dclass,\n"
		"                         Datum   *tup_values)\n"
		"{\n"
		"  void        *addr __attribute__((unused));\n"
		"%s%s", decl.data, context->decl_temp.data);
	pgstrom_union_type_declarations(kern, "temp", type_oid_list);
	appendStringInfo(kern, "\n%s}\n\n", tbody.data);

	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpuscan_projection_arrow(kern_context *kcxt,\n"
		"                         kern_data_store *kds_src,\n"
		"                         size_t   index,\n"
		"                         cl_char *tup_dclass,\n"
		"                         Datum   *tup_values)\n"
		"{\n"
		"  void        *addr __attribute__((unused));\n"
		"%s%s", decl.data, context->decl_temp.data);
	pgstrom_union_type_declarations(kern, "temp", type_oid_list);
	appendStringInfo(kern, "\n%s}\n\n", abody.data);

	appendStringInfo(
		kern,
		"DEVICE_FUNCTION(void)\n"
		"gpuscan_projection_column(kern_context *kcxt,\n"
		"                          kern_data_store *kds_src,\n"
		"                          kern_data_extra *kds_extra,\n"
		"                          size_t index,\n"
		"                          cl_char *tup_dclass,\n"
		"                          Datum *tup_values)\n"
		"{\n"
		"  void        *addr __attribute__((unused));\n"
		"%s%s", decl.data, context->decl_temp.data);
	pgstrom_union_type_declarations(kern, "temp", type_oid_list);
	appendStringInfo(kern, "\n%s}\n\n", cbody.data);

	list_free(tlist_dev);
	list_free(type_oid_list);
	pfree(temp.data);
	pfree(decl.data);
	pfree(tbody.data);
	pfree(abody.data);
	pfree(cbody.data);
}

/*
 * add_unique_expression - adds an expression node on the supplied
 * target-list, then returns true, if new target-entry was added.
 */
static List *
add_unique_expression(List *tlist, Node *node, bool resjunk)
{
	TargetEntry	   *tle;
	ListCell	   *lc;

	foreach (lc, tlist)
	{
		tle = (TargetEntry *) lfirst(lc);
		if (equal(node, tle->expr))
		{
			if (tle->resjunk && !resjunk)
				tle->resjunk = false;
			return tlist;
		}
	}
	tle = makeTargetEntry((Expr *)copyObject(node),
						  list_length(tlist) + 1,
						  NULL,
						  resjunk);
	return lappend(tlist, tle);
}

/*
 * build_gpuscan_projection
 *
 * It checks whether the GpuProjection of GpuScan makes sense.
 * If executor may require the physically compatible tuple as result,
 * we don't need to have a projection in GPU side.
 */
typedef struct
{
	PlannerInfo *root;
	RelOptInfo	*baserel;
	bool		resjunk;
	bool		has_expressions;
	size_t		extra_sz;
	List	   *tlist_temp;
} build_gpuscan_projection_context;

static bool
build_gpuscan_projection_walker(Node *node, void *__context)
{
	build_gpuscan_projection_context *context = __context;
	int			extra_sz;

	if (!node)
		return false;

	if (IsA(node, Var))
	{
		RelOptInfo *baserel = context->baserel;
		Var		   *varnode = (Var *) node;
		bool		resjunk;

		/*
		 * Is it a reference to other relation to be replaced by
		 * replace_nestloop_params(). So, it shall be executed on
		 * the CPU side.
		 */
		if (!bms_is_member(varnode->varno, baserel->relids))
			return false;
		Assert(varnode->varlevelsup == 0);

		/* GPU projection cannot contain whole-row var */
		if (varnode->varattno == InvalidAttrNumber)
			return true;
		resjunk = (varnode->varattno < 0 || context->resjunk);
		context->tlist_temp = add_unique_expression(context->tlist_temp,
													node, resjunk);
		return false;
	}
	else if (IsA(node, Const) || IsA(node, Param))
	{
		/* no need to carry constant values from GPU kernel */
		return false;
	}
	else if (pgstrom_device_expression_extrasz(context->root,
											   context->baserel,
											   (Expr *) node,
											   &extra_sz))
	{
		//TODO: Var must be on scanrel
		context->tlist_temp = add_unique_expression(context->tlist_temp,
													node,
													context->resjunk);
		context->has_expressions = true;
		context->extra_sz += MAXALIGN(extra_sz);
		return false;
	}
	/* walks down if expression is host-only */
	return expression_tree_walker(node, build_gpuscan_projection_walker,
								  context);
}

static List *
build_gpuscan_projection(PlannerInfo *root,
						 RelOptInfo *baserel,
						 Relation relation,
						 List *tlist,
						 List *host_quals,
						 List *dev_quals,
						 cl_int *p_tuple_sz,
						 cl_int *p_extra_sz)
{
	build_gpuscan_projection_context context;
	TupleDesc	tupdesc = RelationGetDescr(relation);
	List	   *tlist_dev = NIL;
	List	   *vars_list;
	ListCell   *lc;
	cl_uint		extra_sz = 0;
	cl_uint		tuple_sz = 0;
	int			j;

	memset(&context, 0, sizeof(context));
	context.root = root;
	context.baserel = baserel;
	if (tlist != NIL)
	{
		foreach (lc, tlist)
		{
			TargetEntry	   *tle = lfirst(lc);

			if (build_gpuscan_projection_walker((Node *)tle->expr, &context))
				goto no_gpu_projection;
		}
	}
	else
	{
		/*
		 * When ProjectionPath is on CustomPath(GpuScan), it always assigns
		 * the result of build_path_tlist() and calls PlanCustomPath method
		 * with tlist == NIL.
		 * So, if GPU projection wants to make something valuable, we need
		 * to check path-target.
		 * Also don't forget all the Var-nodes to be added must exist at
		 * the custom_scan_tlist because setrefs.c references this list.
		 */
		foreach (lc, baserel->reltarget->exprs)
		{
			if (build_gpuscan_projection_walker((Node *)lfirst(lc), &context))
				goto no_gpu_projection;
		}
	}
	if (!context.has_expressions)
		goto no_gpu_projection;

	/*
	 * Referenced by the host quals
	 */
	if (host_quals)
	{
		vars_list = pull_vars_of_level((Node *)host_quals, 0);
		foreach (lc, vars_list)
		{
			Var	   *var = lfirst(lc);
			if (var->varattno == InvalidAttrNumber)
				goto no_gpu_projection;
			context.tlist_temp = add_unique_expression(context.tlist_temp,
													   (Node *)var, false);
		}
		list_free(vars_list);
	}

	/*
	 * Device quals need as junk attribute
	 */
	context.resjunk = true;
	if (dev_quals)
	{
		vars_list = pull_vars_of_level((Node *)dev_quals, 0);
		foreach (lc, vars_list)
		{
			Var	   *var = lfirst(lc);
			if (var->varattno == InvalidAttrNumber)
				goto no_gpu_projection;
			context.tlist_temp = add_unique_expression(context.tlist_temp,
													   (Node *) var, true);
		}
		list_free(vars_list);
	}
	tlist_dev = context.tlist_temp;
no_gpu_projection:
	if (tlist_dev == NIL)
	{
		if (tlist)
			vars_list = pull_vars_of_level((Node *)tlist, 0);
		else
			vars_list = pull_vars_of_level((Node *)baserel->reltarget->exprs, 0);
		if (host_quals != NIL)
			vars_list = list_concat(vars_list,
									pull_vars_of_level((Node *)host_quals, 0));
		foreach (lc, vars_list)
		{
			Var	   *var = lfirst(lc);

			if (var->varattno != InvalidAttrNumber)
				tlist_dev = add_unique_expression(tlist_dev, (Node *)var, false);
			else
			{
				/* whole-row references */
				for (j=0; j < tupdesc->natts; j++)
				{
					Form_pg_attribute attr = tupleDescAttr(tupdesc, j);

					if (attr->attisdropped)
						continue;
					var = makeVar(baserel->relid,
								  attr->attnum,
								  attr->atttypid,
								  attr->atttypmod,
								  attr->attcollation, 0);
					tlist_dev = add_unique_expression(tlist_dev, (Node *)var, false);
				}
			}
		}
		list_free(vars_list);

		if (dev_quals != NIL)
		{
			vars_list = pull_vars_of_level((Node *)dev_quals, 0);
			foreach (lc, vars_list)
			{
				Var	   *var = lfirst(lc);
				Assert(var->varattno != InvalidAttrNumber);
				tlist_dev = add_unique_expression(tlist_dev, (Node *)var, true);
			}
			list_free(vars_list);
		}
	}
	/* calculation of tuple/extra size */
	tuple_sz = offsetof(kern_tupitem,
						htup.t_bits[BITMAPLEN(tupdesc->natts)]);
	if (tupleDescHasOid(tupdesc))
		tuple_sz += sizeof(Oid);
	tuple_sz = MAXALIGN(tuple_sz);
	extra_sz = MAXALIGN(context.extra_sz);
	foreach (lc, tlist_dev)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(lc);
		int16		typlen;
		bool		typbyval;
		char		typalign;

		if (tle->resjunk)
			continue;
		if (IsA(tle->expr, Var))
		{
			Var	   *var = (Var *)tle->expr;

			get_typlenbyvalalign(var->vartype, &typlen, &typbyval, &typalign);
			tuple_sz = att_align_nominal(tuple_sz, typalign);
			tuple_sz += baserel->attr_widths[var->varattno - 1];
			/* Apache Arrow may consume extra buffer for varlena */
			if (typlen == -1)
				extra_sz += 48;
		}
		else
		{
			Oid		type_id = exprType((Node *)tle->expr);
			int		type_mod = exprTypmod((Node *)tle->expr);

			get_typlenbyvalalign(type_id, &typlen, &typbyval, &typalign);
			tuple_sz = att_align_nominal(tuple_sz, typalign);
			tuple_sz += get_typavgwidth(type_id, type_mod);
		}
	}
	*p_tuple_sz = MAXALIGN(tuple_sz);
	*p_extra_sz = extra_sz;
	return tlist_dev;
}

/*
 * PlanGpuScanPath - construction of a new GpuScan plan node
 */
static Plan *
PlanGpuScanPath(PlannerInfo *root,
				RelOptInfo *baserel,
				CustomPath *best_path,
				List *tlist,
				List *clauses,
				List *custom_children)
{
	GpuScanInfo	   *gs_info = linitial(best_path->custom_private);
	CustomScan	   *cscan;
	RangeTblEntry  *rte;
	Relation		relation;
	List		   *host_quals = NIL;
	List		   *dev_quals = NIL;
	List		   *dev_costs = NIL;
	List		   *index_quals = NIL;
	List		   *tlist_dev = NIL;
	List		   *outer_refs = NIL;
	ListCell	   *cell;
	Bitmapset	   *varattnos = NULL;
	cl_int			proj_tuple_sz = 0;
	cl_int			proj_extra_sz = 0;
	cl_int			qual_extra_sz = 0;
	cl_int			i, j;
	StringInfoData	kern;
	codegen_context	context;

	/* It should be a base relation */
	Assert(baserel->relid > 0);
	Assert(baserel->rtekind == RTE_RELATION);
	Assert(custom_children == NIL);

	/*
	 * Distribution of clauses into device executable and others.
	 *
	 * NOTE: Why we don't sort out on Path construction stage is,
	 * create_scan_plan() may add parameterized scan clause, thus
	 * we have to delay the final decision until this point.
	 */
	foreach (cell, clauses)
	{
		RestrictInfo *rinfo = lfirst(cell);
		int		devcost;

		if (exprType((Node *)rinfo->clause) != BOOLOID)
			elog(ERROR, "Bug? clause on GpuScan does not have BOOL type");
		if (!pgstrom_device_expression_devcost(root,
											   baserel,
											   rinfo->clause,
											   &devcost))
			host_quals = lappend(host_quals, rinfo);
		else
		{
			dev_quals = lappend(dev_quals, rinfo);
			dev_costs = lappend_int(dev_costs, devcost);
		}
	}
	/* Reduce RestrictInfo list to bare expressions; ignore pseudoconstants */
	host_quals = extract_actual_clauses(host_quals, false);
	dev_quals = reorder_devqual_clauses(root, dev_quals, dev_costs);
	dev_quals = extract_actual_clauses(dev_quals, false);
	index_quals = extract_actual_clauses(gs_info->index_quals, false);

	/*
	 * Code construction for the CUDA kernel code
	 */
	rte = planner_rt_fetch(baserel->relid, root);
	relation = table_open(rte->relid, NoLock);

	initStringInfo(&kern);
	pgstrom_init_codegen_context(&context, root, baserel);
	codegen_gpuscan_quals(&kern, &context, "gpuscan",
						  baserel->relid, dev_quals);
	qual_extra_sz = context.varlena_bufsz;
	tlist_dev = build_gpuscan_projection(root,
										 baserel,
										 relation,
										 tlist,
										 host_quals,
										 dev_quals,
										 &proj_tuple_sz,
										 &proj_extra_sz);
	if (tlist_dev)
		pull_varattnos((Node *)tlist_dev, baserel->relid, &varattnos);
	else
		pull_varattnos((Node *)baserel->reltarget->exprs,
					   baserel->relid, &varattnos);
	pull_varattnos((Node *)host_quals, baserel->relid, &varattnos);

	context.param_refs = NULL;
	context.varlena_bufsz = Max(qual_extra_sz, proj_extra_sz);
	codegen_gpuscan_projection(&kern,
							   &context,
							   baserel,
							   relation,
							   tlist_dev,
							   varattnos);
	table_close(relation, NoLock);

	/* save the outer_refs for columnar optimization */
	pull_varattnos((Node *)dev_quals, baserel->relid, &varattnos);
	for (i = bms_next_member(varattnos, -1);
		 i >= 0;
		 i = bms_next_member(varattnos, i))
	{
		j = i + FirstLowInvalidHeapAttributeNumber;
		outer_refs = lappend_int(outer_refs, j);
	}

	/*
	 * Construction of GpuScanPlan node; on top of CustomPlan node
	 */
	cscan = makeNode(CustomScan);
	cscan->scan.plan.targetlist = tlist;
	cscan->scan.plan.qual = host_quals;
	cscan->scan.plan.lefttree = NULL;
	cscan->scan.plan.righttree = NULL;
	cscan->scan.scanrelid = baserel->relid;
	cscan->flags = best_path->flags;
	cscan->methods = &gpuscan_plan_methods;
	cscan->custom_plans = NIL;
	cscan->custom_scan_tlist = tlist_dev;

	gs_info->kern_source = kern.data;
	gs_info->extra_flags = context.extra_flags | DEVKERNEL_NEEDS_GPUSCAN;
	gs_info->varlena_bufsz = context.varlena_bufsz;
	gs_info->proj_tuple_sz = proj_tuple_sz;
	gs_info->proj_extra_sz = proj_extra_sz;
	gs_info->outer_refs = outer_refs;
	gs_info->used_params = context.used_params;
	gs_info->dev_quals = dev_quals;
	gs_info->index_quals = index_quals;
	form_gpuscan_info(cscan, gs_info);

	return &cscan->scan.plan;
}

/*
 * pgstrom_pullup_outer_scan - pull up outer_path if it is a simple relation
 * scan with device executable qualifiers.
 */
bool
pgstrom_pullup_outer_scan(PlannerInfo *root,
						  const Path *outer_path,
						  Index *p_outer_relid,
						  List **p_outer_quals,
						  cl_int *p_cuda_dindex,
						  IndexOptInfo **p_index_opt,
						  List **p_index_conds,
						  List **p_index_quals,
						  cl_long *p_index_nblocks)
{
	RelOptInfo *baserel = outer_path->parent;
	PathTarget *outer_target = outer_path->pathtarget;
	List	   *outer_quals = NIL;
	List	   *outer_costs = NIL;
	cl_int		cuda_dindex = -1;
	IndexOptInfo *indexOpt = NULL;
	List	   *indexConds = NIL;
	List	   *indexQuals = NIL;
	cl_long		indexNBlocks = 0;
	ListCell   *lc;

	if (!enable_pullup_outer_scan)
		return false;

	for (;;)
	{
		if (outer_path->pathtype == T_SeqScan)
			break;	/* OK */
		if (pgstrom_path_is_gpuscan(outer_path))
			break;	/* OK, only if GpuScan */
		if (outer_path->pathtype == T_ForeignScan &&
			baseRelIsArrowFdw(outer_path->parent))
			break;	/* OK, only if ArrowFdw or GstoreFdw */
		if (IsA(outer_path, ProjectionPath))
		{
			ProjectionPath *ppath = (ProjectionPath *) outer_path;
			if (ppath->dummypp)
			{
				outer_path = ppath->subpath;
				continue;	/* Dive into one more deep level */
			}
		}
		return false;	/* Elsewhere, we cannot pull-up the scan path */
	}

	/* qualifier has to be device executable */
	foreach (lc, baserel->baserestrictinfo)
	{
		RestrictInfo *rinfo = lfirst(lc);
		int		devcost;

		if (!pgstrom_device_expression_devcost(root,
											   baserel,
											   rinfo->clause,
											   &devcost))
			return false;
		outer_quals = lappend(outer_quals, rinfo);
		outer_costs = lappend_int(outer_costs, devcost);
	}
	outer_quals = reorder_devqual_clauses(root, outer_quals, outer_costs);
	outer_quals = extract_actual_clauses(outer_quals, false);

	/* target entry has to be */
	foreach (lc, outer_target->exprs)
	{
		Expr   *expr = (Expr *) lfirst(lc);

		if (IsA(expr, Var))
		{
			Var	   *var = (Var *) expr;

			/* must be a field on the table */
			if (!bms_is_member(var->varno, baserel->relids))
				return false;
			/* we don't support whole-row reference */
			if (var->varattno == InvalidAttrNumber)
				return false;
		}
		else if (!pgstrom_device_expression(root, baserel, expr))
			return false;
	}
	/* Optimal GPU selection */
	cuda_dindex = GetOptimalGpuForRelation(root, baserel);

	/* BRIN-index parameters */
	indexOpt = pgstrom_tryfind_brinindex(root, baserel,
										 &indexConds,
										 &indexQuals,
										 &indexNBlocks);
	*p_outer_relid = baserel->relid;
	*p_outer_quals = outer_quals;
	*p_cuda_dindex = cuda_dindex;
	*p_index_opt = indexOpt;
	*p_index_conds = indexConds;
	*p_index_quals = indexQuals;

	return true;
}

/*
 * pgstrom_path_is_gpuscan
 *
 * It returns true, if supplied path node is gpuscan.
 */
bool
pgstrom_path_is_gpuscan(const Path *path)
{
	if (IsA(path, CustomPath) &&
		path->pathtype == T_CustomScan &&
		((CustomPath *) path)->methods == &gpuscan_path_methods)
		return true;
	return false;
}

/*
 * pgstrom_plan_is_gpuscan
 *
 * It returns true, if supplied plan node is gpuscan.
 */
bool
pgstrom_plan_is_gpuscan(const Plan *plan)
{
	if (IsA(plan, CustomScan) &&
		((CustomScan *) plan)->methods == &gpuscan_plan_methods)
		return true;
	return false;
}

/*
 * pgstrom_planstate_is_gpuscan
 *
 * It returns true, if supplied planstate node is gpuscan
 */
bool
pgstrom_planstate_is_gpuscan(const PlanState *ps)
{
	if (IsA(ps, CustomScanState) &&
		((CustomScanState *) ps)->methods == &gpuscan_exec_methods)
		return true;
	return false;
}

/*
 * pgstrom_copy_gpuscan_path
 *
 * Note that this function shall never copies individual fields recursively.
 */
Path *
pgstrom_copy_gpuscan_path(const Path *pathnode)
{
	Assert(pgstrom_path_is_gpuscan(pathnode));
	return (Path *)pmemdup(pathnode, sizeof(CustomPath));
}

/*
 * fixup_varnode_to_origin
 */
static Node *
fixup_varnode_to_origin(Node *node, List *custom_scan_tlist)
{
	if (!node)
		return NULL;
	if (IsA(node, Var))
	{
		Var	   *varnode = (Var *)node;
		TargetEntry *tle;

		if (custom_scan_tlist != NIL)
		{
			Assert(varnode->varno == INDEX_VAR);
			Assert(varnode->varattno >= 1 &&
				   varnode->varattno <= list_length(custom_scan_tlist));
			tle = list_nth(custom_scan_tlist,
						   varnode->varattno - 1);
			return (Node *)copyObject(tle->expr);
		}
		Assert(!IS_SPECIAL_VARNO(varnode->varno));
	}
	return expression_tree_mutator(node, fixup_varnode_to_origin,
								   (void *)custom_scan_tlist);
}

/*
 * assign_gpuscan_session_info
 */
void
assign_gpuscan_session_info(StringInfo buf, GpuTaskState *gts)
{
	CustomScan *cscan = (CustomScan *)gts->css.ss.ps.plan;

	appendStringInfo(
		buf,
		"/* GpuScan session info */\n"
		"#define GPUSCAN_HAS_DEVICE_PROJECTION %d\n\n",
		cscan->custom_scan_tlist != NIL ? 1 : 0);
}

/*
 * gpuscan_create_scan_state - allocation of GpuScanState
 */
static Node *
gpuscan_create_scan_state(CustomScan *cscan)
{
	GpuScanState   *gss = MemoryContextAllocZero(CurTransactionContext,
												 sizeof(GpuScanState));
	/* Set tag and executor callbacks */
	NodeSetTag(gss, T_CustomScanState);
	gss->gts.css.flags = cscan->flags;
	if (cscan->methods == &gpuscan_plan_methods)
		gss->gts.css.methods = &gpuscan_exec_methods;
	else
		elog(ERROR, "Bug? unexpected CustomPlanMethods");

	return (Node *) gss;
}

/*
 * ExecInitGpuScan
 */
static void
ExecInitGpuScan(CustomScanState *node, EState *estate, int eflags)
{
	Relation		scan_rel = node->ss.ss_currentRelation;
	GpuScanState   *gss = (GpuScanState *) node;
	CustomScan	   *cscan = (CustomScan *)node->ss.ps.plan;
	GpuScanInfo	   *gs_info = deform_gpuscan_info(cscan);
	GpuContext	   *gcontext;
	TupleDesc		scan_tupdesc;
	bool			explain_only = ((eflags & EXEC_FLAG_EXPLAIN_ONLY) != 0);
	List		   *dev_tlist = NIL;
	List		   *dev_quals_raw;
	ListCell	   *lc;
	StringInfoData	kern_define;
	ProgramId		program_id;

	/* gpuscan should not have inner/outer plan right now */
	Assert(scan_rel != NULL);
	Assert(outerPlanState(node) == NULL);
	Assert(innerPlanState(node) == NULL);
	
	/* setup GpuContext for CUDA kernel execution */
	gcontext = AllocGpuContext(gs_info->optimal_gpu, false, false);
	gss->gts.gcontext = gcontext;

	/*
	 * Re-initialization of scan tuple-descriptor and projection-info,
	 * because commit 1a8a4e5cde2b7755e11bde2ea7897bd650622d3e of
	 * PostgreSQL makes to assign result of ExecTypeFromTL() instead
	 * of ExecCleanTypeFromTL; that leads incorrect projection.
	 * So, we try to remove junk attributes from the scan-descriptor.
	 */
	scan_tupdesc = ExecCleanTypeFromTL(cscan->custom_scan_tlist);
	ExecInitScanTupleSlot(estate, &gss->gts.css.ss, scan_tupdesc,
						  &TTSOpsVirtual);
	ExecAssignScanProjectionInfoWithVarno(&gss->gts.css.ss, INDEX_VAR);

	/* setup common GpuTaskState fields */
	pgstromInitGpuTaskState(&gss->gts,
							gcontext,
							GpuTaskKind_GpuScan,
							gs_info->outer_refs,
							gs_info->used_params,
							gs_info->optimal_gpu,
							gs_info->nrows_per_block,
							eflags);
	gss->gts.cb_next_task   = gpuscan_next_task;
	gss->gts.cb_next_tuple  = gpuscan_next_tuple;
	gss->gts.cb_switch_task = gpuscan_switch_task;
	gss->gts.cb_process_task = gpuscan_process_task;
	gss->gts.cb_release_task = gpuscan_release_task;

	/*
	 * initialize device qualifiers/projection stuff, for CPU fallback
	 *
	 * @dev_quals for CPU fallback references raw tuples regardless of device
	 * projection. So, it must be initialized to reference the raw tuples.
	 */
	dev_quals_raw = (List *)
		fixup_varnode_to_origin((Node *)gs_info->dev_quals,
								cscan->custom_scan_tlist);
	gss->dev_quals = ExecInitQual(dev_quals_raw, &gss->gts.css.ss.ps);

	foreach (lc, cscan->custom_scan_tlist)
	{
		TargetEntry	   *tle = lfirst(lc);

		if (tle->resjunk)
			break;
		dev_tlist = lappend(dev_tlist, tle);
	}

	/* device projection related resource consumption */
	gss->proj_tuple_sz = gs_info->proj_tuple_sz;
	gss->proj_extra_sz = gs_info->proj_extra_sz;
	/* initialize resource for CPU fallback */
	gss->base_slot = MakeSingleTupleTableSlot(RelationGetDescr(scan_rel),
											  &TTSOpsVirtual);
	gss->base_proj = ExecBuildProjectionInfo(dev_tlist,
											 gss->gts.css.ss.ps.ps_ExprContext,
											 gss->gts.css.ss.ss_ScanTupleSlot,
											 &gss->gts.css.ss.ps,
											 RelationGetDescr(scan_rel));
	/* init BRIN-index support, if any */
	pgstromExecInitBrinIndexMap(&gss->gts,
								gs_info->index_oid,
								gs_info->index_conds,
								gs_info->index_quals);

	/* Get CUDA program and async build if any */
	initStringInfo(&kern_define);
	pgstrom_build_session_info(&kern_define,
							   &gss->gts,
							   gs_info->extra_flags);
	program_id = pgstrom_create_cuda_program(gcontext,
											 gs_info->extra_flags,
											 gs_info->varlena_bufsz,
											 gs_info->kern_source,
											 kern_define.data,
											 false,
											 explain_only);
	gss->gts.program_id = program_id;
	pfree(kern_define.data);
}

/*
 * gpuscan_exec_recheck
 *
 * Routine of EPQ recheck on GpuScan. If any, HostQual shall be checked
 * on ExecScan(), all we have to do here is recheck of device qualifier.
 */
static bool
ExecReCheckGpuScan(CustomScanState *node, TupleTableSlot *epq_slot)
{
	GpuScanState   *gss = (GpuScanState *) node;
	ExprContext	   *econtext = node->ss.ps.ps_ExprContext;
	HeapTuple		tuple = ExecFetchSlotHeapTuple(epq_slot, false, NULL);
	TupleTableSlot *scan_slot	__attribute__((unused));
	ExprDoneCond	is_done		__attribute__((unused));
	bool			retval;

	/*
	 * Does the tuple meet the device qual condition?
	 * Please note that we should not use the supplied 'slot' as is,
	 * because it may not be compatible with relations's definition
	 * if device projection is valid.
	 */
	ExecForceStoreHeapTuple(tuple, gss->base_slot, false);
	econtext->ecxt_scantuple = gss->base_slot;
	ResetExprContext(econtext);

	retval = ExecQual(gss->dev_quals, econtext);
	if (retval && gss->base_proj)
	{
		/*
		 * NOTE: If device projection is valid, we have to adjust the
		 * supplied tuple (that follows the base relation's definition)
		 * into ss_ScanTupleSlot, to fit tuple descriptor of the supplied
		 * 'slot'.
		 */
		ExecClearTuple(epq_slot);
		scan_slot = ExecProject(gss->base_proj);
		Assert(scan_slot == epq_slot);
	}
	return retval;
}

/*
 * ExecGpuScan
 */
static TupleTableSlot *
ExecGpuScan(CustomScanState *node)
{
	GpuScanState   *gss = (GpuScanState *) node;

	ActivateGpuContext(gss->gts.gcontext);
	if (!gss->gs_sstate)
		createGpuScanSharedState(gss, NULL, NULL);
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) pgstromExecGpuTaskState,
					(ExecScanRecheckMtd) ExecReCheckGpuScan);
}

/*
 * ExecEndGpuScan
 */
static void
ExecEndGpuScan(CustomScanState *node)
{
	GpuScanState	   *gss = (GpuScanState *)node;
	GpuTaskRuntimeStat *gt_rtstat = (GpuTaskRuntimeStat *) gss->gs_rtstat;
	
	/* wait for completion of asynchronous GpuTaks */
	SynchronizeGpuContext(gss->gts.gcontext);
	/* close index related stuff if any */
	pgstromExecEndBrinIndexMap(&gss->gts);
	/* reset fallback resources */
	if (gss->base_slot)
		ExecDropSingleTupleTableSlot(gss->base_slot);
	pgstromReleaseGpuTaskState(&gss->gts, gt_rtstat);
}

/*
 * ExecReScanGpuScan
 */
static void
ExecReScanGpuScan(CustomScanState *node)
{
	GpuScanState	   *gss = (GpuScanState *) node;

	/* wait for completion of asynchronous GpuTaks */
	SynchronizeGpuContext(gss->gts.gcontext);
	/* reset shared state */
	resetGpuScanSharedState(gss);
	/* common rescan handling */
	pgstromRescanGpuTaskState(&gss->gts);
}

/*
 * ExecGpuScanEstimateDSM - return required size of shared memory
 */
static Size
ExecGpuScanEstimateDSM(CustomScanState *node,
					   ParallelContext *pcxt)
{
	return (MAXALIGN(sizeof(GpuScanSharedState)) +
			pgstromSizeOfBrinIndexMap((GpuTaskState *) node) +
			pgstromEstimateDSMGpuTaskState((GpuTaskState *)node, pcxt));
}

/*
 * ExecGpuScanInitDSM - initialize the coordinate memory on the master backend
 */
static void
ExecGpuScanInitDSM(CustomScanState *node,
				   ParallelContext *pcxt,
				   void *coordinate)
{
	GpuScanState   *gss = (GpuScanState *) node;

	/* save the ParallelContext */
	gss->gts.pcxt = pcxt;
	/* setup shared-state and runtime-statistics */
	createGpuScanSharedState(gss, pcxt, coordinate);
	on_dsm_detach(pcxt->seg,
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gss->gts.gcontext));
	coordinate = ((char *)coordinate + gss->gs_sstate->ss_length);
	if (gss->gts.outer_index_state)
	{
		gss->gts.outer_index_map = (Bitmapset *)coordinate;
		gss->gts.outer_index_map->nwords = -1;	/* uninitialized */
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gss->gts));
	}
	pgstromInitDSMGpuTaskState(&gss->gts, pcxt, coordinate);
}

/*
 * ExecGpuScanInitWorker - initialize GpuScan on the backend worker process
 */
static void
ExecGpuScanInitWorker(CustomScanState *node,
					  shm_toc *toc,
					  void *coordinate)
{
	GpuScanState	   *gss = (GpuScanState *) node;

	gss->gs_sstate = (GpuScanSharedState *)coordinate;
	gss->gs_rtstat = &gss->gs_sstate->gs_rtstat;
	on_dsm_detach(dsm_find_mapping(gss->gs_sstate->ss_handle),
				  SynchronizeGpuContextOnDSMDetach,
				  PointerGetDatum(gss->gts.gcontext));
	coordinate = ((char *)coordinate +
				  MAXALIGN(sizeof(GpuScanSharedState)));
	if (gss->gts.outer_index_state)
	{
		gss->gts.outer_index_map = (Bitmapset *)coordinate;
		coordinate = ((char *)coordinate +
					  pgstromSizeOfBrinIndexMap(&gss->gts));
	}
	pgstromInitWorkerGpuTaskState(&gss->gts, coordinate);
}

static void
ExecGpuScanReInitializeDSM(CustomScanState *node,
						   ParallelContext *pcxt, void *coordinate)
{
	pgstromReInitializeDSMGpuTaskState((GpuTaskState *) node);
}

static void
ExecShutdownGpuScan(CustomScanState *node)
{
	GpuScanState   *gss = (GpuScanState *) node;
	GpuScanRuntimeStat *gs_rtstat_old = gss->gs_rtstat;
	GpuScanRuntimeStat *gs_rtstat_new;

	/*
	 * Note that GpuScan may not be executed if GpuScan node is located
	 * under the GpuJoin at parallel background worker context, because
	 * only master process of GpuJoin is responsible to run inner nodes
	 * to load inner tuples. In other words, any inner plan nodes are
	 * not executed at the parallel worker context.
	 * So, we may not have a valid GpuScanSharedState here.
	 *
	 * Elsewhere, move the statistics from DSM
	 */
	if (!gs_rtstat_old)
		return;

	if (IsParallelWorker())
		mergeGpuTaskRuntimeStatParallelWorker(&gss->gts, &gs_rtstat_old->c);
	else
	{
		EState	   *estate = gss->gts.css.ss.ps.state;

		gs_rtstat_new = MemoryContextAlloc(estate->es_query_cxt,
										   sizeof(GpuScanRuntimeStat));
		memcpy(gs_rtstat_new,
			   gs_rtstat_old,
			   sizeof(GpuScanRuntimeStat));
		gss->gs_rtstat = gs_rtstat_new;
	}
}

/*
 * ExplainGpuScan - EXPLAIN callback
 */
static void
ExplainGpuScan(CustomScanState *node, List *ancestors, ExplainState *es)
{
	GpuScanState	   *gss = (GpuScanState *) node;
	GpuScanRuntimeStat *gs_rtstat = gss->gs_rtstat;
	CustomScan		   *cscan = (CustomScan *) gss->gts.css.ss.ps.plan;
	GpuScanInfo		   *gs_info = deform_gpuscan_info(cscan);
	List			   *dcontext;
	List			   *dev_proj = NIL;
	char			   *exprstr;
	ListCell		   *lc;

	/* merge run-time statistics */
	InstrEndLoop(&gss->gts.outer_instrument);
	if (gs_rtstat)
		mergeGpuTaskRuntimeStat(&gss->gts, &gs_rtstat->c);

	/* Set up deparsing context */
	dcontext = set_deparse_context_planstate(es->deparse_cxt,
											 (Node *)&gss->gts.css.ss.ps,
											 ancestors);
	/* Show device projection (verbose only) */
	if (es->verbose)
	{
		foreach (lc, cscan->custom_scan_tlist)
		{
			TargetEntry	   *tle = lfirst(lc);

			if (!tle->resjunk)
				dev_proj = lappend(dev_proj, tle->expr);
		}

		if (dev_proj != NIL)
		{
			exprstr = deparse_expression((Node *)dev_proj, dcontext,
										 es->verbose, false);
			ExplainPropertyText("GPU Projection", exprstr, es);
		}
	}

	/* Show device filters */
	if (gs_info->dev_quals != NIL)
	{
		Node   *dev_quals = (Node *)make_ands_explicit(gs_info->dev_quals);

		exprstr = deparse_expression(dev_quals, dcontext,
									 es->verbose, false);
		ExplainPropertyText("GPU Filter", exprstr, es);

		if (gss->gts.outer_instrument.nloops > 0)
			ExplainPropertyInteger("Rows Removed by GPU Filter", NULL,
								   gss->gts.outer_instrument.nfiltered1 /
								   gss->gts.outer_instrument.nloops, es);
	}
	/* BRIN-index properties */
	pgstromExplainBrinIndexMap(&gss->gts, es, dcontext);
	/* common portion of EXPLAIN */
	pgstromExplainGpuTaskState(&gss->gts, es);
}

/*
 * createGpuScanSharedState
 */
static void
createGpuScanSharedState(GpuScanState *gss,
						 ParallelContext *pcxt,
						 void *dsm_addr)
{
	EState	   *estate = gss->gts.css.ss.ps.state;
	GpuScanSharedState *gs_sstate;
	GpuScanRuntimeStat *gs_rtstat;
	size_t		ss_length = MAXALIGN(sizeof(GpuScanSharedState));

	if (dsm_addr)
		gs_sstate = dsm_addr;
	else
		gs_sstate = MemoryContextAlloc(estate->es_query_cxt, ss_length);
	memset(gs_sstate, 0, ss_length);
	gs_sstate->ss_handle = (pcxt ? dsm_segment_handle(pcxt->seg) : UINT_MAX);
	gs_sstate->ss_length = ss_length;

	gs_rtstat = &gs_sstate->gs_rtstat;
	SpinLockInit(&gs_rtstat->c.lock);

	gss->gs_sstate = gs_sstate;
	gss->gs_rtstat = gs_rtstat;
}

/*
 * resetGpuScanSharedState
 */
static void
resetGpuScanSharedState(GpuScanState *gss)
{
	/* do nothing */
}

/*
 * gpuscan_create_task - constructor of GpuScanTask
 */
static GpuScanTask *
gpuscan_create_task(GpuScanState *gss,
					pgstrom_data_store *pds_src)
{
	TupleTableSlot *scan_slot = gss->gts.css.ss.ss_ScanTupleSlot;
	TupleDesc		scan_tupdesc = scan_slot->tts_tupleDescriptor;
	GpuContext	   *gcontext = gss->gts.gcontext;
	pgstrom_data_store *pds_dst = NULL;
	GpuScanTask	   *gscan;
	cl_int			sm_count = 0;
	size_t			suspend_sz = 0;
	size_t			result_index_sz = 0;
	size_t			length;
	CUdeviceptr		m_deviceptr;
	CUresult		rc;

	/*
	 * A rough estimation for length of the destination buffer. Even though
	 * pgstrom_chunk_size() is not sufficient for the GpuScan result, we can
	 * suspend the kernel execution then resume it with new buffer. So, here
	 * is no problem, and allocation of identical length has another benefit
	 * because gpu_mmgr.c caches the recently released buffer.
	 */
	pds_dst = PDS_create_slot(gcontext,
							  scan_tupdesc,
							  pgstrom_chunk_size());

	sm_count = devAttrs[gcontext->cuda_dindex].MULTIPROCESSOR_COUNT;
	suspend_sz = STROMALIGN(sizeof(gpuscanSuspendContext) *
							GPUKERNEL_MAX_SM_MULTIPLICITY * sm_count);

	/*
	 * allocation of pgstrom_gpuscan
	 */
	length = (STROMALIGN(offsetof(GpuScanTask, kern.kparams)) +
			  STROMALIGN(gss->gts.kern_params->length) +
			  STROMALIGN(suspend_sz) +
			  STROMALIGN(result_index_sz));
	rc = gpuMemAllocManaged(gcontext,
							&m_deviceptr,
							length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on gpuMemAllocManaged: %s", errorText(rc));
	gscan = (GpuScanTask *) m_deviceptr;
	memset(gscan, 0, length);
	pgstromInitGpuTask(&gss->gts, &gscan->task);
	if ((pds_src->kds.format == KDS_FORMAT_BLOCK &&
		 pds_src->nblocks_uncached > 0) ||
		(pds_src->kds.format == KDS_FORMAT_ARROW &&
		 pds_src->iovec != NULL))
		gscan->with_nvme_strom = true;
	gscan->pds_src = pds_src;
	gscan->pds_dst = pds_dst;
	gscan->kern.suspend_sz = suspend_sz;
	/* kern_parambuf */
	memcpy(KERN_GPUSCAN_PARAMBUF(&gscan->kern),
		   gss->gts.kern_params,
		   gss->gts.kern_params->length);
	return gscan;
}

static void
gpuscan_switch_task(GpuTaskState *gts, GpuTask *gtask)
{
	GpuScanState   *gss = (GpuScanState *) gts;

	gss->fallback_group_id = 0;
	gss->fallback_local_id = 0;
}

/*
 * gpuscan_next_task
 */
static GpuTask *
gpuscan_next_task(GpuTaskState *gts)
{
	GpuScanState	   *gss = (GpuScanState *) gts;
	GpuScanTask		   *gscan;
	pgstrom_data_store *pds;

	if (gss->gts.af_state)
		pds = ExecScanChunkArrowFdw(gts);
	else if (gss->gts.gs_state)
		pds = ExecScanChunkGpuStore(gts);
	else
		pds = pgstromExecScanChunk(gts);
	if (!pds)
		return NULL;
	gscan = gpuscan_create_task(gss, pds);

	return &gscan->task;
}

/*
 * gpuscan_next_tuple_suspended_tuple
 */
static bool
gpuscan_next_tuple_suspended_tuple(GpuScanState *gss, GpuScanTask *gscan)
{
	pgstrom_data_store *pds_src = gscan->pds_src;
	gpuscanSuspendContext *con;
	cl_uint		window_sz = gscan->kern.block_sz * gscan->kern.grid_sz;
	cl_uint		group_id;
	cl_uint		local_id;
	cl_uint		part_index;
	size_t		base_index;

	while (gss->fallback_group_id < gscan->kern.grid_sz)
	{
		group_id = gss->fallback_group_id;
		local_id = gss->fallback_local_id;

		con = KERN_GPUSCAN_SUSPEND_CONTEXT(&gscan->kern, group_id);
		part_index = con->part_index;
		Assert(con->line_index == 0);

		base_index = (part_index * window_sz +
					  group_id * gscan->kern.block_sz);
		if (base_index >= pds_src->kds.nitems)
		{
			gss->fallback_group_id++;
			gss->fallback_local_id = 0;
			continue;
		}

		if (++gss->fallback_local_id >= gscan->kern.block_sz)
		{
			con->part_index++;
			gss->fallback_local_id = 0;
		}
		if (KDS_fetch_tuple_row(gss->base_slot,
								&pds_src->kds,
								&gss->gts.curr_tuple,
								base_index + local_id))
			return true;
	}
	return false;
}

/*
 * gpuscan_next_tuple_suspended_block
 */
static bool
gpuscan_next_tuple_suspended_block(GpuScanState *gss, GpuScanTask *gscan)
{
	pgstrom_data_store *pds_src = gscan->pds_src;
	gpuscanSuspendContext *con;
	cl_uint		group_id;
	cl_uint		local_id;
	cl_uint		part_base;
	cl_uint		part_id;
	cl_uint		part_sz;
	cl_uint		n_parts;
	cl_uint		window_sz;
	cl_uint		part_index;
	cl_uint		line_index;
	cl_uint		n_lines;
	cl_uint		line_no;
	PageHeader	hpage;
	BlockNumber	block_nr;
	ItemId		lpp;

	part_sz = gscan->kern.part_sz;
	n_parts = gscan->kern.block_sz / part_sz;
	window_sz = n_parts * gscan->kern.grid_sz;

	while (gss->fallback_group_id < gscan->kern.grid_sz)
	{
		group_id = gss->fallback_group_id;
		local_id = gss->fallback_local_id;

		con = KERN_GPUSCAN_SUSPEND_CONTEXT(&gscan->kern, group_id);
		part_index = con->part_index;
		line_index = con->line_index;

		part_base = part_index * window_sz + group_id * n_parts;
		part_id = (local_id >> 16) + part_base;
		line_no = (local_id & 0xffff) + line_index * part_sz;
		if (part_id >= pds_src->kds.nitems)
		{
			/* move to the next workgroup */
			gss->fallback_group_id++;
			gss->fallback_local_id = 0;
			continue;
		}
		block_nr = KERN_DATA_STORE_BLOCK_BLCKNR(&pds_src->kds, part_id);
		hpage = KERN_DATA_STORE_BLOCK_PGPAGE(&pds_src->kds, part_id);
		n_lines = PageGetMaxOffsetNumber(hpage);
		if (line_no < n_lines)
		{
			gss->fallback_local_id++;

			lpp = &hpage->pd_linp[line_no];
			if (ItemIdIsNormal(lpp))
			{
				HeapTuple	tuple = &gss->gts.curr_tuple;

				tuple->t_len = ItemIdGetLength(lpp);
				BlockIdSet(&tuple->t_self.ip_blkid, block_nr);
				tuple->t_self.ip_posid = line_no;
				tuple->t_tableOid = pds_src->kds.table_oid;
				tuple->t_data = (HeapTupleHeader)((char *)hpage +
												  ItemIdGetOffset(lpp));
				ExecForceStoreHeapTuple(tuple, gss->base_slot, false);

				return true;
			}
		}
		else
		{
			local_id = (local_id + 0x10000) & ~0xffffU;
			if ((local_id >> 16) < n_parts)
			{
				/* move to the next page */
				gss->fallback_local_id = local_id;
			}
			else
			{
				/* move to the next partition */
				con->part_index++;
				con->line_index = 0;
				gss->fallback_local_id = 0;
			}
		}
	}
	return false;
}

/*
 * gpuscan_next_tuple_fallback - GPU fallback case
 */
static TupleTableSlot *
gpuscan_next_tuple_fallback(GpuScanState *gss, GpuScanTask *gscan)
{
	pgstrom_data_store *pds_src = gscan->pds_src;
	GpuScanRuntimeStat *gs_rtstat = gss->gs_rtstat;
	ExprContext		   *econtext = gss->gts.css.ss.ps.ps_ExprContext;
	TupleTableSlot	   *slot = NULL;
	bool				status;

retry_next:
	ExecClearTuple(gss->base_slot);
	if (!gscan->kern.resume_context)
		status = PDS_fetch_tuple(gss->base_slot, pds_src, &gss->gts);
	else if (pds_src->kds.format == KDS_FORMAT_ROW ||
			 pds_src->kds.format == KDS_FORMAT_ARROW)
		status = gpuscan_next_tuple_suspended_tuple(gss, gscan);
	else if (pds_src->kds.format == KDS_FORMAT_BLOCK)
		status = gpuscan_next_tuple_suspended_block(gss, gscan);
	else
		elog(ERROR, "Bug? unexpected KDS format: %d", pds_src->kds.format);
	if (!status)
		return NULL;
	ResetExprContext(econtext);
	econtext->ecxt_scantuple = gss->base_slot;

	/*
	 * (1) - Evaluation of dev_quals if any
	 */
	pg_atomic_add_fetch_u64(&gs_rtstat->c.source_nitems, 1);
	if (gss->dev_quals)
	{
		bool		retval;

		retval = ExecQual(gss->dev_quals, econtext);
		if (!retval)
		{
			pg_atomic_add_fetch_u64(&gs_rtstat->c.nitems_filtered, 1);
			goto retry_next;
		}
	}

	/*
	 * (2) - Makes a projection if any
	 */
	if (!gss->base_proj)
		slot = gss->base_slot;
	else
		slot = ExecProject(gss->base_proj);

	return slot;
}

/*
 * gpuscan_next_tuple
 */
static TupleTableSlot *
gpuscan_next_tuple(GpuTaskState *gts)
{
	GpuScanState	   *gss = (GpuScanState *) gts;
	GpuScanTask		   *gscan = (GpuScanTask *) gts->curr_task;
	TupleTableSlot	   *slot = NULL;

	if (gscan->task.cpu_fallback)
		slot = gpuscan_next_tuple_fallback(gss, gscan);
	else if (gscan->pds_dst)
	{
		pgstrom_data_store *pds_dst = gscan->pds_dst;

		slot = gss->gts.css.ss.ss_ScanTupleSlot;
		ExecClearTuple(slot);
		if (!PDS_fetch_tuple(slot, pds_dst, &gss->gts))
			slot = NULL;
	}
	else
	{
		pgstrom_data_store *pds_src = gscan->pds_src;
		gpuscanResultIndex *gs_results
			= KERN_GPUSCAN_RESULT_INDEX(&gscan->kern);

		Assert(pds_src->kds.format == KDS_FORMAT_ROW);
		if (gss->gts.curr_index < gs_results->nitems)
		{
			HeapTuple	tuple = &gss->gts.curr_tuple;
			cl_uint		kds_offset;

			kds_offset = gs_results->results[gss->gts.curr_index++];
			tuple->t_data = KDS_ROW_REF_HTUP(&pds_src->kds,
											 kds_offset,
											 &tuple->t_self,
											 &tuple->t_len);
			slot = gss->gts.css.ss.ss_ScanTupleSlot;
			ExecForceStoreHeapTuple(tuple, slot, false);
		}
	}
	return slot;
}

/*
 * gpuscan_throw_partial_result
 */
static void
gpuscan_throw_partial_result(GpuScanTask *gscan, pgstrom_data_store *pds_dst)
{
	GpuContext	   *gcontext = GpuWorkerCurrentContext;
	GpuTaskState   *gts = gscan->task.gts;
	GpuScanTask	   *gresp;		/* responder task */
	size_t			length;
	CUdeviceptr		m_deviceptr;
	CUresult		rc;

	/* setup responder task with supplied @pds_dst */
	length = (STROMALIGN(offsetof(GpuScanTask, kern.kparams)) +
			  STROMALIGN(gscan->kern.kparams.length));
	rc = gpuMemAllocManaged(gcontext,
							&m_deviceptr,
							length,
							CU_MEM_ATTACH_GLOBAL);
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuMemAllocManaged: %s", errorText(rc));
	/* allocation of an empty result buffer */
	gresp = (GpuScanTask *) m_deviceptr;
	memset(gresp, 0, offsetof(GpuScanTask, kern.kparams));
	memcpy(&gresp->kern.kparams,
		   &gscan->kern.kparams,
		   gscan->kern.kparams.length);
	gresp->task.task_kind	= gscan->task.task_kind;
	gresp->task.program_id	= gscan->task.program_id;
	gresp->task.gts			= gts;
	gresp->pds_dst			= pds_dst;
	gresp->kern.nitems_in	= gscan->kern.nitems_in;
	gresp->kern.nitems_out	= gscan->kern.nitems_out;
	gresp->kern.extra_size	= gscan->kern.extra_size;

	/* Back GpuTask to GTS */
	pthreadMutexLock(&gcontext->worker_mutex);
	dlist_push_tail(&gts->ready_tasks,
					&gresp->task.chain);
	gts->num_ready_tasks++;
	pthreadMutexUnlock(&gcontext->worker_mutex);

	SetLatch(MyLatch);
}

/*
 * gpuscan_process_task
 */
static int
__gpuscan_process_task(GpuTask *gtask, CUmodule cuda_module)
{
	GpuContext	   *gcontext = GpuWorkerCurrentContext;
	GpuScanTask	   *gscan = (GpuScanTask *) gtask;
	pgstrom_data_store *pds_src = gscan->pds_src;
	pgstrom_data_store *pds_dst = gscan->pds_dst;
	CUfunction		kern_gpuscan_quals;
	CUdeviceptr		m_gpuscan = (CUdeviceptr)&gscan->kern;
	CUdeviceptr		m_kds_src = 0UL;
	CUdeviceptr		m_kds_extra = 0UL;
	CUdeviceptr		m_kds_dst = (pds_dst ? (CUdeviceptr)&pds_dst->kds : 0UL);
	bool			m_kds_src_release = false;
	const char	   *kern_fname;
	void		   *kern_args[5];
	void		   *last_suspend = NULL;
	size_t			offset;
	size_t			length;
	cl_int			grid_sz;
	cl_int			block_sz;
	size_t			nitems_in;
	size_t			nitems_out;
	CUresult		rc;
	int				retval = 100001;

	/*
	 * Lookup GPU kernel functions
	 */
	if (pds_src->kds.format == KDS_FORMAT_ROW)
		kern_fname = "kern_gpuscan_main_row";
	else if (pds_src->kds.format == KDS_FORMAT_BLOCK)
		kern_fname = "kern_gpuscan_main_block";
	else if (pds_src->kds.format == KDS_FORMAT_ARROW)
		kern_fname = "kern_gpuscan_main_arrow";
	else if (pds_src->kds.format == KDS_FORMAT_COLUMN)
		kern_fname = "kern_gpuscan_main_column";
	else
		werror("GpuScan: unknown PDS format: %d", pds_src->kds.format);

	rc = cuModuleGetFunction(&kern_gpuscan_quals,
							 cuda_module,
							 kern_fname);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuModuleGetFunction('%s'): %s",
			   kern_fname, errorText(rc));

	/*
	 * Allocation of device memory
	 *
	 * MEMO: NVMe-Strom requires the DMA destination address is mapped to
	 * PCI BAR area, but it is usually a small window thus easy to run out.
	 * So, if we cannot allocate i/o mapped device memory, we try to read
	 * the blocks synchronously then kicks usual RAM->GPU DMA.
	 */
	if (gscan->with_nvme_strom)
	{
		Assert(pds_src->kds.format == KDS_FORMAT_BLOCK ||
			   pds_src->kds.format == KDS_FORMAT_ARROW);
		rc = gpuMemAllocIOMap(gcontext,
							  &m_kds_src,
							  pds_src->kds.length);
		if (rc == CUDA_SUCCESS)
			m_kds_src_release = true;
		else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
		{
			gscan->with_nvme_strom = false;
			if (pds_src->kds.format == KDS_FORMAT_BLOCK)
			{
				PDS_fillup_blocks(pds_src);

				rc = gpuMemAlloc(gcontext,
								 &m_kds_src,
								 pds_src->kds.length);
				if (rc == CUDA_SUCCESS)
					m_kds_src_release = true;
				else if (rc == CUDA_ERROR_OUT_OF_MEMORY)
					goto out_of_resource;
				else
					werror("failed on gpuMemAlloc: %s", errorText(rc));
			}
			else
			{
				pds_src = PDS_fillup_arrow(gscan->pds_src);
				PDS_release(gscan->pds_src);
				gscan->pds_src = pds_src;
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
	 * OK, enqueue a series of requests
	 */
	length = KERN_GPUSCAN_DMASEND_LENGTH(&gscan->kern);
	rc = cuMemPrefetchAsync((CUdeviceptr)&gscan->kern,
							length,
							CU_DEVICE_PER_THREAD,
							CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemPrefetchAsync: %s", errorText(rc));

	/* kern_data_store *kds_src */
	if (gscan->with_nvme_strom)
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

	/* head of the kds_dst, if any */
	if (pds_dst)
	{
		length = KERN_DATA_STORE_HEAD_LENGTH(&pds_dst->kds);
		rc = cuMemPrefetchAsync((CUdeviceptr)&pds_dst->kds,
								length,
								CU_DEVICE_PER_THREAD,
								CU_STREAM_PER_THREAD);
		if (rc != CUDA_SUCCESS)
			werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
	}

	/*
	 * KERNEL_FUNCTION(void)
	 * gpuscan_exec_quals_XXXX(kern_gpuscan *kgpuscan,
	 *                         kern_data_store *kds_src,
	 *                         kern_data_store *kds_dst)
	 */
	rc = gpuOptimalBlockSize(&grid_sz,
							 &block_sz,
							 kern_gpuscan_quals,
							 CU_DEVICE_PER_THREAD,
							 0, sizeof(cl_int));
	if (rc != CUDA_SUCCESS)
		werror("failed on gpuOptimalBlockSize: %s", errorText(rc));
	gscan->kern.grid_sz = grid_sz;
	gscan->kern.block_sz = block_sz;
resume_kernel:
	gscan->kern.nitems_in = 0;
	gscan->kern.nitems_out = 0;
	gscan->kern.extra_size = 0;
	gscan->kern.suspend_count = 0;
	kern_args[0] = &m_gpuscan;
	kern_args[1] = &m_kds_src;
	kern_args[2] = &m_kds_extra;
	kern_args[3] = &m_kds_dst;

	rc = cuLaunchKernel(kern_gpuscan_quals,
						grid_sz, 1, 1,
						block_sz, 1, 1,
						sizeof(cl_int) * 1024,
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
	 * Check GPU kernel status and nitems/usage
	 */
	retval = 0;
	nitems_in  = gscan->kern.nitems_in;
	nitems_out = gscan->kern.nitems_out;

	memcpy(&gscan->task.kerror,
		   &((kern_gpuscan *)m_gpuscan)->kerror, sizeof(kern_errorbuf));
	if (gscan->task.kerror.errcode == ERRCODE_STROM_SUCCESS)
	{
		GpuScanState	   *gss = (GpuScanState *)gscan->task.gts;
		GpuScanRuntimeStat *gs_rtstat = gss->gs_rtstat;

		/* update stat */
		pg_atomic_add_fetch_u64(&gs_rtstat->c.source_nitems,
								nitems_in);
		pg_atomic_add_fetch_u64(&gs_rtstat->c.nitems_filtered,
								nitems_in - nitems_out);
		if (!pds_dst)
		{
			/* may not use this code path no longer */
			Assert(gscan->kern.extra_size == 0);

			rc = cuMemPrefetchAsync((CUdeviceptr)
									KERN_GPUSCAN_RESULT_INDEX(&gscan->kern),
									offsetof(gpuscanResultIndex,
											 results[nitems_out]),
									CU_DEVICE_CPU,
									CU_STREAM_PER_THREAD);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
		}
		else if (nitems_out > 0)
		{
			length = KERN_DATA_STORE_SLOT_LENGTH(&pds_dst->kds, nitems_out);
			rc = cuMemPrefetchAsync((CUdeviceptr)&pds_dst->kds,
									length,
									CU_DEVICE_CPU,
									CU_STREAM_PER_THREAD);
			if (rc != CUDA_SUCCESS)
				werror("failed on cuMemPrefetchAsync: %s", errorText(rc));

			if (pds_dst->kds.usage > 0)
			{
				length = __kds_unpack(pds_dst->kds.usage);
				offset = pds_dst->kds.length - length;
				rc = cuMemPrefetchAsync((CUdeviceptr)(&pds_dst->kds) + offset,
										length,
										CU_DEVICE_CPU,
										CU_STREAM_PER_THREAD);
				if (rc != CUDA_SUCCESS)
					werror("failed on cuMemPrefetchAsync: %s", errorText(rc));
			}
		}

		/* resume gpuscan kernel, if suspended */
		if (gscan->kern.suspend_count > 0)
		{
			void	   *temp;
			
			CHECK_WORKER_TERMINATION();
			/* return partial result */
			pds_dst = PDS_clone(gscan->pds_dst);
			gpuscan_throw_partial_result(gscan, gscan->pds_dst);
			/* reset error status, then resume kernel with new buffer */
			memset(&gscan->kern.kerror, 0, sizeof(kern_errorbuf));
			gscan->kern.resume_context = true;
			gscan->pds_dst = pds_dst;
			m_kds_dst = (CUdeviceptr)&pds_dst->kds;
			/*
			 * MEMO: current suspended context must be saved, because
			 * resumed kernel invocation may return CpuReCheck error.
			 * Once it moved to the fallback code, we have to skip rows
			 * already returned on the prior steps.
			 */
			Assert(gscan->kern.suspend_sz > 0);
			if (!last_suspend)
				last_suspend = alloca(gscan->kern.suspend_sz);
			temp = KERN_GPUSCAN_SUSPEND_CONTEXT(&gscan->kern, 0);
			memcpy(last_suspend, temp, gscan->kern.suspend_sz);
			goto resume_kernel;
		}
	}
	else
	{
		if (pgstrom_cpu_fallback_enabled &&
			(gscan->task.kerror.errcode & ERRCODE_FLAGS_CPU_FALLBACK) != 0)
		{
			/*
			 * In case of KDS_FORMAT_BLOCK, we have to write back the buffer
			 * to host-side, because its ItemIdData might be updated, and
			 * blocks might not be loaded yet if NVMe-Strom mode.
			 * Due to the same reason, KDS_FORMAT_ARROW with NVMe-Strom mode
			 * needs to write back the device buffer to host-side.
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
				gscan->pds_src = PDS_writeback_arrow(pds_src, m_kds_src);
			}
			memset(&gscan->task.kerror, 0, sizeof(kern_errorbuf));
			gscan->task.cpu_fallback = true;
			/* restore suspend context, if any */
			gscan->kern.resume_context = (last_suspend != NULL);
			if (last_suspend)
			{
				void   *temp = KERN_GPUSCAN_SUSPEND_CONTEXT(&gscan->kern, 0);

				memcpy(temp, last_suspend, gscan->kern.suspend_sz);
			}
		}
	}
out_of_resource:
	if (m_kds_src_release)
		gpuMemFree(gcontext, m_kds_src);
	return retval;
}

static int
gpuscan_process_task(GpuTask *gtask, CUmodule cuda_module)
{
	GpuScanTask	   *gscan = (GpuScanTask *) gtask;
	pgstrom_data_store *pds_src = gscan->pds_src;
	volatile bool	gstore_mapped = false;
	int				retval;
	CUresult		rc;

	/*
	 * NOTE (2020-09-11):
	 * The 'gstore_mapped' has 'volatile' qualifier.
	 * From the compiler point of view, it looks here is no code path
	 * that set gstore_mapped in the exception block, however, we may
	 * run the STROM_CATCH() block, if __gpuscan_process_task() raises
	 * an exception.
	 * Compiler optimization by GCC8.3.1 eliminated invocation of
	 * gstoreFdwUnmapDeviceMemory even if gstore_mapped is set.
	 * So, we explicitly disabled the optimization by the volatile.
	 */
	STROM_TRY();
	{
		if (pds_src->kds.format == KDS_FORMAT_COLUMN)
		{
			rc = gpuStoreMapDeviceMemory(GpuWorkerCurrentContext, pds_src);
			if (rc != CUDA_SUCCESS)
				werror("failed on gstoreFdwMapDeviceMemory: %s", errorText(rc));
			gstore_mapped = true;
		}
		retval = __gpuscan_process_task(gtask, cuda_module);
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
 * gpuscan_release_task
 */
static void
gpuscan_release_task(GpuTask *gtask)
{
	GpuScanTask	   *gscan = (GpuScanTask *) gtask;
	GpuTaskState   *gts = gscan->task.gts;

	if (gscan->pds_src)
		PDS_release(gscan->pds_src);
	if (gscan->pds_dst)
		PDS_release(gscan->pds_dst);
	gpuMemFree(gts->gcontext, (CUdeviceptr) gscan);
}

/*
 * pgstrom_init_gpuscan
 */
void
pgstrom_init_gpuscan(void)
{
	/* pg_strom.enable_gpuscan */
	DefineCustomBoolVariable("pg_strom.enable_gpuscan",
							 "Enables the use of GPU accelerated full-scan",
							 NULL,
							 &enable_gpuscan,
							 true,
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	/* pg_strom.pullup_outer_scan */
	DefineCustomBoolVariable("pg_strom.pullup_outer_scan",
							 "Enables to pull up simple outer scan",
							 NULL,
							 &enable_pullup_outer_scan,
							 true,
							 PGC_USERSET,
                             GUC_NOT_IN_SAMPLE,
                             NULL, NULL, NULL);

	/* setup path methods */
	memset(&gpuscan_path_methods, 0, sizeof(gpuscan_path_methods));
	gpuscan_path_methods.CustomName			= "GpuScan";
	gpuscan_path_methods.PlanCustomPath		= PlanGpuScanPath;

	/* setup plan methods */
	memset(&gpuscan_plan_methods, 0, sizeof(gpuscan_plan_methods));
	gpuscan_plan_methods.CustomName			= "GpuScan";
	gpuscan_plan_methods.CreateCustomScanState = gpuscan_create_scan_state;
	RegisterCustomScanMethods(&gpuscan_plan_methods);

	/* setup exec methods */
	memset(&gpuscan_exec_methods, 0, sizeof(gpuscan_exec_methods));
	gpuscan_exec_methods.CustomName         = "GpuScan";
	gpuscan_exec_methods.BeginCustomScan    = ExecInitGpuScan;
	gpuscan_exec_methods.ExecCustomScan     = ExecGpuScan;
	gpuscan_exec_methods.EndCustomScan      = ExecEndGpuScan;
	gpuscan_exec_methods.ReScanCustomScan   = ExecReScanGpuScan;
	gpuscan_exec_methods.EstimateDSMCustomScan = ExecGpuScanEstimateDSM;
	gpuscan_exec_methods.InitializeDSMCustomScan = ExecGpuScanInitDSM;
	gpuscan_exec_methods.InitializeWorkerCustomScan = ExecGpuScanInitWorker;
	gpuscan_exec_methods.ReInitializeDSMCustomScan = ExecGpuScanReInitializeDSM;
	gpuscan_exec_methods.ShutdownCustomScan	= ExecShutdownGpuScan;
	gpuscan_exec_methods.ExplainCustomScan  = ExplainGpuScan;

	/* hook registration */
	set_rel_pathlist_next = set_rel_pathlist_hook;
	set_rel_pathlist_hook = gpuscan_add_scan_path;
}
