/*
 * multirels.c
 *
 * Inner relations loader for GpuJoin
 * ----
 * Copyright 2011-2015 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 * Copyright 2014-2015 (C) The PG-Strom Development Team
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
#include "postgres.h"
#include "catalog/pg_type.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/planmain.h"
#include "utils/lsyscache.h"
#include "utils/pg_crc.h"
#include "utils/ruleutils.h"
#include "pg_strom.h"
#include "cuda_numeric.h"
#include "cuda_gpujoin.h"

/* static variables */
static CustomScanMethods	multirels_plan_methods;
static PGStromExecMethods	multirels_exec_methods;

/*
 * MultiRelsInfo - state object of CustomScan(MultiRels)
 */
typedef struct
{
	JoinType	join_type;		/* one of JOIN_* */
	int			depth;			/* depth of this inner relation */
	int			nbatches;		/* expected number of batches */
	Size		kmrels_length;	/* expected length of kern_multirels */
	double		kmrels_rate;	/* expected rate to kmrels_length */

	/* width of hash-slot if hash-join case */
	cl_uint		nslots;
    /*
     * NOTE: setrefs.c adjusts varnode reference on hash_keys because
     * of custom-scan interface contract. It shall be redirected to
     * INDEX_VAR reference, to reference pseudo-scan tlist.
     * MultiHash has idential pseudo-scan tlist with its outer scan-
     * path, it always reference correct attribute as long as tuple-
     * slot is stored on ecxt_scantuple of ExprContext.
     */
	List	   *hash_inner_keys;
} MultiRelsInfo;

/*
 * MultiRelsState - execution state object of CustomScan(MultiRels)
 */
typedef struct
{
	CustomScanState	css;
	GpuContext	   *gcontext;
	JoinType		join_type;
	int				depth;
	int				nbatches_plan;
	int				nbatches_exec;
	Size			kmrels_length;	/* length of kern_multirels */
	double			kmrels_rate;	/* rate of this chunk to kmrels_length */

	/*
	 * Current materialization state
	 */
	bool			outer_done;
	TupleTableSlot *outer_overflow;
	void		   *curr_chunk;

	/*
	 * For hash-join
	 */
	cl_uint			nslots;
	cl_uint			hgram_shift;
	cl_uint			hgram_curr;
	Size		   *hgram_size;
	List		   *hash_keys;
	List		   *hash_keylen;
	List		   *hash_keybyval;
	List		   *hash_keytype;
	Tuplestorestate *tupstore;	/* for JOIN_FULL or JOIN_LEFT */
} MultiRelsState;

/*
 * pgstrom_multirels
 *
 *
 */
typedef struct pgstrom_multirels
{
	Size			kmrels_length;	/* total length of the kern_multirels */
	Size			head_length;	/* length of the header portion */
	Size			usage_length;	/* length actually in use */
	Size			lomap_length;	/* length of left outer map */
	void		  **inner_chunks;	/* array of KDS or Hash chunks */
	cl_int		   *refcnt;			/* reference counter for each context */
	CUdeviceptr	   *m_kmrels;		/* GPU memory for each CUDA context */
	CUevent		   *ev_loaded;		/* Sync object for each CUDA context */
	CUdeviceptr		m_lomaps;		/* Managed GPU memory for LEFT JOIN */
	kern_multirels	kern;			/* header of in-kernel structure */
} pgstrom_multirels;

/*
 * form_multirels_info
 */
static void
form_multirels_info(CustomScan *cscan, MultiRelsInfo *mr_info)
{
	List	   *exprs = NIL;
	List	   *privs = NIL;
	long		kmrels_rate;

	privs = lappend(privs, makeInteger(mr_info->depth));
	privs = lappend(privs, makeInteger(mr_info->nbatches));
	privs = lappend(privs, makeInteger(mr_info->kmrels_length));
	kmrels_rate = (long)(mr_info->kmrels_rate * 1000000.0);
	privs = lappend(privs, makeInteger(kmrels_rate));
	privs = lappend(privs, makeInteger(mr_info->nslots));
	exprs = lappend(exprs, mr_info->hash_inner_keys);

	cscan->custom_private = privs;
	cscan->custom_exprs = exprs;
}

/*
 * deform_multirels_info
 */
static MultiRelsInfo *
deform_multirels_info(CustomScan *cscan)
{
	MultiRelsInfo  *mr_info = palloc0(sizeof(MultiRelsInfo));
	List	   *privs = cscan->custom_private;
	List	   *exprs = cscan->custom_exprs;
	int			pindex = 0;
	int			eindex = 0;
	long		kmrels_rate;

	mr_info->depth = intVal(list_nth(privs, pindex++));
	mr_info->nbatches = intVal(list_nth(privs, pindex++));
	mr_info->kmrels_length = intVal(list_nth(privs, pindex++));
	kmrels_rate = intVal(list_nth(privs, pindex++));
	mr_info->kmrels_rate = (double)kmrels_rate / 1000000.0;
	mr_info->nslots = intVal(list_nth(privs, pindex++));
	mr_info->hash_inner_keys = list_nth(exprs, eindex++);

	return mr_info;
}

/*
 * pgstrom_plan_is_multirels
 */
bool
pgstrom_plan_is_multirels(const Plan *plan)
{
	CustomScan *cscan = (CustomScan *) plan;

	if (IsA(cscan, CustomScan) &&
		cscan->methods == &multirels_plan_methods)
		return true;
	return false;
}

/*
 * pgstrom_planstate_is_multirels
 */
bool
pgstrom_planstate_is_multirels(const PlanState *planstate)
{
	CustomScanState	*css = (CustomScanState *) planstate;

	if (IsA(css, CustomScanState) &&
		css->methods == &multirels_exec_methods.c)
		return true;
	return false;
}

/*
 * pgstrom_create_multirels_plan
 *
 *
 */
CustomScan *
pgstrom_create_multirels_plan(PlannerInfo *root,
							  int depth,
							  Cost mrels_startup_cost,
							  Cost mrels_total_cost,
							  JoinType join_type,
							  Path *outer_path,
							  Size kmrels_length,
							  double kmrels_rate,
							  cl_uint nbatches,
							  cl_uint nslots,
							  List *hash_inner_keys)
{
	CustomScan	   *cscan;
	MultiRelsInfo	mr_info;
	Plan		   *outer_plan = create_plan_recurse(root, outer_path);

	cscan = makeNode(CustomScan);
	cscan->scan.plan.plan_rows = outer_plan->plan_rows;
	cscan->scan.plan.startup_cost = mrels_startup_cost;
	cscan->scan.plan.total_cost = mrels_total_cost;
	cscan->scan.plan.plan_width = outer_plan->plan_width;
	cscan->scan.plan.targetlist = outer_plan->targetlist;
	cscan->scan.plan.qual = NIL;
	cscan->scan.scanrelid = 0;
	cscan->flags = 0;
	cscan->custom_ps_tlist = copyObject(outer_plan->targetlist);
	cscan->custom_relids = NULL;
	cscan->methods = &multirels_plan_methods;
	outerPlan(cscan) = outer_plan;

	memset(&mr_info, 0, sizeof(MultiRelsInfo));
	mr_info.join_type = join_type;
	mr_info.depth = depth;
	mr_info.nbatches = nbatches;
	mr_info.kmrels_length = kmrels_length;
	mr_info.kmrels_rate = kmrels_rate;
	mr_info.nslots = nslots;
	mr_info.hash_inner_keys = hash_inner_keys;
	form_multirels_info(cscan, &mr_info);

	return cscan;
}


static Node *
multirels_create_scan_state(CustomScan *cscan)
{
	MultiRelsState *mrs = palloc0(sizeof(MultiRelsState));

	NodeSetTag(mrs, T_CustomScanState);
	mrs->css.flags = cscan->flags;
	mrs->css.methods = &multirels_exec_methods.c;
	mrs->gcontext = pgstrom_get_gpucontext();

	return (Node *) mrs;
}

static void
multirels_begin(CustomScanState *node, EState *estate, int eflags)
{
	MultiRelsState *mrs = (MultiRelsState *) node;
	CustomScan	   *cscan = (CustomScan *) node->ss.ps.plan;
	MultiRelsInfo  *mr_info = deform_multirels_info(cscan);
	List		   *hash_keys = NIL;
	List		   *hash_keylen = NIL;
	List		   *hash_keybyval = NIL;
	List		   *hash_keytype = NIL;
	ListCell	   *lc;

	/* check for unsupported flags */
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));
	/* ensure the plan is MultiHash */
	Assert(pgstrom_plan_is_multirels((Plan *) cscan));

	mrs->join_type = mr_info->join_type;
	mrs->depth = mr_info->depth;
	mrs->nbatches_plan = mr_info->nbatches;
	mrs->nbatches_exec = ((eflags & EXEC_FLAG_EXPLAIN_ONLY) != 0 ? -1 : 0);
	mrs->kmrels_length = mr_info->kmrels_length;
	mrs->kmrels_rate = mr_info->kmrels_rate;
	mrs->nslots = mr_info->nslots;
	if (mr_info->hash_inner_keys)
	{
		cl_uint		shift;

		shift = get_next_log2(mr_info->nbatches) + 4;
		Assert(shift < sizeof(cl_uint) * BITS_PER_BYTE);
		mrs->hgram_size = palloc0(sizeof(Size)    * (1U << shift));
		mrs->hgram_shift = sizeof(cl_uint) * BITS_PER_BYTE - shift;
	}
	mrs->outer_overflow = NULL;
	mrs->outer_done = false;
	mrs->curr_chunk = NULL;

	/*
	 * initialize the expression state of hash-keys, if any
	 */
	foreach (lc, mr_info->hash_inner_keys)
	{
		Oid			type_oid = exprType(lfirst(lc));
		int16		typlen;
		bool		typbyval;
		ExprState  *key_expr;

		get_typlenbyval(type_oid, &typlen, &typbyval);

		key_expr = ExecInitExpr(lfirst(lc), &mrs->css.ss.ps);
		hash_keys = lappend(hash_keys, key_expr);
		hash_keylen = lappend_int(hash_keylen, typlen);
		hash_keybyval = lappend_int(hash_keybyval, typbyval);
		hash_keytype = lappend_oid(hash_keytype, type_oid);
	}
	mrs->hash_keys = hash_keys;
	mrs->hash_keylen = hash_keylen;
	mrs->hash_keybyval = hash_keybyval;
	mrs->hash_keytype = hash_keytype;

	/*
     * initialize child nodes
     */
	outerPlanState(mrs) = ExecInitNode(outerPlan(cscan), estate, eflags);
	innerPlanState(mrs) = ExecInitNode(innerPlan(cscan), estate, eflags);
}

static TupleTableSlot *
multirels_exec(CustomScanState *node)
{
	elog(ERROR, "MultiRels does not support ExecProcNode call convention");
	return NULL;
}

static bool
multirels_expand_length(MultiRelsState *mrs, pgstrom_multirels *pmrels)
{
	MultiRelsState *temp = mrs;
	Size		new_length = 2 * pmrels->kmrels_length;

	/*
	 * No more physical space to expand, we will give up
	 */
	if (new_length > gpuMemMaxAllocSize())
		return false;

	/*
	 * Update expected total length of pgstrom_multirels
	 */
	while (temp)
	{
		Assert(pgstrom_planstate_is_multirels((PlanState *) temp));
		temp->kmrels_length = new_length;
		temp = (MultiRelsState *)innerPlanState(temp);
	}
	pmrels->kmrels_length = new_length;

	return true;
}

static kern_hashtable *
create_kern_hashtable(MultiRelsState *mrs, pgstrom_multirels *pmrels)
{
	GpuContext	   *gcontext = mrs->gcontext;
	TupleTableSlot *scan_slot = mrs->css.ss.ss_ScanTupleSlot;
    TupleDesc		scan_desc = scan_slot->tts_tupleDescriptor;
	int				natts = scan_desc->natts;
	kern_hashtable *khtable;
	Size			chunk_size;
	Size			required;
	cl_uint		   *hash_slots;
	int				attcacheoff;
	int				attalign;
	int				i;

	required = (LONGALIGN(offsetof(kern_hashtable,
								   colmeta[scan_desc->natts])) +
				LONGALIGN(sizeof(cl_uint) * mrs->nslots));
	do {
		chunk_size = (Size)(mrs->kmrels_rate *
							(double)(pmrels->kmrels_length -
									 pmrels->head_length));
		if (required < chunk_size)
			break;
		if (!multirels_expand_length(mrs, pmrels))
			elog(ERROR, "failed to assign minimum required memory");
	} while (true);
	khtable = MemoryContextAlloc(gcontext->memcxt, chunk_size);
	khtable->length = chunk_size;
	khtable->usage = required;
	khtable->ncols = natts;
	khtable->nitems = 0;
	khtable->nslots = mrs->nslots;
	khtable->hash_min = 0;
	khtable->hash_max = UINT_MAX;

	attcacheoff = offsetof(HeapTupleHeaderData, t_bits);
	if (scan_desc->tdhasoid)
		attcacheoff += sizeof(Oid);
	attcacheoff = MAXALIGN(attcacheoff);

	for (i=0; i < natts; i++)
	{
		Form_pg_attribute attr = scan_desc->attrs[i];

		attalign = typealign_get_width(attr->attalign);
		if (attcacheoff > 0)
		{
			if (attr->attlen > 0)
				attcacheoff = TYPEALIGN(attalign, attcacheoff);
			else
				attcacheoff = -1;	/* no more shortcut any more */
		}
		khtable->colmeta[i].attbyval = attr->attbyval;
		khtable->colmeta[i].attalign = attalign;
		khtable->colmeta[i].attlen = attr->attlen;
		khtable->colmeta[i].attnum = attr->attnum;
		khtable->colmeta[i].attcacheoff = attcacheoff;
		if (attcacheoff >= 0)
			attcacheoff += attr->attlen;
	}
	hash_slots = KERN_HASHTABLE_SLOT(khtable);
	memset(hash_slots, 0, sizeof(cl_uint) * khtable->nslots);

	return khtable;
}

static pg_crc32
get_tuple_hashvalue(MultiRelsState *mrs, TupleTableSlot *slot)
{
	ExprContext	   *econtext = mrs->css.ss.ps.ps_ExprContext;
	pg_crc32		hash;
	ListCell	   *lc1;
	ListCell	   *lc2;
	ListCell	   *lc3;
	ListCell	   *lc4;

	/* calculation of a hash value of this entry */
	econtext->ecxt_scantuple = slot;
	INIT_LEGACY_CRC32(hash);
	forfour (lc1, mrs->hash_keys,
			 lc2, mrs->hash_keylen,
			 lc3, mrs->hash_keybyval,
			 lc4, mrs->hash_keytype)
	{
		ExprState  *clause = lfirst(lc1);
		int			keylen = lfirst_int(lc2);
		bool		keybyval = lfirst_int(lc3);
		Oid			keytype = lfirst_oid(lc4);
		int			errcode;
		Datum		value;
		bool		isnull;

		value = ExecEvalExpr(clause, econtext, &isnull, NULL);
		if (isnull)
			continue;

		/* fixup host representation to special internal format. */
		if (keytype == NUMERICOID)
		{
			pg_numeric_t	temp;

			temp = pg_numeric_from_varlena(&errcode, (struct varlena *)
										   DatumGetPointer(value));
			keylen = sizeof(temp.value);
			keybyval = true;
			value = temp.value;
		}

		if (keylen > 0)
		{
			if (keybyval)
				COMP_LEGACY_CRC32(hash, &value, keylen);
			else
				COMP_LEGACY_CRC32(hash, DatumGetPointer(value), keylen);
		}
		else
		{
			COMP_LEGACY_CRC32(hash,
							  VARDATA_ANY(value),
							  VARSIZE_ANY_EXHDR(value));
		}
	}
	FIN_LEGACY_CRC32(hash);

	return hash;
}

static bool
multirels_preload_hash_partial(MultiRelsState *mrs, kern_hashtable *khtable)
{
	TupleTableSlot *tupslot = mrs->css.ss.ss_ScanTupleSlot;
	kern_hashentry *khentry;
	cl_uint			hash;
	cl_uint		   *hash_slots;
	cl_uint			i, limit;
	Size			required = 0;

	Assert(mrs->tupstore != NULL);

	/* reset khtable's usage */
	Assert(khtable->hostptr == (hostptr_t)&khtable->hostptr);
	khtable->usage = (LONGALIGN(offsetof(kern_hashtable,
										 colmeta[khtable->ncols])) +
					  LONGALIGN(sizeof(cl_uint) * mrs->nslots));
	khtable->nitems = 0;
	hash_slots = KERN_HASHTABLE_SLOT(khtable);
	memset(hash_slots, 0, sizeof(cl_uint) * khtable->nslots);

	/*
	 * find a suitable range of hash_min/hash_max
	 */
	limit = (1U << (sizeof(cl_uint) * BITS_PER_BYTE - mrs->hgram_shift));
	if (mrs->hgram_curr >= limit)
		return false;	/* no more records to read */
	khtable->hash_min = mrs->hgram_curr * (1U << mrs->hgram_shift);
	khtable->hash_max = UINT_MAX;
	for (i = mrs->hgram_curr; i < limit; i++)
	{
		if (khtable->usage + required + mrs->hgram_size[i] > khtable->length)
		{
			if (required == 0)
				elog(ERROR, "hash-key didn't distribute tuples enough");
			khtable->hash_max = i * (1U << mrs->hgram_shift) - 1;
			break;
		}
		required += mrs->hgram_size[i];
	}
	mrs->hgram_curr = i;

	if (required == 0)
		return false;	/* no more records to read */

	/*
	 * Load from the tuplestore
	 */
	while (tuplestore_gettupleslot(mrs->tupstore, true, false, tupslot))
	{
		/*
		 * calculation of hash value, then load it to kern_hashtable
		 * if its hash value is in-range.
		 */
		hash = get_tuple_hashvalue(mrs, tupslot);
		if (hash >= khtable->hash_min && hash <= khtable->hash_max)
		{
			HeapTuple	tuple = ExecFetchSlotTuple(tupslot);
			Size		entry_size;
			cl_int		index;

			entry_size = MAXALIGN(offsetof(kern_hashentry, htup) +
								  tuple->t_len);
			khentry = (kern_hashentry *)((char *)khtable + khtable->usage);
			khentry->hash = hash;
			khentry->rowid = khtable->nitems++;
			khentry->t_len = tuple->t_len;
			memcpy(&khentry->htup, tuple->t_data, tuple->t_len);

			index = hash % khtable->nslots;
			khentry->next = hash_slots[index];
			hash_slots[index] = khtable->usage;

			/* usage increment */
			khtable->usage += entry_size;
		}
	}
	Assert(khtable->usage <= khtable->length);

	return true;
}

static void
multirels_preload_hash(MultiRelsState *mrs,
					   pgstrom_multirels *pmrels,
					   double *p_ntuples)
{
	TupleTableSlot *scan_slot = mrs->css.ss.ss_ScanTupleSlot;
	kern_hashtable *khtable;
	kern_hashentry *khentry;
	HeapTuple		tuple;
	Size			entry_size;
	cl_uint		   *hash_slots;
	cl_uint			hash;
	int				index;

	khtable = create_kern_hashtable(mrs, pmrels);
	hash_slots = KERN_HASHTABLE_SLOT(khtable);

	while (!mrs->outer_done)
	{
		if (!mrs->outer_overflow)
			scan_slot = ExecProcNode(outerPlanState(mrs));
		else
		{
			scan_slot = mrs->outer_overflow;
			mrs->outer_overflow = NULL;
		}

		if (TupIsNull(scan_slot))
		{
			mrs->outer_done = true;
			break;
		}
		tuple = ExecFetchSlotTuple(scan_slot);
		hash = get_tuple_hashvalue(mrs, scan_slot);
		entry_size = MAXALIGN(offsetof(kern_hashentry, htup) + tuple->t_len);

		/*
		 * Once we switched to the Tuplestore instead of kern_hashtable,
		 * we try to materialize the inner relation once, then split it
		 * to the suitable scale.
		 */
		if (mrs->tupstore)
		{
			tuplestore_puttuple(mrs->tupstore, tuple);
			mrs->hgram_size[hash >> mrs->hgram_shift] += entry_size;
			continue;
		}

		/* do we have enough space to store? */
		if (khtable->usage + entry_size <= khtable->length)
		{
			khentry = (kern_hashentry *)((char *)khtable + khtable->usage);
			khentry->hash = hash;
			khentry->rowid = khtable->nitems ++;
			khentry->t_len = tuple->t_len;
			memcpy(&khentry->htup, tuple->t_data, tuple->t_len);

			index = hash % khtable->nslots;
			khentry->next = hash_slots[index];
			hash_slots[index] = (uintptr_t)khentry - (uintptr_t)khtable;

			/* usage increment */
			khtable->usage += entry_size;
			/* histgram update */
			mrs->hgram_size[hash >> mrs->hgram_shift] += entry_size;
		}
		else
		{
			Assert(mrs->outer_overflow == NULL);
			mrs->outer_overflow = scan_slot;

			if (multirels_expand_length(mrs, pmrels))
			{
				Size	chunk_size_new = (Size)
					(mrs->kmrels_rate *(double)(pmrels->kmrels_length -
												pmrels->head_length));
				khtable = repalloc(khtable, chunk_size_new);
				khtable->hostptr = (hostptr_t)&khtable->hostptr;
				khtable->length = chunk_size_new;
			}
			else if (mrs->join_type == JOIN_INNER ||
					 mrs->join_type == JOIN_RIGHT)
			{
				/*
				 * In case of inner-join, we don't need to materialize
				 * the underlying relation once, because join-logic don't
				 * care about range of hash-value.
				 */
				break;
			}
			else
			{
				/*
				 * If join logic is one of outer, and we cannot expand
				 * a single kern_hashtable chunk any more, we switch to
				 * use tuple-store to materialize the underlying relation
				 * once. Then, we split tuples according to the hash range.
				 */
				kern_hashentry *khentry;
				HeapTupleData	tupData;

				mrs->tupstore = tuplestore_begin_heap(false, false, work_mem);
				for (index = 0; index < khtable->nslots; index++)
				{
					for (khentry = KERN_HASH_FIRST_ENTRY(khtable, index);
						 khentry != NULL;
						 khentry = KERN_HASH_NEXT_ENTRY(khtable, khentry))
					{
						tupData.t_len = khentry->t_len;
						tupData.t_data = &khentry->htup;
						tuplestore_puttuple(mrs->tupstore, &tupData);
					}
				}
			}
		}
	}

	/*
	 * Try to preload the kern_hashtable if inner relation was too big
	 * to load into a single chunk, thus we materialized them on the
	 * tuple-store once.
	 */
	if (mrs->tupstore &&
		!multirels_preload_hash_partial(mrs, khtable))
	{
		Assert(mrs->outer_done);
		pfree(khtable);
		return;
	}

	/* release kern_hashtable, if no tuples were loaded */
	if (khtable && khtable->nitems == 0)
	{
		pfree(khtable);
		return;
	}

	/* OK, kern_hashtable was preloaded */
	mrs->curr_chunk = khtable;

	/* number of tuples read */
	*p_ntuples = (double) khtable->nitems;
}

static void
multirels_preload_heap(MultiRelsState *mrs,
					   pgstrom_multirels *pmrels,
					   double *p_ntuples)
{
	TupleTableSlot *scan_slot = mrs->css.ss.ss_ScanTupleSlot;
	TupleDesc		scan_desc = scan_slot->tts_tupleDescriptor;
	Size			chunk_size;
	pgstrom_data_store *pds;
	kern_data_store	   *kds;

	/*
	 * Make a pgstrom_data_store for materialization
	 */
	chunk_size = (Size)(mrs->kmrels_rate * (double)(pmrels->kmrels_length -
													pmrels->head_length));
	pds = pgstrom_create_data_store_row(mrs->gcontext,
										scan_desc, chunk_size, false);
	while (true)
	{
		if (!mrs->outer_overflow)
			scan_slot = ExecProcNode(outerPlanState(mrs));
		else
		{
			scan_slot = mrs->outer_overflow;
			mrs->outer_overflow = NULL;
		}

		if (TupIsNull(scan_slot))
		{
			mrs->outer_done = true;
			break;
		}

		if (!pgstrom_data_store_insert_tuple(pds, scan_slot))
		{
			/* to be inserted on the next try */
			Assert(mrs->outer_overflow == NULL);
			mrs->outer_overflow = scan_slot;

			/*
			 * We try to expand total length of pgstrom_multirels buffer,
			 * as long as it can be acquired on the device memory.
			 * If no more physical space is expected, we give up to preload
			 * entire relation on this store.
			 */
			if (!multirels_expand_length(mrs, pmrels))
				break;
			/*
			 * Once total length of the buffer got expanded, current store
			 * also can have wider space.
			 */
			chunk_size = (Size)(mrs->kmrels_rate *
								(double)(pmrels->kmrels_length -
										 pmrels->head_length));
			chunk_size = STROMALIGN_DOWN(chunk_size);
			pgstrom_expand_data_store(mrs->gcontext, pds, chunk_size);
		}
	}

	/* actually not loaded */
	if (pds->kds->nitems == 0)
	{
		pgstrom_release_data_store(pds);
		return;
	}

	/*
	 * NOTE: all we need here is kern_data_store, not pgstrom_data_store.
	 * So, we untrack PDS object and release it, but KDS shall be retained.
	 */
	kds = pds->kds;
	Assert(pds->pds_chain.prev && pds->pds_chain.next && !pds->kds_fname);
	dlist_delete(&pds->pds_chain);
	pfree(pds);

	mrs->curr_chunk = kds;

	/* number of tuples read */
	*p_ntuples = (double)kds->nitems;
}

static void *
multirels_exec_bulk(CustomScanState *node)
{
	MultiRelsState *mrs = (MultiRelsState *) node;
	GpuContext	   *gcontext = mrs->gcontext;
	pgstrom_multirels *pmrels;
	double			ntuples = 0.0;
	bool			scan_forward = false;

	Assert(pgstrom_planstate_is_multirels(&node->ss.ps));
	/* must provide our own instrumentation support */
	if (node->ss.ps.instrument)
		InstrStartNode(node->ss.ps.instrument);

	if (innerPlanState(mrs))
	{
		CustomScanState *inner_ps = (CustomScanState *)innerPlanState(mrs);

		pmrels = multirels_exec_bulk(inner_ps);
		if (!pmrels)
		{
			if (mrs->outer_done)
				goto out;
			ExecReScan(&mrs->css.ss.ps);
			pmrels = multirels_exec_bulk(inner_ps);
			if (!pmrels)
				goto out;
			scan_forward = true;
		}
		else if (!mrs->curr_chunk)
			scan_forward = true;
	}
	else
	{
		/* No deeper relations, so create a new pgstrom_multi_relations */
		int		nrels = mrs->depth;
		Size	head_length;
		Size	alloc_length;
		char   *pos;

		if (mrs->outer_done)
			goto out;
		scan_forward = true;

		/* allocation of pgstrom_multi_relations */
		head_length = STROMALIGN(offsetof(pgstrom_multirels,
										  kern.chunks[nrels]));
		alloc_length = head_length +
			STROMALIGN(sizeof(void *) * nrels) +
			STROMALIGN(sizeof(cl_int) * gcontext->num_context) +
			STROMALIGN(sizeof(CUdeviceptr) * gcontext->num_context) +
			STROMALIGN(sizeof(CUevent) * gcontext->num_context);

		pmrels = MemoryContextAllocZero(gcontext->memcxt, alloc_length);
		pmrels->kmrels_length = mrs->kmrels_length;
		pmrels->head_length = head_length;
		pmrels->usage_length = head_length;

		pos = (char *)pmrels + head_length;
		pmrels->inner_chunks = (void **) pos;
		pos += STROMALIGN(sizeof(void *) * nrels);
		pmrels->refcnt = (cl_int *) pos;
		pos += STROMALIGN(sizeof(cl_int) * gcontext->num_context);
		pmrels->m_kmrels = (CUdeviceptr *) pos;
		pos += STROMALIGN(sizeof(CUdeviceptr) * gcontext->num_context);
		pmrels->ev_loaded = (CUevent *) pos;

		memcpy(pmrels->kern.pg_crc32_table,
			   pg_crc32_table,
			   sizeof(cl_uint) * 256);
		pmrels->kern.nrels = nrels;
		memset(pmrels->kern.chunks,
			   0,
			   offsetof(pgstrom_multirels, kern.chunks[nrels]) -
			   offsetof(pgstrom_multirels, kern.chunks[0]));
	}
	Assert(pmrels != NULL);

	/*
	 * If needed, we make the outer scan advanced and load its contents
	 * to the data-store or hash-table. Elsewhere, presious chunk shall
	 * be used.
	 */
	if (scan_forward)
	{
		if (mrs->curr_chunk != NULL)
		{
			pfree(mrs->curr_chunk);
			mrs->curr_chunk = NULL;
		}
		if (mrs->hash_keys != NIL)
			multirels_preload_hash(mrs, pmrels, &ntuples);
		else
			multirels_preload_heap(mrs, pmrels, &ntuples);
	}

	if (!mrs->curr_chunk)
	{
		pfree(pmrels);
		pmrels = NULL;	/* end of scan */
	}
	else
	{
		Size	chunk_length = ((kern_data_store *)mrs->curr_chunk)->length;
		cl_uint	chunk_nitems = ((kern_data_store *)mrs->curr_chunk)->nitems;
		int		depth = mrs->depth;

		pmrels->inner_chunks[depth - 1] = mrs->curr_chunk;
		pmrels->kern.chunks[depth - 1].chunk_offset = pmrels->usage_length;

		if (mrs->join_type == JOIN_LEFT || mrs->join_type == JOIN_FULL)
		{
			pmrels->kern.chunks[depth - 1].left_outer = true;
			pmrels->kern.chunks[depth - 1].lomap_offset = pmrels->lomap_length;
			pmrels->lomap_length += STROMALIGN(sizeof(cl_bool) * chunk_nitems);
		}
		if (mrs->join_type == JOIN_RIGHT || mrs->join_type == JOIN_FULL)
			pmrels->kern.chunks[depth - 1].right_outer = true;
		/* make advance usage counter */
		pmrels->usage_length += chunk_length;
		Assert(pmrels->usage_length <= pmrels->kmrels_length);
	}
out:
	/* must provide our own instrumentation support */
	if (node->ss.ps.instrument)
		InstrStopNode(node->ss.ps.instrument, ntuples);

	if (pmrels)
		mrs->nbatches_exec++;

	return pmrels;
}

pgstrom_multirels *
pgstrom_multirels_exec_bulk(PlanState *plannode)
{
	return multirels_exec_bulk((CustomScanState *) plannode);
}

static void
multirels_end(CustomScanState *node)
{
	MultiRelsState *mrs = (MultiRelsState *) node;

	/*
	 * Release current chunk, if any
	 */
	if (mrs->curr_chunk)
	{
		// TODO: put kds or hash here
		mrs->curr_chunk = NULL;
	}

	/*
	 * Shutdown the subplans
	 */
	ExecEndNode(outerPlanState(node));
    ExecEndNode(innerPlanState(node));

	/* Release GpuContext */
	pgstrom_put_gpucontext(mrs->gcontext);
}

static void
multirels_rescan(CustomScanState *node)
{
	MultiRelsState *mrs = (MultiRelsState *) node;

	// release curr_chunk here

	if (innerPlanState(node))
		ExecReScan(innerPlanState(node));
	ExecReScan(outerPlanState(node));
	mrs->outer_done = false;
	mrs->outer_overflow = NULL;
}

static void
multirels_explain(CustomScanState *node, List *ancestors, ExplainState *es)
{
	MultiRelsState *mrs = (MultiRelsState *) node;
	CustomScan	   *cscan = (CustomScan *) node->ss.ps.plan;
	MultiRelsInfo  *mr_info = deform_multirels_info(cscan);
	List		   *context;
	char			buffer[256];

	/* set up deparsing context */
	context = set_deparse_context_planstate(es->deparse_cxt,
											(Node *) node,
											ancestors);
	/* shows hash keys, if any */
	if (mr_info->hash_inner_keys != NIL)
	{
		char   *expstr = deparse_expression((Node *) mr_info->hash_inner_keys,
											context,
											es->verbose,
											false);
		ExplainPropertyText("Hash keys", expstr, es);
		pfree(expstr);
	}

	/* shows other properties */
	if (es->format != EXPLAIN_FORMAT_TEXT)
	{
		if (mrs->nbatches_exec >= 0)
			ExplainPropertyInteger("nBatches", mrs->nbatches_exec, es);
		else
			ExplainPropertyInteger("nBatches", mrs->nbatches_plan, es);
		ExplainPropertyInteger("Buckets", mr_info->nslots, es);
		snprintf(buffer, sizeof(buffer),
				 "%.2f%%", 100.0 * mr_info->kmrels_rate);
		ExplainPropertyText("Memory Usage", buffer, es);
	}
	else
	{
		appendStringInfoSpaces(es->str, es->indent * 2);
		appendStringInfo(
			es->str,
			"nBatches: %u  Buckets: %u  Memory Usage: %.2f%%\n",
			mrs->nbatches_exec >= 0
			? mrs->nbatches_exec
			: mrs->nbatches_plan,
			mr_info->nslots,
			100.0 * mr_info->kmrels_rate);
	}
}

/*****/
bool
multirels_get_gpumem(pgstrom_multirels *pmrels, GpuTask *gtask,
					 CUdeviceptr *p_kmrels,		/* inner relations */
					 CUdeviceptr *p_lomaps)		/* left-outer map */
{
	cl_int		cuda_index = gtask->cuda_index;
	CUresult	rc;

	if (pmrels->refcnt[cuda_index] == 0)
	{
		CUdeviceptr	m_kmrels;
		CUdeviceptr	m_lomaps;

		/* buffer for the inner multi-relations */
		m_kmrels = gpuMemAlloc(gtask, pmrels->kmrels_length);
		if (!m_kmrels)
			return false;

		if (pmrels->lomap_length > 0 && !pmrels->m_lomaps)
		{
			rc = cuMemAllocManaged(&m_lomaps,
								   pmrels->lomap_length,
								   CU_MEM_ATTACH_HOST);
			if (rc != CUDA_SUCCESS)
			{
				if (rc == CUDA_ERROR_OUT_OF_MEMORY)
				{
					gpuMemFree(gtask, m_kmrels);
					return false;
				}
				elog(ERROR, "failed on cuMemAllocManaged: %s", errorText(rc));
			}
			/* zero clear in synchronous manner */
			rc = cuMemsetD8(pmrels->m_lomaps, 0, pmrels->lomap_length);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuMemsetD8: %s", errorText(rc));
		}
		Assert(!pmrels->m_kmrels[cuda_index]);
		Assert(!pmrels->ev_loaded[cuda_index]);
		Assert(!pmrels->m_lomaps);
		pmrels->m_kmrels[cuda_index] = m_kmrels;
		pmrels->m_lomaps = m_lomaps;
	}
	pmrels->refcnt[cuda_index]++;
	*p_kmrels = pmrels->m_kmrels[cuda_index];
	*p_lomaps = pmrels->m_lomaps;

	return true;
}

void
multirels_put_gpumem(pgstrom_multirels *pmrels, GpuTask *gtask)
{
	cl_int		cuda_index = gtask->cuda_index;
	CUresult	rc;

	Assert(pmrels->refcnt[cuda_index] > 0);
	if (--pmrels->refcnt[cuda_index] == 0)
	{
		/*
		 * OK, no concurrent tasks did not reference the inner-relations
		 * buffer any more, so release it and mark the pointer as NULL.
		 */
		Assert(pmrels->m_kmrels[cuda_index] != 0UL);
		gpuMemFree(gtask, pmrels->m_kmrels[cuda_index]);
		pmrels->m_kmrels[cuda_index] = 0UL;

		/*
		 * Also, event object if any
		 */
		if (pmrels->ev_loaded[cuda_index])
		{
			rc = cuEventDestroy(pmrels->ev_loaded[cuda_index]);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuEventDestroy: %s", errorText(rc));
			pmrels->ev_loaded[cuda_index] = NULL;
		}
	}
}

void
multirels_send_gpumem(pgstrom_multirels *pmrels, GpuTask *gtask)
{
	cl_int		cuda_index = gtask->cuda_index;
	CUstream	cuda_stream = gtask->cuda_stream;
	CUresult	rc;

	if (!pmrels->ev_loaded[cuda_index])
	{
		CUdeviceptr	m_kmrels = pmrels->m_kmrels[cuda_index];
		CUevent		ev_loaded;
		cl_int		i;

		rc = cuEventCreate(&ev_loaded, CU_EVENT_DEFAULT);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuEventCreate: %s", errorText(rc));

		/* DMA send to the kern_multirels buffer */
		rc = cuMemcpyHtoDAsync(m_kmrels, &pmrels->kern, pmrels->head_length,
							   cuda_stream);
		if (rc != CUDA_SUCCESS)
			elog(ERROR, "failed on cuMemcpyHtoDAsync: %s", errorText(rc));

		for (i=0; i < pmrels->kern.nrels; i++)
		{
			kern_data_store *kds = pmrels->inner_chunks[i];
			Size	offset = pmrels->kern.chunks[i].chunk_offset;

			rc = cuMemcpyHtoDAsync(m_kmrels + offset, kds, kds->length,
								   cuda_stream);
			if (rc != CUDA_SUCCESS)
				elog(ERROR, "failed on cuMemcpyHtoDAsync: %s", errorText(rc));
		}
		/* save the event */
		pmrels->ev_loaded[cuda_index] = ev_loaded;
	}
	/* DMA Send synchronization */
	rc = cuEventRecord(pmrels->ev_loaded[cuda_index], cuda_stream);
	if (rc != CUDA_SUCCESS)
		elog(ERROR, "failed on cuEventRecord: %s", errorText(rc));
}

void
multirels_free_lomaps(pgstrom_multirels *pmrels, GpuTask *gtask)
{
	CUresult	rc;

	if (pmrels->m_lomaps)
	{
#ifdef USE_ASSERT_CHECKING
		GpuContext *gcontext = gtask->gts->gcontext;
		int			i;

		for (i=0; i < gcontext->num_context; i++)
			Assert(pmrels->refcnt[i] == 0);
#endif
		rc = cuMemFree(pmrels->m_lomaps);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuMemFree: %s", errorText(rc));
		pmrels->m_lomaps = (CUdeviceptr)(-1UL);
	}
}

/*
 * pgstrom_init_multirels
 *
 * entrypoint of this custom-scan provider
 */
void
pgstrom_init_multirels(void)
{
	/* setup plan methods */
	multirels_plan_methods.CustomName			= "MultiRels";
	multirels_plan_methods.CreateCustomScanState
		= multirels_create_scan_state;
	multirels_plan_methods.TextOutCustomScan	= NULL;

	/* setup exec methods */
	multirels_exec_methods.c.CustomName			= "MultiRels";
	multirels_exec_methods.c.BeginCustomScan	= multirels_begin;
	multirels_exec_methods.c.ExecCustomScan		= multirels_exec;
	multirels_exec_methods.c.EndCustomScan		= multirels_end;
	multirels_exec_methods.c.ReScanCustomScan	= multirels_rescan;
	multirels_exec_methods.c.MarkPosCustomScan	= NULL;
	multirels_exec_methods.c.RestrPosCustomScan	= NULL;
	multirels_exec_methods.c.ExplainCustomScan	= multirels_explain;
	multirels_exec_methods.ExecCustomBulk		= multirels_exec_bulk;
}
