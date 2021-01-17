/*
 * gpu_mmgr.c
 *
 * Routines to manage GPU device memory
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

#define GPUMEM_CHUNKSZ_MAX_BIT		30		/* 1GB */
#define GPUMEM_CHUNKSZ_MIN_BIT		14		/* 16KB */
#define GPUMEM_CHUNKSZ_MAX			(1UL << GPUMEM_CHUNKSZ_MAX_BIT)
#define GPUMEM_CHUNKSZ_MIN			(1UL << GPUMEM_CHUNKSZ_MIN_BIT)

typedef enum
{
	GpuMemKind__NormalMemory	= (1 << 0),
	GpuMemKind__ManagedMemory	= (1 << 1),
	GpuMemKind__IOMapMemory		= (1 << 2),
	GpuMemKind__HostMemory		= (1 << 3),
} GpuMemKind;

typedef struct
{
	dlist_node		chain;
	cl_int			mclass;
	cl_int			refcnt;
} GpuMemChunk;

#define GPUMEMCHUNK_IS_FREE(chunk)					\
	((chunk)->chain.prev != NULL &&					\
	 (chunk)->chain.next != NULL &&					\
	 (chunk)->mclass >= GPUMEM_CHUNKSZ_MIN_BIT &&	\
	 (chunk)->mclass <= GPUMEM_CHUNKSZ_MAX_BIT &&	\
	 (chunk)->refcnt == 0)
#define GPUMEMCHUNK_IS_ACTIVE(chunk)				 \
	((chunk)->chain.prev == NULL &&					 \
	 (chunk)->chain.next == NULL &&					 \
	 (chunk)->mclass >= GPUMEM_CHUNKSZ_MIN_BIT &&	 \
	 (chunk)->mclass <= GPUMEM_CHUNKSZ_MAX_BIT &&	 \
	 (chunk)->refcnt > 0)

typedef struct
{
	dlist_node		chain;
	cl_int			cuda_dindex;
	GpuMemKind		gm_kind;	/* one of GpuMemKind__* */
	CUdeviceptr		m_segment;	/* device pointer of the segment */
	unsigned long	iomap_handle; /* only if GpuMemKind__IOMapMemory */
	slock_t			lock;		/* protection of chunks */
	pg_atomic_uint32 num_active_chunks; /* # of active chunks */
	dlist_head		free_chunks[GPUMEM_CHUNKSZ_MAX_BIT + 1];
	GpuMemChunk		gm_chunks[FLEXIBLE_ARRAY_MEMBER];
} GpuMemSegment;

/* statistics of GPU memory usage (shared; per device) */
//to be used for memory release request mechanism
typedef struct
{
	size_t				total_size;
	pg_atomic_uint64	normal_usage;
	pg_atomic_uint64	managed_usage;
	pg_atomic_uint64	iomap_usage;
} GpuMemStatistics;

/*
 * GpuMemPreserved
 */
typedef struct
{
	CUipcMemHandle	m_handle;
	cl_int			cuda_dindex;
	size_t			bytesize;
   	CUdeviceptr		m_devptr;	/* valid only keeper */
	Oid				owner;		/* owner of the preserved memory */
	TimestampTz		ctime;		/* time of creation */
} GpuMemPreserved;

/*
 * GpuMemPreservedRequest
 */
typedef struct
{
	dlist_node		chain;
	Latch		   *backend;
	Oid				owner;
	CUresult		result;
	CUipcMemHandle	m_handle;
	cl_int			cuda_dindex;
	ssize_t			bytesize;
} GpuMemPreservedRequest;

/*
 * GpuMemPreservedHead
 */
typedef struct
{
	GpuMemPreservedRequest __gmemp_req_items[120];
	slock_t			lock;
	dlist_head		gmemp_req_free_list;
	struct {
		Latch	   *gmemp_req_latch;
		dlist_head	gmemp_req_pending;
	} bgworkers[FLEXIBLE_ARRAY_MEMBER];
} GpuMemPreservedHead;

/* functions */
extern void gpummgrBgWorkerMain(Datum arg);

/* static variables */
static shmem_startup_hook_type shmem_startup_next = NULL;
static GpuMemStatistics *gm_stat_array = NULL;
static int			gpu_memory_segment_size_kb;	/* GUC */
static size_t		gm_segment_sz;	/* bytesize */

static bool			gpummgr_bgworker_got_signal = false;
static GpuMemPreservedHead *gmemp_head = NULL;
static HTAB		   *gmemp_htab = NULL;	/* for GpuMemPreserved */

/*
 * gpuMemFreeChunk
 */
static CUresult
gpuMemFreeChunk(GpuContext *gcontext,
				CUdeviceptr m_deviceptr,
				GpuMemSegment *gm_seg)
{
	GpuMemChunk	   *gm_chunk;
	GpuMemChunk	   *gm_buddy;
	cl_long			unitsz = GPUMEM_CHUNKSZ_MIN;
	cl_long			nchunks = gm_segment_sz / unitsz;
	cl_long			index;
	cl_long			shift;

	Assert(m_deviceptr >= gm_seg->m_segment &&
		   m_deviceptr <  gm_seg->m_segment + gm_segment_sz);
	index = (m_deviceptr - gm_seg->m_segment) / unitsz;
	Assert(index >= 0 && index < nchunks);
	gm_chunk = &gm_seg->gm_chunks[index];
	Assert(GPUMEMCHUNK_IS_ACTIVE(gm_chunk));
	SpinLockAcquire(&gm_seg->lock);
	if (--gm_chunk->refcnt > 0)
	{
		SpinLockRelease(&gm_seg->lock);
		return CUDA_SUCCESS;
	}

	/* merge with prev/next free chunks if any */
	while (gm_chunk->mclass < GPUMEM_CHUNKSZ_MAX_BIT)
	{
		index = (gm_chunk - gm_seg->gm_chunks);
		shift = 1 << (gm_chunk->mclass - GPUMEM_CHUNKSZ_MIN_BIT);
		Assert((index & (shift - 1)) == 0);
		if ((index & shift) == 0)
		{
			/* try to merge with next */
			if (index + shift >= nchunks)
				break;	/* out of range, give up */

			gm_buddy = &gm_seg->gm_chunks[index + shift];
			if (GPUMEMCHUNK_IS_FREE(gm_buddy) &&
				gm_chunk->mclass == gm_buddy->mclass)
			{
				/* ok, let's merge */
				dlist_delete(&gm_buddy->chain);
				memset(gm_buddy, 0, sizeof(GpuMemChunk));
				gm_chunk->mclass++;
			}
			else
				break;	/* give up */
		}
		else
		{
			/* try to merge with prev */
			if (index < shift)
				break;	/* out of range, give up */
			gm_buddy = &gm_seg->gm_chunks[index - shift];
			if (GPUMEMCHUNK_IS_FREE(gm_buddy) &&
				gm_chunk->mclass == gm_buddy->mclass)
			{
				/* ok, let's merge */
				dlist_delete(&gm_buddy->chain);
				memset(gm_chunk, 0, sizeof(GpuMemChunk));
				gm_buddy->mclass++;
				gm_chunk = gm_buddy;
			}
			else
				break;	/* give up */
		}
	}
	/* back to the free list again */
	dlist_push_head(&gm_seg->free_chunks[gm_chunk->mclass],
					&gm_chunk->chain);
	pg_atomic_fetch_sub_u32(&gm_seg->num_active_chunks, 1);
	SpinLockRelease(&gm_seg->lock);

    return CUDA_SUCCESS;
}

/*
 * gpuMemFreeExtra
 */
static inline CUresult
gpuMemFreeExtra(GpuContext *gcontext,
				CUdeviceptr m_deviceptr,
				void *extra)
{
	CUresult	rc;

	if (!extra)
		return CUDA_ERROR_INVALID_VALUE;
	GPUCONTEXT_PUSH(gcontext);
	if (extra == GPUMEM_DEVICE_RAW_EXTRA)
		rc = cuMemFree(m_deviceptr);
	else if (extra == GPUMEM_HOST_RAW_EXTRA)
		rc = cuMemFreeHost((void *)m_deviceptr);
	else
		rc = gpuMemFreeChunk(gcontext, m_deviceptr, (GpuMemSegment *)extra);
	GPUCONTEXT_POP(gcontext);

	return rc;
}

/*
 * gpuMemFree
 */
CUresult
gpuMemFree(GpuContext *gcontext,
		   CUdeviceptr m_deviceptr)
{
	return gpuMemFreeExtra(gcontext,
						   m_deviceptr,
						   untrackGpuMem(gcontext, m_deviceptr));
}

/*
 * gpuMemFreeHost
 */
CUresult
gpuMemFreeHost(GpuContext *gcontext,
			   void *hostptr)
{
	return gpuMemFreeExtra(gcontext,
						   (CUdeviceptr)hostptr,
						   untrackGpuMem(gcontext, (CUdeviceptr)hostptr));
}

/*
 * gpuMemAllocRaw
 */
CUresult
__gpuMemAllocRaw(GpuContext *gcontext,
				 CUdeviceptr *p_devptr,
				 size_t bytesize,
				 const char *filename, int lineno)
{
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	GPUCONTEXT_PUSH(gcontext);
	rc = cuMemAlloc(&m_deviceptr, bytesize);
	if (rc != CUDA_SUCCESS)
		wnotice("failed on cuMemAlloc(%zu): %s", bytesize, errorText(rc));
	else if (!trackGpuMem(gcontext, m_deviceptr,
						  GPUMEM_DEVICE_RAW_EXTRA,
						  filename, lineno))
	{
		cuMemFree(m_deviceptr);
		rc = CUDA_ERROR_OUT_OF_MEMORY;
	}
	else
	{
		*p_devptr = m_deviceptr;
	}
	GPUCONTEXT_POP(gcontext);
	return rc;
}

/*
 * __gpuMemAllocManagedRaw
 */
CUresult
__gpuMemAllocManagedRaw(GpuContext *gcontext,
						CUdeviceptr *p_deviceptr,
						size_t bytesize,
						int flags,
						const char *filename, int lineno)
{
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	GPUCONTEXT_PUSH(gcontext);
	rc = cuMemAllocManaged(&m_deviceptr, bytesize, flags);
	if (rc != CUDA_SUCCESS)
		wnotice("failed on cuMemAllocManaged(%zu): %s",
				bytesize, errorText(rc));
	else if (!trackGpuMem(gcontext, m_deviceptr,
						  GPUMEM_DEVICE_RAW_EXTRA,
						  filename, lineno))
	{
		cuMemFree(m_deviceptr);
		rc = CUDA_ERROR_OUT_OF_MEMORY;
	}
	else
	{
		*p_deviceptr = m_deviceptr;
	}
	GPUCONTEXT_POP(gcontext);

	return rc;
}

/*
 * __gpuMemAllocHostRaw
 */
CUresult
__gpuMemAllocHostRaw(GpuContext *gcontext,
					 void **p_hostptr,
					 size_t bytesize,
					 const char *filename, int lineno)
{
	void	   *hostptr;
	CUresult	rc;

	GPUCONTEXT_PUSH(gcontext);
	rc = cuMemAllocHost(&hostptr, bytesize);
	if (rc != CUDA_SUCCESS)
		wnotice("failed on cuMemAllocHost(%zu): %s", bytesize, errorText(rc));
	else if (!trackGpuMem(gcontext, (CUdeviceptr)hostptr,
						  GPUMEM_HOST_RAW_EXTRA,
						  filename, lineno))
	{
		cuMemFreeHost(hostptr);
		rc = CUDA_ERROR_OUT_OF_MEMORY;
	}
	else
	{
		*p_hostptr = hostptr;
	}
	GPUCONTEXT_POP(gcontext);

	return rc;
}

/*
 * __gpuMemAllocDev - normal device memory allocation for exports
 */
CUresult
__gpuMemAllocDev(GpuContext *gcontext,
				 CUdeviceptr *p_deviceptr,
				 size_t bytesize,
				 CUipcMemHandle *p_mhandle,
				 const char *filename, int lineno)
{
	CUdeviceptr	m_deviceptr;
	CUresult	rc;

	GPUCONTEXT_PUSH(gcontext);
	rc = cuMemAlloc(&m_deviceptr, bytesize);
	if (rc != CUDA_SUCCESS)
		wnotice("failed on cuMemAlloc(%zu): %s", bytesize, errorText(rc));
	else
	{
		if (p_mhandle)
		{
			rc = cuIpcGetMemHandle(p_mhandle, m_deviceptr);
			if (rc != CUDA_SUCCESS)
			{
				wnotice("failed on cuIpcGetMemHandle: %s", errorText(rc));
				cuMemFree(m_deviceptr);
			}
		}
		if (rc == CUDA_SUCCESS)
		{
			if (!trackGpuMem(gcontext, m_deviceptr,
							 GPUMEM_DEVICE_RAW_EXTRA,
							 filename, lineno))
			{
				cuMemFree(m_deviceptr);
				rc = CUDA_ERROR_OUT_OF_MEMORY;
			}
			else
			{
				*p_deviceptr = m_deviceptr;
			}
		}
	}
	GPUCONTEXT_POP(gcontext);

	return rc;
}

/*
 * gpuMemSplitChunk
 */
static bool
gpuMemSplitChunk(GpuMemSegment *gm_seg, cl_int mclass)
{
	GpuMemChunk	   *gm_chunk1;
	GpuMemChunk	   *gm_chunk2;
	dlist_node	   *dnode;
	long			offset;

	if (mclass > GPUMEM_CHUNKSZ_MAX_BIT)
		return false;
	Assert(mclass > GPUMEM_CHUNKSZ_MIN_BIT);
	if (dlist_is_empty(&gm_seg->free_chunks[mclass]))
	{
		if (!gpuMemSplitChunk(gm_seg, mclass + 1))
			return false;
	}
	Assert(!dlist_is_empty(&gm_seg->free_chunks[mclass]));
	dnode = dlist_pop_head_node(&gm_seg->free_chunks[mclass]);
	offset = 1UL << (mclass - 1 - GPUMEM_CHUNKSZ_MIN_BIT);
	gm_chunk1 = dlist_container(GpuMemChunk, chain, dnode);
	gm_chunk2 = gm_chunk1 + offset;
	Assert(GPUMEMCHUNK_IS_FREE(gm_chunk1));
	Assert(gm_chunk2->mclass == 0);
	Assert(gm_chunk1->refcnt == 0 && gm_chunk2->refcnt == 0);
	gm_chunk1->mclass = mclass - 1;
	gm_chunk2->mclass = mclass - 1;

	dlist_push_tail(&gm_seg->free_chunks[mclass - 1],
					&gm_chunk1->chain);
	dlist_push_tail(&gm_seg->free_chunks[mclass - 1],
					&gm_chunk2->chain);
	return true;
}

/*
 * gpuMemAllocChunk
 */
static CUresult
gpuMemAllocChunk(GpuMemKind gm_kind,
				 GpuContext *gcontext,
				 CUdeviceptr *p_deviceptr,
				 cl_int mclass,
				 const char *filename, int lineno)
{
	GpuMemStatistics *gm_stat;
	GpuMemSegment  *gm_seg;
	GpuMemChunk	   *gm_chunk;
	CUdeviceptr		m_deviceptr;
	CUdeviceptr		m_segment;
	dlist_iter		iter;
	dlist_node	   *dnode;
	dlist_head	   *gm_segment_list;
	CUresult		rc;
	size_t			unitsz = GPUMEM_CHUNKSZ_MIN;
	cl_int			nchunks = gm_segment_sz / unitsz;
	cl_int			i, __mclass;
	size_t			segment_usage;
	bool			has_exclusive_lock = false;

	switch (gm_kind)
	{
		case GpuMemKind__NormalMemory:
			gm_segment_list = &gcontext->gm_normal_list;
			break;
		case GpuMemKind__IOMapMemory:
			gm_segment_list = &gcontext->gm_iomap_list;
			break;
		case GpuMemKind__ManagedMemory:
			gm_segment_list = &gcontext->gm_managed_list;
			break;
		case GpuMemKind__HostMemory:
			gm_segment_list = &gcontext->gm_hostmem_list;
			break;
		default:
			return CUDA_ERROR_INVALID_VALUE;
	}

	/*
	 * Try to lookup already allocated segment first
	 */
	pthreadRWLockReadLock(&gcontext->gm_rwlock);
retry:
	dlist_foreach(iter, gm_segment_list)
	{
		gm_seg = dlist_container(GpuMemSegment, chain, iter.cur);
		Assert(gm_seg->gm_kind == gm_kind);
		SpinLockAcquire(&gm_seg->lock);
		/* try to split larger chunks if any */
		if (dlist_is_empty(&gm_seg->free_chunks[mclass]))
			gpuMemSplitChunk(gm_seg, mclass + 1);

		if (!dlist_is_empty(&gm_seg->free_chunks[mclass]))
		{
			dnode = dlist_pop_head_node(&gm_seg->free_chunks[mclass]);
			gm_chunk = dlist_container(GpuMemChunk, chain, dnode);
			Assert(GPUMEMCHUNK_IS_FREE(gm_chunk) &&
				   gm_chunk->mclass == mclass);
			memset(&gm_chunk->chain, 0, sizeof(dlist_node));
			gm_chunk->refcnt++;
			pg_atomic_fetch_add_u32(&gm_seg->num_active_chunks, 1);
			SpinLockRelease(&gm_seg->lock);
			pthreadRWLockUnlock(&gcontext->gm_rwlock);
			/* ok, found */
			Assert(gm_chunk >= gm_seg->gm_chunks &&
				   (gm_chunk - gm_seg->gm_chunks) < nchunks);
			i = gm_chunk - gm_seg->gm_chunks;
			m_deviceptr = gm_seg->m_segment + i * unitsz;
			if (!trackGpuMem(gcontext, m_deviceptr, gm_seg,
							 filename, lineno))
			{
				gpuMemFreeChunk(gcontext, m_deviceptr, gm_seg);
				return CUDA_ERROR_OUT_OF_MEMORY;
			}
			*p_deviceptr = gm_seg->m_segment + i * unitsz;
			return CUDA_SUCCESS;
		}
		SpinLockRelease(&gm_seg->lock);
	}

	if (!has_exclusive_lock)
	{
		pthreadRWLockUnlock(&gcontext->gm_rwlock);
		has_exclusive_lock = true;
		pthreadRWLockWriteLock(&gcontext->gm_rwlock);
		goto retry;
	}

	/*
	 * allocation of a new segment
	 */
	gm_seg = calloc(1, offsetof(GpuMemSegment, gm_chunks[nchunks]));
	if (!gm_seg)
	{
		pthreadRWLockUnlock(&gcontext->gm_rwlock);
		return CUDA_ERROR_OUT_OF_MEMORY;
	}

	rc = cuCtxPushCurrent(gcontext->cuda_context);
	if (rc != CUDA_SUCCESS)
	{
		free(gm_seg);
		pthreadRWLockUnlock(&gcontext->gm_rwlock);
		wnotice("failed on cuCtxPushCurrent: %s", errorText(rc));
		return rc;
	}

	switch (gm_kind)
	{
		case GpuMemKind__NormalMemory:
			rc = cuMemAlloc(&m_segment, gm_segment_sz);
			//wnotice("normal m_segment = %p - %p by %s:%d", (void *)m_segment, (void *)(m_segment - gm_segment_sz), filename, lineno);
			break;

		case GpuMemKind__ManagedMemory:
			rc = cuMemAllocManaged(&m_segment, gm_segment_sz,
								   CU_MEM_ATTACH_GLOBAL);
			//wnotice("managed m_segment = %p - %p", (void *)m_segment, (void *)(m_segment + gm_segment_sz));
			break;

		case GpuMemKind__IOMapMemory:
			rc = cuMemAlloc(&m_segment, gm_segment_sz);
			if (rc == CUDA_SUCCESS)
			{
				rc = gpuDirectMapGpuMemory(m_segment,
										   gm_segment_sz,
										   &gm_seg->iomap_handle);
				if (rc != CUDA_SUCCESS)
				{
					wnotice("failed on gpuDirectMapGpuMemory: %s", errorText(rc));
					cuMemFree(m_segment);
				}
			}
			//wnotice("iomap m_segment = %p - %p", (void *)m_segment, (void *)(m_segment - gm_segment_sz));
			break;

		case GpuMemKind__HostMemory:
			rc = cuMemHostAlloc((void **)&m_segment, gm_segment_sz,
								CU_MEMHOSTALLOC_PORTABLE);
			//wnotice("hostmem m_segment = %p - %p", (void *)m_segment, (void *)(m_segment - gm_segment_sz));
			break;

		default:
			rc = CUDA_ERROR_INVALID_VALUE;
			break;
	}
	cuCtxPopCurrent(NULL);

	if (rc != CUDA_SUCCESS)
	{
		free(gm_seg);
		pthreadRWLockUnlock(&gcontext->gm_rwlock);
		return rc;
	}
	/* setup of GpuMemSegment */
	gm_seg->cuda_dindex = gcontext->cuda_dindex;
	gm_seg->gm_kind		= gm_kind;
	gm_seg->m_segment	= m_segment;
	SpinLockInit(&gm_seg->lock);
	pg_atomic_init_u32(&gm_seg->num_active_chunks, 0);
	for (i=0; i <= GPUMEM_CHUNKSZ_MAX_BIT; i++)
		dlist_init(&gm_seg->free_chunks[i]);

	__mclass = GPUMEM_CHUNKSZ_MAX_BIT;
	segment_usage = 0;
	while (segment_usage < gm_segment_sz &&
		   __mclass >= GPUMEM_CHUNKSZ_MIN_BIT)
	{
		if (segment_usage + (1UL << __mclass) > gm_segment_sz)
			__mclass--;
		else
		{
			i = (segment_usage >> GPUMEM_CHUNKSZ_MIN_BIT);
			Assert(i < nchunks);
			gm_chunk = &gm_seg->gm_chunks[i];
			gm_chunk->mclass = __mclass;
			dlist_push_tail(&gm_seg->free_chunks[__mclass],
							&gm_chunk->chain);
			segment_usage += (1UL << __mclass);
		}
	}
	Assert(segment_usage == gm_segment_sz);
	dlist_push_head(gm_segment_list, &gm_seg->chain);

	/* update statistics */
	gm_stat = &gm_stat_array[gcontext->cuda_dindex];
	switch (gm_kind)
	{
		case GpuMemKind__NormalMemory:
			pg_atomic_add_fetch_u64(&gm_stat->normal_usage, gm_segment_sz);
			break;
		case GpuMemKind__ManagedMemory:
			pg_atomic_add_fetch_u64(&gm_stat->managed_usage, gm_segment_sz);
			break;
		case GpuMemKind__IOMapMemory:
			pg_atomic_add_fetch_u64(&gm_stat->iomap_usage, gm_segment_sz);
			break;
		default:
			break;
	}
	goto retry;
}

/*
 * gpuMemAlloc
 */
CUresult
__gpuMemAlloc(GpuContext *gcontext,
			  CUdeviceptr *p_deviceptr,
			  size_t bytesize,
			  const char *filename, int lineno)
{
	if (bytesize <= gm_segment_sz / 2)
	{
		cl_int	mclass = Max(get_next_log2(bytesize),
							 GPUMEM_CHUNKSZ_MIN_BIT);

		return gpuMemAllocChunk(GpuMemKind__NormalMemory,
								gcontext, p_deviceptr, mclass,
								filename, lineno);
	}
	return __gpuMemAllocRaw(gcontext,
							p_deviceptr,
							bytesize,
							filename, lineno);
}

/*
 * gpuMemAllocIOMap
 */
CUresult
__gpuMemAllocIOMap(GpuContext *gcontext,
				   CUdeviceptr *p_deviceptr,
				   size_t bytesize,
				   const char *filename, int lineno)
{
	if (bytesize <= gm_segment_sz / 2)
	{
		cl_int	mclass = Max(get_next_log2(bytesize),
							 GPUMEM_CHUNKSZ_MIN_BIT);

		return gpuMemAllocChunk(GpuMemKind__IOMapMemory,
								gcontext, p_deviceptr, mclass,
								filename, lineno);
	}
	/*
	 * 'iomap_handle' returned from nvme_strom driver must be kept in
	 * GpuMemSegment, so we don't provide _Raw interface here.
	 */
	return CUDA_ERROR_INVALID_VALUE;
}

size_t
gpuMemAllocIOMapMaxLength(void)
{
	return gm_segment_sz / 2;
}

/*
 * __gpuMemAllocManaged
 */
CUresult
__gpuMemAllocManaged(GpuContext *gcontext,
					 CUdeviceptr *p_deviceptr,
					 size_t bytesize,
					 int flags,
					 const char *filename, int lineno)
{
	if (flags == CU_MEM_ATTACH_GLOBAL &&
		bytesize <= gm_segment_sz / 2)
	{
		cl_int	mclass = Max(get_next_log2(bytesize),
							 GPUMEM_CHUNKSZ_MIN_BIT);

		return gpuMemAllocChunk(GpuMemKind__ManagedMemory,
								gcontext, p_deviceptr, mclass,
								filename, lineno);
	}
	return __gpuMemAllocManagedRaw(gcontext,
								   p_deviceptr,
								   bytesize,
								   flags,
								   filename, lineno);
}

/*
 * __gpuMemAllocHost
 */
CUresult
__gpuMemAllocHost(GpuContext *gcontext,
				  void **p_hostptr,
				  size_t bytesize,
				  const char *filename, int lineno)
{
	CUdeviceptr	m_devptr;
	CUresult	rc;

	if (bytesize <= gm_segment_sz / 2)
	{
		cl_int	mclass = Max(get_next_log2(bytesize),
							 GPUMEM_CHUNKSZ_MIN_BIT);

		rc = gpuMemAllocChunk(GpuMemKind__HostMemory,
							  gcontext, &m_devptr, mclass,
							  filename, lineno);
		if (rc == CUDA_SUCCESS)
			*p_hostptr = (void *)m_devptr;
		return rc;
	}
	return __gpuMemAllocHostRaw(gcontext, p_hostptr, bytesize,
								filename, lineno);
}

/*
 * __gpuMemRequestPreserved
 */
static CUresult
__gpuMemPreservedRequest(cl_int cuda_dindex,
						 CUipcMemHandle *m_handle,
						 ssize_t bytesize)
{
	GpuMemPreservedRequest *gmemp_req = NULL;
	dlist_node	   *dnode;
	CUresult		rc;
	int				ev;

	SpinLockAcquire(&gmemp_head->lock);
	for (;;)
	{
		if (!gmemp_head->bgworkers[cuda_dindex].gmemp_req_latch)
		{
			SpinLockRelease(&gmemp_head->lock);
			return CUDA_ERROR_NOT_READY;
		}
		if (!dlist_is_empty(&gmemp_head->gmemp_req_free_list))
			break;
		SpinLockRelease(&gmemp_head->lock);
		CHECK_FOR_INTERRUPTS();
		pg_usleep(5000L);		/* 5msec */
		SpinLockAcquire(&gmemp_head->lock);
	}
	dnode = dlist_pop_head_node(&gmemp_head->gmemp_req_free_list);
	gmemp_req = dlist_container(GpuMemPreservedRequest, chain, dnode);
	memset(gmemp_req, 0, sizeof(GpuMemPreservedRequest));
	gmemp_req->backend = MyLatch;
	gmemp_req->owner = GetUserId();
	gmemp_req->result = (CUresult) UINT_MAX;
	if (bytesize == 0)
		memcpy(&gmemp_req->m_handle, m_handle, sizeof(CUipcMemHandle));
	else
		memset(&gmemp_req->m_handle, 0, sizeof(CUipcMemHandle));
	gmemp_req->cuda_dindex = cuda_dindex;
	gmemp_req->bytesize = bytesize;

	dlist_push_tail(&gmemp_head->bgworkers[cuda_dindex].gmemp_req_pending,
					&gmemp_req->chain);
	SetLatch(gmemp_head->bgworkers[cuda_dindex].gmemp_req_latch);
	while (gmemp_req->result == (CUresult) UINT_MAX)
	{
		SpinLockRelease(&gmemp_head->lock);

		PG_TRY();
		{
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
			SpinLockAcquire(&gmemp_head->lock);
			if (gmemp_req->chain.next && gmemp_req->chain.prev)
			{
				/* not fetched yet */
				dlist_delete(&gmemp_req->chain);
				dlist_push_tail(&gmemp_head->gmemp_req_free_list,
								&gmemp_req->chain);
			}
			else if (gmemp_req->result == (CUresult) UINT_MAX)
			{
				/* under the process */
				gmemp_req->backend = NULL;
			}
			else if (gmemp_req->bytesize > 0)
			{
				/* already allocated; revert allocation */
				gmemp_req->backend = NULL;
				gmemp_req->result = (CUresult) UINT_MAX;
				gmemp_req->bytesize = 0;
				dlist_push_tail(&gmemp_head->bgworkers[cuda_dindex].gmemp_req_pending,
								&gmemp_req->chain);
				SetLatch(gmemp_head->bgworkers[cuda_dindex].gmemp_req_latch);
			}
			else
			{
				/* already released; it's ok */
				dlist_push_tail(&gmemp_head->gmemp_req_free_list,
								&gmemp_req->chain);
			}
			SpinLockRelease(&gmemp_head->lock);
			PG_RE_THROW();
		}
		PG_END_TRY();

		SpinLockAcquire(&gmemp_head->lock);
	}
	rc = gmemp_req->result;
	if (rc == CUDA_SUCCESS)
	{
		if (bytesize > 0)
			memcpy(m_handle, &gmemp_req->m_handle,
				   sizeof(CUipcMemHandle));
	}
	dlist_push_tail(&gmemp_head->gmemp_req_free_list,
					&gmemp_req->chain);
	SpinLockRelease(&gmemp_head->lock);

	return rc;
}

/*
 * __gpuMemAllocPreserved
 */
CUresult
__gpuMemAllocPreserved(cl_int cuda_dindex,
					   CUipcMemHandle *ipc_mhandle,
					   ssize_t bytesize,
					   const char *filename, int lineno)
{
	Assert(bytesize > 0);
	return __gpuMemPreservedRequest(cuda_dindex,
									ipc_mhandle,
									bytesize);
}

/*
 * gpuMemFreePreserved
 */
CUresult
gpuMemFreePreserved(cl_int cuda_dindex,
					CUipcMemHandle m_handle)
{
	return __gpuMemPreservedRequest(cuda_dindex, &m_handle, 0);
}

/*
 * gpuMemReclaimSegment - release a free segment if any
 */
void
gpuMemReclaimSegment(GpuContext *gcontext)
{
	dlist_head	   *dhead_n = &gcontext->gm_normal_list;
	dlist_head	   *dhead_i = &gcontext->gm_iomap_list;
	dlist_head	   *dhead_m = &gcontext->gm_managed_list;
	dlist_head	   *dhead_h = &gcontext->gm_hostmem_list;
	dlist_node	   *dnode_n = NULL;
	dlist_node	   *dnode_i = NULL;
	dlist_node	   *dnode_m = NULL;
	dlist_node	   *dnode_h = NULL;
	GpuMemSegment  *gm_seg;
	CUresult		rc;

	pthreadRWLockWriteLock(&gcontext->gm_rwlock);
	if (!dlist_is_empty(dhead_n))
		dnode_n = dlist_tail_node(dhead_n);
	if (!dlist_is_empty(dhead_i))
		dnode_i = dlist_tail_node(dhead_i);
	if (!dlist_is_empty(dhead_m))
		dnode_m = dlist_tail_node(dhead_m);
	if (!dlist_is_empty(dhead_h))
		dnode_h = dlist_tail_node(dhead_h);
	while (dnode_n || dnode_i)
	{
		if (dnode_n)
		{
			gm_seg = dlist_container(GpuMemSegment, chain, dnode_n);
			if (dlist_has_prev(dhead_n, dnode_n))
				dnode_n = dlist_prev_node(dhead_n, dnode_n);
			else
				dnode_n = NULL;
			Assert(gm_seg->gm_kind == GpuMemKind__NormalMemory);
			if (pg_atomic_read_u32(&gm_seg->num_active_chunks) == 0)
			{
				rc = cuMemFree(gm_seg->m_segment);
				if (rc != CUDA_SUCCESS)
				{
					pthreadRWLockUnlock(&gcontext->gm_rwlock);
					werror("failed on cuMemFree: %s", errorText(rc));
				}
				dlist_delete(&gm_seg->chain);
				free(gm_seg);
				break;
			}
					}

		if (dnode_i)
		{
			gm_seg = dlist_container(GpuMemSegment, chain, dnode_i);
			if (dlist_has_prev(dhead_i, dnode_i))
				dnode_i = dlist_prev_node(dhead_i, dnode_i);
			else
				dnode_i = NULL;
			Assert(gm_seg->gm_kind == GpuMemKind__IOMapMemory);
			if (pg_atomic_read_u32(&gm_seg->num_active_chunks) == 0)
            {
				rc = gpuDirectUnmapGpuMemory(gm_seg->m_segment,
											 gm_seg->iomap_handle);
				if (rc != CUDA_SUCCESS)
					wnotice("failed on gpuDirectUnmapGpuMemory: %s", errorText(rc));

				rc = cuMemFree(gm_seg->m_segment);
				if (rc != CUDA_SUCCESS)
				{
					pthreadRWLockUnlock(&gcontext->gm_rwlock);
					werror("failed on cuMemFree: %s", errorText(rc));
				}
				dlist_delete(&gm_seg->chain);
				free(gm_seg);
				break;
			}
		}

		if (dnode_m)
		{
			gm_seg = dlist_container(GpuMemSegment, chain, dnode_m);
			if (dlist_has_prev(dhead_m, dnode_m))
				dnode_m = dlist_prev_node(dhead_m, dnode_m);
			else
				dnode_m = NULL;
			Assert(gm_seg->gm_kind == GpuMemKind__ManagedMemory);
			if (pg_atomic_read_u32(&gm_seg->num_active_chunks) == 0)
			{
				rc = cuMemFree(gm_seg->m_segment);
				if (rc != CUDA_SUCCESS)
				{
					pthreadRWLockUnlock(&gcontext->gm_rwlock);
					werror("failed on cuMemFree: %s", errorText(rc));
				}
				dlist_delete(&gm_seg->chain);
				free(gm_seg);
			}
		}
		if (dnode_h)
		{
			gm_seg = dlist_container(GpuMemSegment, chain, dnode_h);
			if (dlist_has_prev(dhead_h, dnode_h))
				dnode_h = dlist_prev_node(dhead_h, dnode_h);
			else
				dnode_h = NULL;
			Assert(gm_seg->gm_kind == GpuMemKind__HostMemory);
			if (pg_atomic_read_u32(&gm_seg->num_active_chunks) == 0)
			{
				rc = cuMemFreeHost((void *)gm_seg->m_segment);
				if (rc != CUDA_SUCCESS)
				{
					pthreadRWLockUnlock(&gcontext->gm_rwlock);
					werror("failed on cuMemFreeHost: %s", errorText(rc));
				}
				dlist_delete(&gm_seg->chain);
				free(gm_seg);
			}
		}
	}
	pthreadRWLockUnlock(&gcontext->gm_rwlock);
}

/*
 * pgstrom_gpu_mmgr_init_gpucontext - Per GpuContext initialization
 */
void
pgstrom_gpu_mmgr_init_gpucontext(GpuContext *gcontext)
{
	pthreadRWLockInit(&gcontext->gm_rwlock);
	dlist_init(&gcontext->gm_normal_list);
	dlist_init(&gcontext->gm_iomap_list);
	dlist_init(&gcontext->gm_managed_list);
	dlist_init(&gcontext->gm_hostmem_list);
}

/*
 * pgstrom_gpu_mmgr_cleanup_gpucontext - Per GpuContext cleanup
 *
 * NOTE: CUDA context is already destroyed on the invocation time. 
 * So, we don't need to release individual segment, but need to release
 * heap memory.
 */
void
pgstrom_gpu_mmgr_cleanup_gpucontext(GpuContext *gcontext)
{
	GpuMemStatistics *gm_stat = &gm_stat_array[gcontext->cuda_dindex];
	GpuMemSegment  *gm_seg;
	dlist_node	   *dnode;
	CUresult		rc;

	while (!dlist_is_empty(&gcontext->gm_normal_list))
	{
		dnode = dlist_pop_head_node(&gcontext->gm_normal_list);
		gm_seg = dlist_container(GpuMemSegment, chain, dnode);
		rc = cuMemFree(gm_seg->m_segment);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuMemFree(normal): %s", errorText(rc));
		pg_atomic_sub_fetch_u64(&gm_stat->normal_usage, gm_segment_sz);
		free(gm_seg);
	}

	while (!dlist_is_empty(&gcontext->gm_managed_list))
	{
		dnode = dlist_pop_head_node(&gcontext->gm_managed_list);
		gm_seg = dlist_container(GpuMemSegment, chain, dnode);
		rc = cuMemFree(gm_seg->m_segment);
        if (rc != CUDA_SUCCESS)
            elog(WARNING, "failed on cuMemFree(managed): %s", errorText(rc));
		pg_atomic_sub_fetch_u64(&gm_stat->managed_usage, gm_segment_sz);
		free(gm_seg);
	}

	while (!dlist_is_empty(&gcontext->gm_iomap_list))
	{
		dnode = dlist_pop_head_node(&gcontext->gm_iomap_list);
		gm_seg = dlist_container(GpuMemSegment, chain, dnode);

		rc = gpuDirectUnmapGpuMemory(gm_seg->m_segment,
									 gm_seg->iomap_handle);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on gpuDirectUnmapGpuMemory: %s", errorText(rc));

		rc = cuMemFree(gm_seg->m_segment);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuMemFree(io-map): %s", errorText(rc));
		pg_atomic_sub_fetch_u64(&gm_stat->iomap_usage, gm_segment_sz);
		free(gm_seg);
	}

	while (!dlist_is_empty(&gcontext->gm_hostmem_list))
	{
		dnode = dlist_pop_head_node(&gcontext->gm_hostmem_list);
		gm_seg = dlist_container(GpuMemSegment, chain, dnode);
		rc = cuMemFreeHost((void *)gm_seg->m_segment);
		if (rc != CUDA_SUCCESS)
			elog(WARNING, "failed on cuMemFreeHost: %s", errorText(rc));
		free(gm_seg);
	}
}

/*
 * gpummgrBgWorkerAllocPreserved
 */
static CUresult
gpummgrHandleAllocPreserved(GpuMemPreservedRequest *gmemp_req)
{
	MemoryContext	memcxt = CurrentMemoryContext;
	GpuMemPreserved *gmemp;
	CUresult		rc = CUDA_SUCCESS;
	CUdeviceptr		m_devptr;
	CUipcMemHandle	m_handle;
	bool			found;

	rc = cuMemAlloc(&m_devptr, gmemp_req->bytesize);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuMemAlloc: %s", errorText(rc));
		return rc;
	}

	rc = cuIpcGetMemHandle(&m_handle, m_devptr);
	if (rc != CUDA_SUCCESS)
	{
		elog(WARNING, "failed on cuIpcGetMemHandle: %s", errorText(rc));
		cuMemFree(m_devptr);
		return rc;
	}
	memcpy(&gmemp_req->m_handle, &m_handle, sizeof(CUipcMemHandle));

	PG_TRY();
	{
		gmemp = hash_search(gmemp_htab, &m_handle, HASH_ENTER, &found);
		if (found)
			elog(ERROR, "Bug? duplicated GPU preserved memory handle");
		gmemp->cuda_dindex = gmemp_req->cuda_dindex;
		gmemp->bytesize = gmemp_req->bytesize;
		gmemp->m_devptr = m_devptr;
		gmemp->owner = gmemp_req->owner;
		gmemp->ctime = GetCurrentTimestamp();
	}
	PG_CATCH();
	{
		ErrorData  *errdata;

		MemoryContextSwitchTo(memcxt);
		errdata = CopyErrorData();
		elog(WARNING, "%s:%d) %s",
			 errdata->filename,
			 errdata->lineno,
			 errdata->message);
		FlushErrorState();
		rc = CUDA_ERROR_OUT_OF_MEMORY;
	}
	PG_END_TRY();

	return rc;
}

/*
 * gpummgrHandleFreePreserved
 */
static CUresult
gpummgrHandleFreePreserved(GpuMemPreservedRequest *gmemp_req)
{
	GpuMemPreserved *gmemp = NULL;
	CUresult	rc;

	gmemp = hash_search(gmemp_htab, &gmemp_req->m_handle, HASH_FIND, NULL);
	if (!gmemp)
		return CUDA_ERROR_NOT_FOUND;

	rc = cuMemFree(gmemp->m_devptr);
	if (rc != CUDA_SUCCESS)
		elog(WARNING, "failed on cuMemFree: %s", errorText(rc));

	hash_search(gmemp_htab, &gmemp_req->m_handle, HASH_REMOVE, NULL);

	return rc;
}

/*
 * gpummgrBgWorker(Begin|Dispatch|End)
 */
static void
gpummgrBgWorkerBegin(int cuda_dindex)
{
	HASHCTL		hctl;

	memset(&hctl, 0, sizeof(HASHCTL));
	hctl.keysize = sizeof(CUipcMemHandle);
	hctl.entrysize = sizeof(GpuMemPreserved);
	hctl.hcxt = TopMemoryContext;

	gmemp_htab = hash_create("Preserved GPU Memory", 256, &hctl,
							 HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	SpinLockAcquire(&gmemp_head->lock);
	gmemp_head->bgworkers[cuda_dindex].gmemp_req_latch = MyLatch;
	SpinLockRelease(&gmemp_head->lock);
}

static bool
gpummgrBgWorkerDispatch(int cuda_dindex)
{
	GpuMemPreservedRequest *gmemp_req;
	dlist_head *plist;
	CUresult	rc;

	SpinLockAcquire(&gmemp_head->lock);
	plist = &gmemp_head->bgworkers[cuda_dindex].gmemp_req_pending;
	if (dlist_is_empty(plist))
	{
		SpinLockRelease(&gmemp_head->lock);
		return true;	/* bgworker can go to sleep */
	}
	gmemp_req = dlist_container(GpuMemPreservedRequest, chain,
								dlist_pop_head_node(plist));
	memset(&gmemp_req->chain, 0, sizeof(dlist_node));
	SpinLockRelease(&gmemp_head->lock);

	if (gmemp_req->cuda_dindex != cuda_dindex)
		rc = CUDA_ERROR_INVALID_VALUE;
	else if (gmemp_req->bytesize > 0)
		rc = gpummgrHandleAllocPreserved(gmemp_req);
	else if (gmemp_req->bytesize == 0)
		rc = gpummgrHandleFreePreserved(gmemp_req);
	else
		rc = CUDA_ERROR_INVALID_VALUE;

	SpinLockAcquire(&gmemp_head->lock);
	if (gmemp_req->backend)
	{
		gmemp_req->result = rc;
		SetLatch(gmemp_req->backend);
	}
	else
	{
		memset(gmemp_req, 0, sizeof(GpuMemPreservedRequest));
		dlist_push_tail(&gmemp_head->gmemp_req_free_list,
						&gmemp_req->chain);
	}
	SpinLockRelease(&gmemp_head->lock);

	return false;
}

static bool
gpummgrBgWorkerIdleTask(int cuda_dindex)
{
	return true;
}

static void
gpummgrBgWorkerEnd(int cuda_dindex)
{
	SpinLockAcquire(&gmemp_head->lock);
	gmemp_head->bgworkers[cuda_dindex].gmemp_req_latch = NULL;
	SpinLockRelease(&gmemp_head->lock);
}

/*
 * gpummgrBgWorkerSigTerm
 */
static void
gpummgrBgWorkerSigTerm(SIGNAL_ARGS)
{
	int		saved_errno = errno;

	gpummgr_bgworker_got_signal = true;

	pg_memory_barrier();

	SetLatch(MyLatch);

	errno = saved_errno;
}

/*
 * gpummgrBgWorkerMain - main loop for device memory keeper
 */
void
gpummgrBgWorkerMain(Datum arg)
{
	int			cuda_dindex = DatumGetInt32(arg);
	CUdevice	cuda_device;
	CUcontext	cuda_context;
	CUresult	rc;

	pqsignal(SIGTERM, gpummgrBgWorkerSigTerm);
	BackgroundWorkerUnblockSignals();

	/* never use MPS */
	if (setenv("CUDA_MPS_PIPE_DIRECTORY", "/dev/null", 1) != 0)
		elog(ERROR, "failed on setenv: %m");

	/* init CUDA context */
	Assert(cuda_dindex >= 0 && cuda_dindex < numDevAttrs);
	rc = cuInit(0);
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

	/* initial setup */
	gpummgrBgWorkerBegin(cuda_dindex);
	gpuStoreBgWorkerBegin(cuda_dindex);
	/*
	 * Event loop
	 */
	while (!gpummgr_bgworker_got_signal)
	{
		if (gpummgrBgWorkerDispatch(cuda_dindex) &
			gpuStoreBgWorkerDispatch(cuda_dindex))
		{
			if (gpummgrBgWorkerIdleTask(cuda_dindex) &
				gpuStoreBgWorkerIdleTask(cuda_dindex))
			{
				int		ev = WaitLatch(MyLatch,
									   WL_LATCH_SET |
									   WL_TIMEOUT |
									   WL_POSTMASTER_DEATH,
									   1000L,
									   PG_WAIT_EXTENSION);
				ResetLatch(MyLatch);
				if (ev & WL_POSTMASTER_DEATH)
					elog(FATAL, "unexpected Postmaster dead");
			}
		}
	}
	/* Exit */
	gpummgrBgWorkerEnd(cuda_dindex);
	gpuStoreBgWorkerEnd(cuda_dindex);
}

/*
 * pgstrom_device_preserved_meminfo (deprecated)
 */
Datum pgstrom_device_preserved_meminfo(PG_FUNCTION_ARGS);

Datum
pgstrom_device_preserved_meminfo(PG_FUNCTION_ARGS)
{
	elog(ERROR, "pgstrom_device_preserved_meminfo() is deprecated");
	PG_RETURN_NULL();
}
PG_FUNCTION_INFO_V1(pgstrom_device_preserved_meminfo);

/*
 * pgstrom_startup_gpu_mmgr
 */
static void
pgstrom_startup_gpu_mmgr(void)
{
	size_t		required;
	bool		found;
	int			i;

	if (shmem_startup_next)
		(*shmem_startup_next)();

	/*
	 * GpuMemStatistics
	 */
	required = STROMALIGN(sizeof(GpuMemStatistics) * numDevAttrs);
	gm_stat_array = ShmemInitStruct("GPU Device Memory Statistics",
									required, &found);
	if (found)
		elog(ERROR, "Bug? GPU Device Memory Statistics exists");
	memset(gm_stat_array, 0, required);
	for (i=0; i < numDevAttrs; i++)
		gm_stat_array[i].total_size = devAttrs[i].DEV_TOTAL_MEMSZ;

	/*
	 * GpuMemPreservedHead
	 */
	required = STROMALIGN(offsetof(GpuMemPreservedHead,
								   bgworkers[numDevAttrs]));
	gmemp_head = ShmemInitStruct("GPU Device Memory for Multi-Processes",
								 required, &found);
	if (found)
		elog(ERROR, "Bug? GPU Device Memory for Multi-Processes exists");
	memset(gmemp_head, 0, required);
	SpinLockInit(&gmemp_head->lock);
	dlist_init(&gmemp_head->gmemp_req_free_list);
	for (i=0; i < lengthof(gmemp_head->__gmemp_req_items); i++)
	{
		dlist_push_tail(&gmemp_head->gmemp_req_free_list,
						&gmemp_head->__gmemp_req_items[i].chain);
	}
	for (i=0; i < numDevAttrs; i++)
	{
		gmemp_head->bgworkers[i].gmemp_req_latch = NULL;
		dlist_init(&gmemp_head->bgworkers[i].gmemp_req_pending);
	}
}

/*
 * pgstrom_init_gpu_mmgr
 */
void
pgstrom_init_gpu_mmgr(void)
{
	Size		segment_sz;
	Size		required;
	int			dindex;

	/*
	 * segment size of the device memory in kB
	 */
	DefineCustomIntVariable("pg_strom.gpu_memory_segment_size",
							"default size of the GPU device memory segment",
							NULL,
							&gpu_memory_segment_size_kb,
							(pgstrom_chunk_size() * 8) >> 10,
							pgstrom_chunk_size() >> 10,
							GPUMEM_CHUNKSZ_MAX >> 10,
							PGC_POSTMASTER,
							GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE | GUC_UNIT_KB,
							NULL, NULL, NULL);
	segment_sz = (size_t)gpu_memory_segment_size_kb << 10;
	if (segment_sz % pgstrom_chunk_size() != 0)
		elog(ERROR, "pg_strom.gpu_memory_segment_size(%dkB) must be multiple number of pg_strom.chunk_size(%dkB)",
			 gpu_memory_segment_size_kb,
			 (int)(pgstrom_chunk_size() >> 10));
	gm_segment_sz = (size_t)gpu_memory_segment_size_kb << 10;

	/*
	 * Background workers per device, to keep device memory for multi-process
	 */
	for (dindex=0; dindex < numDevAttrs; dindex++)
	{
		BackgroundWorker worker;

		memset(&worker, 0, sizeof(BackgroundWorker));
		snprintf(worker.bgw_name, sizeof(worker.bgw_name),
				 "GPU%u memory keeper", dindex);
		worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
		worker.bgw_start_time = BgWorkerStart_PostmasterStart;
		worker.bgw_restart_time = 1;
		snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_strom");
		snprintf(worker.bgw_function_name, BGW_MAXLEN, "gpummgrBgWorkerMain");
		worker.bgw_main_arg = Int32GetDatum(dindex);
		RegisterBackgroundWorker(&worker);
	}

	/*
	 * request for the static shared memory
	 */
	required = STROMALIGN(sizeof(GpuMemStatistics) * numDevAttrs) +
		STROMALIGN(offsetof(GpuMemPreservedHead, bgworkers[numDevAttrs]));
	RequestAddinShmemSpace(required);
	shmem_startup_next = shmem_startup_hook;
	shmem_startup_hook = pgstrom_startup_gpu_mmgr;
}

/* ----------------------------------------------------------------
 *
 * APIs for SSD-to-GPU Direct DMA
 *
 * ---------------------------------------------------------------- 
 */

/*
 * __gpuMemCopyFromSSD_Block - for KDS_FORMAT_BLOCK
 */
static void
__gpuMemCopyFromSSD_Block(GpuContext *gcontext,
						  GpuMemSegment *gm_seg,
						  CUdeviceptr m_kds,
						  pgstrom_data_store *pds)
{
	StromCmd__MemCopySsdToGpuRaw cmd __attribute__((unused));
	size_t			offset = m_kds - gm_seg->m_segment;
	size_t			length;
	cl_uint			nr_loaded;
	CUresult		rc;

	Assert(pds->kds.format == KDS_FORMAT_BLOCK);
	/* nothing special if all the blocks are already loaded */
	if (pds->nblocks_uncached == 0)
	{
		rc = cuMemcpyHtoDAsync(m_kds,
							   &pds->kds,
							   pds->kds.length,
							   CU_STREAM_PER_THREAD);
		if (rc != CUDA_SUCCESS)
			werror("failed on cuMemcpyHtoDAsync: %s", errorText(rc));
		return;
	}
	Assert(pds->nblocks_uncached <= pds->kds.nitems);
	nr_loaded = pds->kds.nitems - pds->nblocks_uncached;
	length = ((char *)KERN_DATA_STORE_BLOCK_PGPAGE(&pds->kds, nr_loaded) -
			  (char *)(&pds->kds));
	offset += length;

	/* (1) kick RAM2GPU DMA (earlier half) */
	rc = cuMemcpyHtoDAsync(m_kds,
						   &pds->kds,
						   length,
						   CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemcpyHtoDAsync: %s", errorText(rc));

	/* (2) kick SSD2GPU P2P DMA, if any */
	if (pds->iovec)
	{
		gpuDirectFileReadIOV(&pds->filedesc,
							 gm_seg->m_segment,
							 gm_seg->iomap_handle,
							 offset,
							 pds->iovec);
	}
}

/*
 * __gpuMemCopyFromSSD_Arrow - for KDS_FORMAT_ARROW
 */
static void
__gpuMemCopyFromSSD_Arrow(GpuContext *gcontext,
						  GpuMemSegment *gm_seg,
						  CUdeviceptr m_kds,
						  pgstrom_data_store *pds)
{
	size_t		head_sz;
	CUresult	rc;

	Assert(pds->kds.format == KDS_FORMAT_ARROW);

	/* (1) RAM2GPU DMA (header portion) */
	head_sz = KERN_DATA_STORE_HEAD_LENGTH(&pds->kds);
	rc = cuMemcpyHtoDAsync(m_kds,
						   &pds->kds,
						   head_sz,
						   CU_STREAM_PER_THREAD);
	if (rc != CUDA_SUCCESS)
		werror("failed on cuMemcpyHtoDAsync: %s", errorText(rc));
	
	/* (2) SSD2GPU P2P DMA */
	if (pds->iovec)
	{
		gpuDirectFileReadIOV(&pds->filedesc,
							 gm_seg->m_segment,
							 gm_seg->iomap_handle,
							 m_kds - gm_seg->m_segment,
							 pds->iovec);
	}
}

/*
 * gpuMemCopyFromSSD - kick SSD-to-GPU Direct DMA, then wait for completion
 */
void
gpuMemCopyFromSSD(CUdeviceptr m_kds, pgstrom_data_store *pds)
{
	GpuContext	   *gcontext = GpuWorkerCurrentContext;
	GpuMemSegment  *gm_seg;

	/* ensure the @m_kds is exactly i/o mapped buffer */
	Assert(gcontext != NULL);
	gm_seg = lookupGpuMem(gcontext, m_kds);
	if (!gm_seg || gm_seg->gm_kind != GpuMemKind__IOMapMemory)
		werror("nvme-strom: invalid device pointer");
	Assert(m_kds >= gm_seg->m_segment &&
		   m_kds + pds->kds.length <= gm_seg->m_segment + gm_segment_sz);
	switch (pds->kds.format)
	{
		case KDS_FORMAT_BLOCK:
			__gpuMemCopyFromSSD_Block(gcontext, gm_seg, m_kds, pds);
			break;
		case KDS_FORMAT_ARROW:
			__gpuMemCopyFromSSD_Arrow(gcontext, gm_seg, m_kds, pds);
			break;
		default:
			werror("nvme-strom: unsupported KDS format: %d",
				   pds->kds.format);
			break;
	}
}
