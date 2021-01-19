/*
 * cuda_common.h
 *
 * A common header for CUDA device code
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
#ifndef CUDA_COMMON_H
#define CUDA_COMMON_H

/* ---- Check minimum required CUDA version ---- */
#ifdef __CUDACC__
#if __CUDACC_VER_MAJOR__ < 9 || \
   (__CUDACC_VER_MAJOR__ == 9 && __CUDACC_VER_MINOR__ < 2)
#error PG-Strom requires CUDA 9.2 or later. Use newer version.
#endif	/* >=CUDA9.2 */
#include <pg_config.h>
#include <pg_config_manual.h>
#endif	/* __CUDACC__ */

/* check MAXIMUM_ALIGNOF */
#if MAXIMUM_ALIGNOF == 8
#define MAXIMUM_ALIGNOF_SHIFT	3
#else
#error Unexpected MAXIMUM_ALIGNOF definition
#endif

/*
 * Basic type definition - because of historical reason, we use "cl_"
 * prefix for the definition of data types below. It might imply
 * something related to OpenCL, but what we intend at this moment is
 * "CUDA Language".
 */
typedef char				cl_bool;
typedef char				cl_char;
typedef unsigned char		cl_uchar;
typedef short				cl_short;
typedef unsigned short		cl_ushort;
typedef int					cl_int;
typedef unsigned int		cl_uint;
#ifdef __CUDACC__
typedef long long			cl_long;
typedef unsigned long long	cl_ulong;
#else	/* __CUDACC__ */
typedef long				cl_long;
typedef unsigned long		cl_ulong;
#endif	/* !__CUDACC__ */
#ifdef __CUDACC__
#include <cuda_fp16.h>
typedef __half				cl_half;
#else
/* Host code has no __half definition, so put dummy definition */
typedef unsigned short		cl_half;
#endif	/* __CUDACC__ */
typedef float				cl_float;
typedef double				cl_double;

#define CL_SHORT_NBITS		(sizeof(cl_short) * BITS_PER_BYTE)
#define CL_INT_NBITS		(sizeof(cl_int) * BITS_PER_BYTE)
#define CL_LONG_NBITS		(sizeof(cl_long) * BITS_PER_BYTE)

/* PG's utility macros */
#ifdef __CUDACC__
#ifdef offsetof
#undef offsetof
#endif /* offsetof */
#define offsetof(TYPE,FIELD)			((long) &((TYPE *)0UL)->FIELD)

/*
 * At CUDA10, we found nvcc replaces the offsetof above by __builtin_offsetof
 * regardless of our macro definitions. It is mostly equivalent, however, it
 * does not support offset calculation which includes run-time values.
 * E.g) offsetof(kds, colmeta[kds->ncols]) made an error.
 */
#ifdef __NVCC__
#define __builtin_offsetof(TYPE,FIELD)	((long) &((TYPE *)0UL)->FIELD)
#endif /* __NVCC__ */

#ifdef lengthof
#undef lengthof
#endif
#define lengthof(ARRAY)			(sizeof(ARRAY) / sizeof((ARRAY)[0]))

#ifdef container_of
#undef container_of
#endif
#define container_of(TYPE,FIELD,PTR)			\
	((TYPE *)((char *) (PTR) - offsetof(TYPE, FIELD)))

#ifndef true
#define true			((cl_bool) 1)
#endif
#ifndef false
#define false			((cl_bool) 0)
#endif
#ifdef __CUDACC__
#undef FLEXIBLE_ARRAY_MEMBER
#define FLEXIBLE_ARRAY_MEMBER	1
#elif !defined(FLEXIBLE_ARRAY_MEMBER)
#define FLEXIBLE_ARRAY_MEMBER	1
#endif	/* __CUDACC__ */

/*
 * If NVCC includes this file, some inline function needs declarations of
 * basic utility functions.
 */
#ifndef __CUDACC_RTC__
#include <assert.h>
#include <stdio.h>
#endif	/* __CUDACC_RTC__ */

#define Assert(cond)	assert(cond)

/* Another basic type definitions */
typedef cl_ulong	hostptr_t;
typedef cl_ulong	Datum;
typedef struct nameData
{
	char		data[NAMEDATALEN];
} NameData;

#define PointerGetDatum(X)	((Datum) (X))
#define DatumGetPointer(X)	((char *) (X))

#define SET_1_BYTE(value)	(((Datum) (value)) & 0x000000ffL)
#define SET_2_BYTES(value)	(((Datum) (value)) & 0x0000ffffL)
#define SET_4_BYTES(value)	(((Datum) (value)) & 0xffffffffL)
#define SET_8_BYTES(value)	((Datum) (value))

#define READ_INT8_PTR(addr)		SET_1_BYTE(*((cl_uchar *)(addr)))
#define READ_INT16_PTR(addr)	SET_2_BYTES(*((cl_ushort *)(addr)))
#define READ_INT32_PTR(addr)	SET_4_BYTES(*((cl_uint *)(addr)))
#define READ_INT64_PTR(addr)	SET_8_BYTES(*((cl_ulong *)(addr)))

#define INT64CONST(x)	((cl_long) x##L)
#define UINT64CONST(x)	((cl_ulong) x##UL)

#define Max(a,b)		((a) > (b) ? (a) : (b))
#define Max3(a,b,c)		((a) > (b) ? Max((a),(c)) : Max((b),(c)))
#define Max4(a,b,c,d)	Max(Max((a),(b)),Max((c),(d)))

#define Min(a,b)		((a) < (b) ? (a) : (b))
#define Min3(a,b,c)		((a) < (b) ? Min((a),(c)) : Min((b),(c)))
#define Min4(a,b,c,d)	Min(Min((a),(b)),Min((c),(d)))

#define Add(a,b)		((a) + (b))
#define Add3(a,b,c)		((a) + (b) + (c))
#define Add4(a,b,c,d)	((a) + (b) + (c) + (d))

#define Compare(a,b)	((a) > (b) ? 1 : ((a) < (b) ? -1 : 0))

/* same as host side get_next_log2() */
#define get_next_log2(value)								\
	((value) == 0 ? 0 : (sizeof(cl_ulong) * BITS_PER_BYTE - \
						 __clzll((cl_ulong)(value) - 1)))
/*
 * Limitation of types
 */
#ifndef SHRT_MAX
#define SHRT_MAX		32767
#endif
#ifndef SHRT_MIN
#define SHRT_MIN		(-32767-1)
#endif
#ifndef USHRT_MAX
#define USHRT_MAX		65535
#endif
#ifndef INT_MAX
#define INT_MAX			2147483647
#endif
#ifndef INT_MIN
#define INT_MIN			(-INT_MAX - 1)
#endif
#ifndef UINT_MAX
#define UINT_MAX		4294967295U
#endif
#ifndef LONG_MAX
#define LONG_MAX		0x7FFFFFFFFFFFFFFFLL
#endif
#ifndef LONG_MIN
#define LONG_MIN        (-LONG_MAX - 1LL)
#endif
#ifndef ULONG_MAX
#define ULONG_MAX		0xFFFFFFFFFFFFFFFFULL
#endif
#ifndef HALF_MAX
#define HALF_MAX		__short_as_half(0x7bff)
#endif
#ifndef HALF_MIN
#define HALF_MIN		__short_as_half(0x0400)
#endif
#ifndef HALF_INFINITY
#define HALF_INFINITY	__short_as_half(0x0x7c00)
#endif
#ifndef FLT_MAX
#define FLT_MAX			__int_as_float(0x7f7fffffU)
#endif
#ifndef FLT_MIN
#define FLT_MIN			__int_as_float(0x00800000U)
#endif
#ifndef FLT_INFINITY
#define FLT_INFINITY	__int_as_float(0x7f800000U)
#endif
#ifndef FLT_NAN
#define FLT_NAN			__int_as_float(0x7fffffffU)
#endif
#ifndef DBL_MAX
#define DBL_MAX			__longlong_as_double(0x7fefffffffffffffULL)
#endif
#ifndef DBL_MIN
#define DBL_MIN			__longlong_as_double(0x0010000000000000ULL)
#endif
#ifndef DBL_INFINITY
#define DBL_INFINITY	__longlong_as_double(0x7ff0000000000000ULL)
#endif
#ifndef DBL_NAN
#define DBL_NAN			__longlong_as_double(0x7fffffffffffffffULL)
#endif

/*
 * Alignment macros
 */
#define TYPEALIGN(ALIGNVAL,LEN)	\
	(((cl_ulong) (LEN) + ((ALIGNVAL) - 1)) & ~((cl_ulong) ((ALIGNVAL) - 1)))
#define TYPEALIGN_DOWN(ALIGNVAL,LEN) \
	(((cl_ulong) (LEN)) & ~((cl_ulong) ((ALIGNVAL) - 1)))
#define INTALIGN(LEN)			TYPEALIGN(sizeof(cl_int), (LEN))
#define INTALIGN_DOWN(LEN)		TYPEALIGN_DOWN(sizeof(cl_int), (LEN))
#define LONGALIGN(LEN)          TYPEALIGN(sizeof(cl_long), (LEN))
#define LONGALIGN_DOWN(LEN)     TYPEALIGN_DOWN(sizeof(cl_long), (LEN))
#define MAXALIGN(LEN)			TYPEALIGN(MAXIMUM_ALIGNOF, (LEN))
#define MAXALIGN_DOWN(LEN)		TYPEALIGN_DOWN(MAXIMUM_ALIGNOF, (LEN))
#endif	/* __CUDACC__ */

/* wider alignment */
#define STROMALIGN_LEN			16
#define STROMALIGN(LEN)			TYPEALIGN(STROMALIGN_LEN,(LEN))
#define STROMALIGN_DOWN(LEN)	TYPEALIGN_DOWN(STROMALIGN_LEN,(LEN))

#define GPUMEMALIGN_LEN			1024
#define GPUMEMALIGN(LEN)		TYPEALIGN(GPUMEMALIGN_LEN,(LEN))
#define GPUMEMALIGN_DOWN(LEN)	TYPEALIGN_DOWN(GPUMEMALIGN_LEN,(LEN))

#define BLCKALIGN(LEN)			TYPEALIGN(BLCKSZ,(LEN))
#define BLCKALIGN_DOWN(LEN)		TYPEALIGN_DOWN(BLCKSZ,(LEN))

#ifdef __CUDACC__
/*
 * MEMO: We takes dynamic local memory using cl_ulong data-type because of
 * alignment problem. The nvidia's driver adjust alignment of local memory
 * according to the data type; 1byte for cl_char, 4bytes for cl_uint and
 * so on. Unexpectedly, void * pointer has 1byte alignment even if it is
 * expected to be casted another data types.
 * A pragma option __attribute__((aligned)) didn't work at least driver
 * version 340.xx. So, we declared the local_workmem as cl_ulong * pointer
 * as a workaround.
 */
#define SHARED_WORKMEM(TYPE)	((TYPE *) __pgstrom_dynamic_shared_workmem)
extern __shared__ cl_ulong __pgstrom_dynamic_shared_workmem[];

/*
 * Thread index like OpenCL style.
 *
 * Be careful to use this convenient alias if grid/block size may become
 * larger than INT_MAX, because threadIdx and blockDim are declared as
 * 32bit integer, thus, it makes overflow during intermediation results
 * if it is larger than INT_MAX.
 */
#define get_group_id()			(blockIdx.x)
#define get_num_groups()		(gridDim.x)
#define get_local_id()			(threadIdx.x)
#define get_local_size()		(blockDim.x)
#define get_global_id()			(threadIdx.x + blockIdx.x * blockDim.x)
#define get_global_size()		(blockDim.x * gridDim.x)
#define get_global_base()		(blockIdx.x * blockDim.x)

#else	/* __CUDACC__ */
typedef cl_ulong		hostptr_t;
#endif	/* !__CUDACC__ */

/*
 * Template of static function declarations
 *
 * CUDA compilar raises warning if static functions are not used, but
 * we can restain this message with"unused" attribute of function/values.
 * STATIC_INLINE / STATIC_FUNCTION packs common attributes to be
 * assigned on host/device functions
 */
#define MAXTHREADS_PER_BLOCK		1024
#define MAXWARPS_PER_BLOCK			(MAXTHREADS_PER_BLOCK / 32)
#ifdef __CUDACC__
#define STATIC_INLINE(RET_TYPE)					\
	__device__ __host__ __forceinline__			\
	static RET_TYPE __attribute__ ((unused))
#define STATIC_FUNCTION(RET_TYPE)				\
	__device__ __host__							\
	static RET_TYPE
#define DEVICE_INLINE(RET_TYPE)					\
	__device__ __forceinline__					\
	static RET_TYPE __attribute__ ((unused))
#define DEVICE_FUNCTION(RET_TYPE)				\
	__device__ RET_TYPE __attribute__ ((unused))
#define PUBLIC_FUNCTION(RET_TYPE)				\
	__device__ __host__ RET_TYPE
#define KERNEL_FUNCTION(RET_TYPE)				\
	extern "C" __global__ RET_TYPE
#define KERNEL_FUNCTION_MAXTHREADS(RET_TYPE)	\
	extern "C" __global__ RET_TYPE __launch_bounds__(MAXTHREADS_PER_BLOCK)
#else	/* __CUDACC__ */
#define STATIC_INLINE(RET_TYPE)		static inline RET_TYPE
#define STATIC_FUNCTION(RET_TYPE)	static inline RET_TYPE
#define PUBLIC_FUNCTION(RET_TYPE)	RET_TYPE
#endif	/* !__CUDACC__ */

/*
 * __Fetch - access macro regardless of memory alignment
 */
#ifdef __CUDA_ARCH__
template <typename T>
DEVICE_INLINE(T)
__Fetch(const T *ptr)
{
	T	temp;
	/*
	 * (2019/06/01) Originally, this function used direct pointer access
	 * using *ptr, if pointer is aligned. However, it looks NVCC/NVRTC
	 * optimization generates binary code that accesses unaligned pointer.
	 * '--device-debug' eliminates the strange behavior, and 'volatile'
	 * qualification also stop the behavior.
	 * Maybe, future version of CUDA and NVCC/NVRTC will fix the problem.
	 */
	memcpy(&temp, ptr, sizeof(T));

	return temp;
}
#else	/* __CUDA_ARCH__ */
#define __Fetch(PTR)			(*(PTR))
#endif	/* !__CUDA_ARCH__ */

/*
 * Error code definition
 *
 * MEMO: SQL ERRCODE_* uses 0-29bits. We also use 30bit for a flag of
 * CPU fallback. Host code tries CPU fallback if this flag is set and
 * pg_strom.cpu_fallback_enabled is set.
 */
#ifndef MAKE_SQLSTATE
#define PGSIXBIT(ch)		(((ch) - '0') & 0x3F)
#define MAKE_SQLSTATE(ch1,ch2,ch3,ch4,ch5)  \
	(PGSIXBIT(ch1) + (PGSIXBIT(ch2) << 6) + (PGSIXBIT(ch3) << 12) + \
	 (PGSIXBIT(ch4) << 18) + (PGSIXBIT(ch5) << 24))
#endif  /* MAKE_SQLSTATE */
#include "utils/errcodes.h"
#define ERRCODE_FLAGS_CPU_FALLBACK			(1U<<30)
#define ERRCODE_STROM_SUCCESS				0
#define ERRCODE_STROM_DATASTORE_NOSPACE		MAKE_SQLSTATE('H','D','B','0','4')
#define ERRCODE_STROM_WRONG_CODE_GENERATION	MAKE_SQLSTATE('H','D','B','0','5')
#define ERRCODE_STROM_DATA_CORRUPTION		MAKE_SQLSTATE('H','D','B','0','7')
#define ERRCODE_STROM_VARLENA_UNSUPPORTED	MAKE_SQLSTATE('H','D','B','0','8')
#define ERRCODE_STROM_RECURSION_TOO_DEEP	MAKE_SQLSTATE('H','D','B','0','9')

#define KERN_ERRORBUF_FILENAME_LEN		24
#define KERN_ERRORBUF_FUNCNAME_LEN		64
#define KERN_ERRORBUF_MESSAGE_LEN		200
typedef struct
{
	cl_int		errcode;	/* one of the ERRCODE_* */
	cl_int		lineno;
	char		filename[KERN_ERRORBUF_FILENAME_LEN];
	char		funcname[KERN_ERRORBUF_FUNCNAME_LEN];
	char		message[KERN_ERRORBUF_MESSAGE_LEN];
} kern_errorbuf;

/*
 * kern_context - a set of run-time information
 */
struct kern_parambuf;

typedef struct
{
	cl_int			errcode;
	const char	   *error_filename;
	cl_int			error_lineno;
	const char	   *error_funcname;
	const char	   *error_message;	/* !!only const static cstring!! */
	struct kern_parambuf *kparams;
	void		   *stack_bounds;
	cl_char		   *vlpos;
	cl_char		   *vlend;
	cl_char			vlbuf[1];
} kern_context;

/*
 * Usually, kern_context is declared at the auto-generated portion,
 * then its pointer shall be passed to the pre-built GPU binary part.
 * Its vlbuf length shall be determined on run-time compilation using
 * the macro below.
 */
#define KERN_CONTEXT_VARLENA_BUFSZ_LIMIT	8192
#ifdef __CUDACC_RTC__
#define DECL_KERNEL_CONTEXT(NAME)								\
	union {														\
		kern_context kcxt;										\
		char __dummy__[offsetof(kern_context, vlbuf) +			\
					   MAXALIGN(KERN_CONTEXT_VARLENA_BUFSZ)];	\
	} NAME
#endif /* __CUDACC_RTC__ */

#define INIT_KERNEL_CONTEXT(kcxt,__kparams)							\
	do {															\
		memset(kcxt, 0, offsetof(kern_context, vlbuf));					\
		(kcxt)->kparams = (__kparams);									\
		assert((cl_ulong)(__kparams) == MAXALIGN(__kparams));			\
		(kcxt)->stack_bounds = (char *)(kcxt) - KERN_CONTEXT_STACK_LIMIT; \
		(kcxt)->vlpos = (kcxt)->vlbuf;									\
		(kcxt)->vlend = (kcxt)->vlbuf + KERN_CONTEXT_VARLENA_BUFSZ;		\
	} while(0)

#define PTR_ON_VLBUF(kcxt,ptr,len)							\
	((char *)(ptr) >= (kcxt)->vlbuf &&						\
	 (char *)(ptr) + (len) <= (kcxt)->vlend)

STATIC_INLINE(void *)
kern_context_alloc(kern_context *kcxt, size_t len)
{
	char   *pos = (char *)MAXALIGN(kcxt->vlpos);

	if (pos >= kcxt->vlbuf && pos + len <= kcxt->vlend)
	{
		kcxt->vlpos = pos + len;
		return pos;
	}
	return NULL;
}

#define CHECK_KERNEL_STACK_DEPTH(kcxt)						\
	(((cl_ulong)((kcxt)->stack_bounds)) > ((cl_ulong)(&(kcxt))))

#ifdef __CUDA_ARCH__
/*
 * It sets an error code unless no significant error code is already set.
 * Also, CpuReCheck has higher priority than RowFiltered because CpuReCheck
 * implies device cannot run the given expression completely.
 * (Usually, due to compressed or external varlena datum)
 */
STATIC_INLINE(void)
__STROM_EREPORT(kern_context *kcxt, cl_int errcode,
				const char *filename, cl_int lineno,
				const char *funcname, const char *message)
{
	cl_int		oldcode = kcxt->errcode;

	if (oldcode == ERRCODE_STROM_SUCCESS &&
		errcode != ERRCODE_STROM_SUCCESS)
	{
		const char *pos;

		for (pos=filename; *pos != '\0'; pos++)
		{
			if (pos[0] == '/' && pos[1] != '\0')
				filename = pos + 1;
		}
		if (!message)
			message = "GPU kernel internal error";
		kcxt->errcode  = errcode;
		kcxt->error_filename = filename;
		kcxt->error_lineno   = lineno;
		kcxt->error_funcname = funcname;
		kcxt->error_message  = message;
	}
}

#define STROM_ELOG(kcxt, message)										\
	__STROM_EREPORT((kcxt),ERRCODE_INTERNAL_ERROR,						\
					__FILE__,__LINE__,__FUNCTION__,(message))
#define STROM_EREPORT(kcxt, errcode, message)							\
	__STROM_EREPORT((kcxt),(errcode),									\
					__FILE__,__LINE__,__FUNCTION__,(message))
#define STROM_CPU_FALLBACK(kcxt, errcode, message)						\
	__STROM_EREPORT((kcxt),(errcode) | ERRCODE_FLAGS_CPU_FALLBACK,		\
					__FILE__,__LINE__,__FUNCTION__,(message))

STATIC_INLINE(void)
__strncpy(char *d, const char *s, cl_uint n)
{
	cl_uint		i, m = n-1;

	for (i=0; i < m && s[i] != '\0'; i++)
		d[i] = s[i];
	while (i < n)
		d[i++] = '\0';
}

/*
 * kern_writeback_error_status
 */
STATIC_INLINE(void)
kern_writeback_error_status(kern_errorbuf *result, kern_context *kcxt)
{
	/*
	 * It writes back a thread local error status only when the global
	 * error status is not set yet and the caller thread contains any
	 * error status. Elsewhere, we don't involves any atomic operation
	 * in the most of code path.
	 */
	if (kcxt->errcode != ERRCODE_STROM_SUCCESS &&
		atomicCAS(&result->errcode,
				  ERRCODE_STROM_SUCCESS,
				  kcxt->errcode) == ERRCODE_STROM_SUCCESS)
	{
		result->errcode = kcxt->errcode;
		result->lineno  = kcxt->error_lineno;
		__strncpy(result->filename,
				  kcxt->error_filename,
				  KERN_ERRORBUF_FILENAME_LEN);
		__strncpy(result->funcname,
				  kcxt->error_funcname,
				  KERN_ERRORBUF_FUNCNAME_LEN);
		__strncpy(result->message,
				  kcxt->error_message,
				  KERN_ERRORBUF_MESSAGE_LEN);
	}
}
#elif defined(__CUDACC__)
#define STROM_EREPORT(kcxt, errcode, message)		\
	do {											\
		fprintf(stderr, "%s:%d %s (code=%d)\n",		\
				__FUNCTION__, __LINE__,				\
				message, errcode);					\
		exit(1);									\
	} while(0)
#define STROM_CPU_FALLBACK(a,b,c)	STROM_EREPORT((a),(b),(c))
#else /* !__CUDA_ARCH__ && !__CUDACC__ == gcc by pg_config */
#define STROM_EREPORT(kcxt, errcode, message)		\
	elog(ERROR, "%s:%d %s (code=%d)",				\
		 __FUNCTION__, __LINE__,					\
		 message, errcode)
#define STROM_CPU_FALLBACK(a,b,c)	STROM_EREPORT((a),(b),(c))
#endif	/* !__CUDA_ARCH__ && !__CUDACC__ */

#ifdef __CUDACC__
/* definitions at storage/block.h */
typedef cl_uint		BlockNumber;
#define InvalidBlockNumber		((BlockNumber) 0xFFFFFFFF)
#define MaxBlockNumber			((BlockNumber) 0xFFFFFFFE)

/* details are defined at cuda_gpuscan.h */
struct PageHeaderData;

/* definitions at access/htup_details.h */
typedef struct {
	struct {
		cl_ushort	bi_hi;
		cl_ushort	bi_lo;
	} ip_blkid;
	cl_ushort		ip_posid;
} ItemPointerData;

STATIC_FUNCTION(cl_bool)
ItemPointerEquals(ItemPointerData *ip1, ItemPointerData *ip2)
{
	return (ip1->ip_blkid.bi_hi == ip2->ip_blkid.bi_hi &&
			ip1->ip_blkid.bi_lo == ip2->ip_blkid.bi_lo &&
			ip1->ip_posid       == ip2->ip_posid);
}

typedef struct HeapTupleFields
{
	cl_uint			t_xmin;		/* inserting xact ID */
	cl_uint			t_xmax;		/* deleting or locking xact ID */
	union
	{
		cl_uint		t_cid;		/* inserting or deleting command ID, or both */
		cl_uint		t_xvac;		/* old-style VACUUM FULL xact ID */
    }	t_field3;
} HeapTupleFields;

typedef struct DatumTupleFields
{
	cl_int		datum_len_;		/* varlena header (do not touch directly!) */
	cl_int		datum_typmod;	/* -1, or identifier of a record type */
	cl_uint		datum_typeid;	/* composite type OID, or RECORDOID */
} DatumTupleFields;

typedef struct {
	union {
		HeapTupleFields		t_heap;
		DatumTupleFields	t_datum;
	} t_choice;

	ItemPointerData	t_ctid;			/* current TID of this or newer tuple */

	cl_ushort		t_infomask2;	/* number of attributes + various flags */
	cl_ushort		t_infomask;		/* various flag bits, see below */
	cl_uchar		t_hoff;			/* sizeof header incl. bitmap, padding */
	/* ^ - 23 bytes - ^ */
	cl_uchar		t_bits[1];		/* bitmap of NULLs -- VARIABLE LENGTH */
} HeapTupleHeaderData;

#define att_isnull(ATT, BITS) (!((BITS)[(ATT) >> 3] & (1 << ((ATT) & 0x07))))
#define BITMAPLEN(NATTS) (((int)(NATTS) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

/*
 * information stored in t_infomask:
 */
#define HEAP_HASNULL			0x0001	/* has null attribute(s) */
#define HEAP_HASVARWIDTH		0x0002	/* has variable-width attribute(s) */
#define HEAP_HASEXTERNAL		0x0004	/* has external stored attribute(s) */
#define HEAP_HASOID				0x0008	/* has an object-id field */
#define HEAP_XMAX_KEYSHR_LOCK	0x0010	/* xmax is a key-shared locker */
#define HEAP_COMBOCID			0x0020	/* t_cid is a combo cid */
#define HEAP_XMAX_EXCL_LOCK		0x0040	/* xmax is exclusive locker */
#define HEAP_XMAX_LOCK_ONLY		0x0080	/* xmax, if valid, is only a locker */

/*
 * information stored in t_infomask2:
 */
#define HEAP_NATTS_MASK			0x07FF	/* 11 bits for number of attributes */
#define HEAP_KEYS_UPDATED		0x2000	/* tuple was updated and key cols
										 * modified, or tuple deleted */
#define HEAP_HOT_UPDATED		0x4000	/* tuple was HOT-updated */
#define HEAP_ONLY_TUPLE			0x8000	/* this is heap-only tuple */
#define HEAP2_XACT_MASK			0xE000	/* visibility-related bits */

/*
 * Index tuple header structure
 *
 * All index tuples start with IndexTupleData.  If the HasNulls bit is set,
 * this is followed by an IndexAttributeBitMapData.  The index attribute
 * values follow, beginning at a MAXALIGN boundary.
 */
typedef struct IndexTupleData
{
	ItemPointerData		t_tid;		/* reference TID to heap tuple */

	/* ---------------
	 * t_info is laid out in the following fashion:
	 *
	 * 15th (high) bit: has nulls
	 * 14th bit: has var-width attributes
	 * 13th bit: AM-defined meaning
	 * 12-0 bit: size of tuple
	 * ---------------
	 */
	unsigned short		t_info;

	char				data[1];	/* data or IndexAttributeBitMapData */
} IndexTupleData;

typedef struct IndexAttributeBitMapData
{
	cl_uchar			bits[(INDEX_MAX_KEYS + 8 - 1) / 8];
} IndexAttributeBitMapData;

#define INDEX_SIZE_MASK		0x1fff
#define INDEX_VAR_MASK		0x4000
#define INDEX_NULL_MASK		0x8000

/*
 * Below is routines to support KDS_FORMAT_BLOCKS - This KDS format is used
 * to load raw PostgreSQL heap blocks to GPU without modification by CPU.
 * All CPU has to pay attention is, not to load rows which should not be
 * visible to the current scan snapshot.
 */
typedef cl_uint		TransactionId;
#define InvalidTransactionId		((TransactionId) 0)
#define FrozenTransactionId			((TransactionId) 2)
#define InvalidCommandId			(~0U)
#else
#include "access/htup_details.h"
#endif	/* __CUDACC__ */

typedef struct
{
	cl_int		vl_len_;
	cl_int		ndim;			/* always 1 for xidvector */
	cl_int		dataoffset;		/* always 0 for xidvector */
	cl_uint		elemtype;		/* XIDOID */
	cl_int		dim1;			/* number of items */
	cl_int		lbound1;		/* always 1 for xidvector */
	TransactionId values[FLEXIBLE_ARRAY_MEMBER];
} xidvector;

#ifdef __CUDACC__
/* definitions at storage/itemid.h */
typedef struct ItemIdData
{
	unsigned	lp_off:15,		/* offset to tuple (from start of page) */
				lp_flags:2,		/* state of item pointer, see below */
				lp_len:15;		/* byte length of tuple */
} ItemIdData;

#define LP_UNUSED		0		/* unused (should always have lp_len=0) */
#define LP_NORMAL		1		/* used (should always have lp_len>0) */
#define LP_REDIRECT		2		/* HOT redirect (should have lp_len=0) */
#define LP_DEAD			3		/* dead, may or may not have storage */

#define ItemIdGetOffset(itemId)		((itemId)->lp_off)
#define ItemIdGetLength(itemId)		((itemId)->lp_len)
#define ItemIdIsUsed(itemId)		((itemId)->lp_flags != LP_UNUSED)
#define ItemIdIsNormal(itemId)		((itemId)->lp_flags == LP_NORMAL)
#define ItemIdIsRedirected(itemId)	((itemId)->lp_flags == LP_REDIRECT)
#define ItemIdIsDead(itemId)		((itemId)->lp_flags == LP_DEAD)
#define ItemIdHasStorage(itemId)	((itemId)->lp_len != 0)
#define ItemIdSetUnused(itemId)			\
	do {								\
		(itemId)->lp_flags = LP_UNUSED;	\
		(itemId)->lp_off = 0;			\
		(itemId)->lp_len = 0;			\
	} while(0)

/* definitions at storage/off.h */
typedef cl_ushort		OffsetNumber;

#define InvalidOffsetNumber		((OffsetNumber) 0)
#define FirstOffsetNumber		((OffsetNumber) 1)
#define MaxOffsetNumber			((OffsetNumber) (BLCKSZ / sizeof(ItemIdData)))
#define OffsetNumberMask		(0xffff)	/* valid uint16 bits */

#define OffsetNumberNext(offsetNumber)			\
	((OffsetNumber) (1 + (offsetNumber)))

/* definitions at storage/bufpage.h */
typedef cl_ushort	LocationIndex;

typedef struct PageHeaderData
{
#if 0
	/*
	 * NOTE: device code (ab-)uses this field to track parent block/item
	 * when GiST index is loaded. Without this hack, hard to implement
	 * depth-first search at GpuJoin.
	 */
	PageXLogRecPtr	pd_lsn;			/* LSN: next byte after last byte of xlog
									 * record for last change to this page */
#else
	cl_uint			pd_parent_blkno;
	cl_uint			pd_parent_item;	
#endif
	cl_ushort		pd_checksum;	/* checksum */
	cl_ushort		pd_flags;		/* flag bits, see below */
	LocationIndex	pd_lower;		/* offset to start of free space */
	LocationIndex	pd_upper;		/* offset to end of free space */
	LocationIndex	pd_special;		/* offset to start of special space */
	cl_ushort		pd_pagesize_version;
	TransactionId pd_prune_xid;		/* oldest prunable XID, or zero if none */
	ItemIdData		pd_linp[FLEXIBLE_ARRAY_MEMBER]; /* line pointer array */
} PageHeaderData;

#define SizeOfPageHeaderData	(offsetof(PageHeaderData, pd_linp))

#define PD_HAS_FREE_LINES	0x0001	/* are there any unused line pointers? */
#define PD_PAGE_FULL		0x0002	/* not enough free space for new tuple? */
#define PD_ALL_VISIBLE		0x0004	/* all tuples on page are visible to
									 * everyone */
#define PD_VALID_FLAG_BITS  0x0007	/* OR of all valid pd_flags bits */

#define PageGetItemId(page, offsetNumber)				\
	(&((PageHeaderData *)(page))->pd_linp[(offsetNumber) - 1])
#define PageGetItem(page, lpp)							\
	((HeapTupleHeaderData *)((char *)(page) + ItemIdGetOffset(lpp)))
STATIC_INLINE(cl_uint)
PageGetMaxOffsetNumber(PageHeaderData *page)
{
	cl_uint		pd_lower = page->pd_lower;

	return (pd_lower <= SizeOfPageHeaderData ? 0 :
			(pd_lower - SizeOfPageHeaderData) / sizeof(ItemIdData));
}

#endif	/* __CUDACC__ */

/*
 * kern_data_store
 */
#include "arrow_defs.h"

#define TYPE_KIND__BASE			'b'
#define TYPE_KIND__ARRAY		'a'
#define TYPE_KIND__COMPOSITE	'c'
#define TYPE_KIND__DOMAIN		'd'
#define TYPE_KIND__ENUM			'e'
#define TYPE_KIND__PSEUDO		'p'
#define TYPE_KIND__RANGE		'r'

typedef struct {
	/* true, if column is held by value. Elsewhere, a reference */
	cl_char			attbyval;
	/* alignment; 1,2,4 or 8, not characters in pg_attribute */
	cl_char			attalign;
	/* length of attribute */
	cl_short		attlen;
	/* attribute number */
	cl_short		attnum;
	/* offset of attribute location, if deterministic */
	cl_short		attcacheoff;
	/* oid of the SQL data type */
	cl_uint			atttypid;
	/* typmod of the SQL data type */
	cl_int			atttypmod;
	/* one of TYPE_KIND__* */
	cl_char			atttypkind;
	/*
	 * (for array and composite types)
	 * Some of types contain sub-fields like array or composite type.
	 * We carry type definition information (kern_colmeta) using the
	 * kds->colmeta[] array next to the top-level fields.
	 * An array type has relevant element type. So, its @num_subattrs
	 * is always 1, and kds->colmeta[@idx_subattrs] informs properties
	 * of the element type.
	 * A composite type has several fields.
	 * kds->colmeta[@idx_subattrs ... @idx_subattrs + @num_subattrs -1]
	 * carries its sub-fields properties.
	 */
	cl_ushort		idx_subattrs;
	cl_ushort		num_subattrs;

	/* column name */
	NameData		attname;

	/*
	 * (only arrow/column format)
	 * @attoptions keeps extra information of Apache Arrow type. Unlike
	 * PostgreSQL types, it can have variation of data accuracy in time
	 * related data types, or precision in decimal data type.
	 */
	ArrowTypeOptions attopts;
	cl_uint			nullmap_offset;
	cl_uint			nullmap_length;
	cl_uint			values_offset;
	cl_uint			values_length;
	cl_uint			extra_offset;
	cl_uint			extra_length;
} kern_colmeta;

/*
 * kern_tupitem - individual items for KDS_FORMAT_ROW
 */
typedef struct
{
	cl_uint			t_len;		/* length of tuple */
	cl_uint			rowid;		/* unique Id of this item */
	HeapTupleHeaderData	htup;
} kern_tupitem;

/*
 * kern_hashitem - individual items for KDS_FORMAT_HASH
 */
typedef struct
{
	cl_uint				hash;	/* 32-bit hash value */
	cl_uint				next;	/* offset of the next (PACKED) */
	kern_tupitem		t;		/* HeapTuple of this entry */
} kern_hashitem;

#define KDS_FORMAT_ROW			1
#define KDS_FORMAT_SLOT			2
#define KDS_FORMAT_HASH			3	/* inner hash table for GpuHashJoin */
#define KDS_FORMAT_BLOCK		4	/* raw blocks for direct loading */
#define KDS_FORMAT_COLUMN		5	/* columnar based storage format */
#define KDS_FORMAT_ARROW		6	/* apache arrow format */

typedef struct {
	size_t			length;		/* length of this data-store */
	/*
	 * NOTE: {nitems + usage} must be aligned to 64bit because these pair of
	 * values can be updated atomically using cmpxchg.
	 */
	cl_uint			nitems; 	/* number of rows in this store */
	cl_uint			usage;		/* usage of this data-store (PACKED) */
	cl_uint			nrooms;		/* number of available rows in this store */
	cl_uint			ncols;		/* number of columns in this store */
	cl_char			format;		/* one of KDS_FORMAT_* above */
	cl_char			has_varlena; /* true, if any varlena attribute */
	cl_char			tdhasoid;	/* copy of TupleDesc.tdhasoid */
	cl_uint			tdtypeid;	/* copy of TupleDesc.tdtypeid */
	cl_int			tdtypmod;	/* copy of TupleDesc.tdtypmod */
	cl_uint			table_oid;	/* OID of the table (only if GpuScan) */
	cl_uint			nslots;		/* width of hash-slot (only HASH format) */
	cl_uint			nrows_per_block; /* average number of rows per
									  * PostgreSQL block (only BLOCK format) */
	cl_uint			nr_colmeta;	/* number of colmeta[] array elements;
								 * maybe, >= ncols, if any composite types */
	kern_colmeta	colmeta[FLEXIBLE_ARRAY_MEMBER]; /* metadata of columns */
} kern_data_store;

/*
 * kern_data_extra - extra buffer of KDS_FORMAT_COLUMN
 */
typedef struct
{
	cl_ulong	length;
	cl_ulong	usage;
	char		data[FLEXIBLE_ARRAY_MEMBER];
} kern_data_extra;

/* attribute number of system columns */
#ifndef SYSATTR_H
#define SelfItemPointerAttributeNumber			(-1)
#define ObjectIdAttributeNumber					(-2)
#define MinTransactionIdAttributeNumber			(-3)
#define MinCommandIdAttributeNumber				(-4)
#define MaxTransactionIdAttributeNumber			(-5)
#define MaxCommandIdAttributeNumber				(-6)
#define TableOidAttributeNumber					(-7)
#define FirstLowInvalidHeapAttributeNumber		(-8)
#endif	/* !SYSATTR_H */

/*
 * MEMO: Support of 32GB KDS - KDS with row-, hash- and column-format
 * internally uses 32bit offset value from the head or base address.
 * We have assumption here - any objects pointed by the offset value
 * is always aligned to MAXIMUM_ALIGNOF boundary (64bit).
 * It means we can use 32bit offset to represent up to 32GB range (35bit).
 */
STATIC_INLINE(cl_uint)
__kds_packed(size_t offset)
{
	Assert((offset & (~((size_t)(~0U) << MAXIMUM_ALIGNOF_SHIFT))) == 0);
	return (cl_uint)(offset >> MAXIMUM_ALIGNOF_SHIFT);
}

STATIC_INLINE(size_t)
__kds_unpack(cl_uint offset)
{
	return (size_t)offset << MAXIMUM_ALIGNOF_SHIFT;
}
#define KDS_OFFSET_MAX_SIZE		((size_t)UINT_MAX << MAXIMUM_ALIGNOF_SHIFT)

/* 'nslots' estimation; 25% larger than nitems, but 128 at least */
#define __KDS_NSLOTS(nitems)					\
	Max(128, ((nitems) * 5) >> 2)
/*
 * NOTE: For strict correctness, header portion of kern_data_store may
 * have larger number of colmeta[] items than 'ncols', if array or composite
 * types are in the field definition.
 * However, it is relatively rare, and 'ncols' == 'nr_colmeta' in most cases.
 * The macros below are used for just cost estimation; no need to be strict
 * connect for size estimatino.
 */
// use KDS_calculateHeadSize() instead
#define KDS_ESTIMATE_HEAD_LENGTH(ncols)					\
	STROMALIGN(offsetof(kern_data_store, colmeta[(ncols)]))
#define KDS_ESTIMATE_ROW_LENGTH(ncols,nitems,htup_sz)					\
	(KDS_ESTIMATE_HEAD_LENGTH(ncols) +									\
	 STROMALIGN(sizeof(cl_uint) * (nitems)) +							\
	 STROMALIGN(MAXALIGN(offsetof(kern_tupitem,							\
								  htup) + htup_sz) * (nitems)))
#define KDS_ESTIMATE_HASH_LENGTH(ncols,nitems,htup_sz)					\
	(KDS_ESTIMATE_HEAD_LENGTH(ncols) +									\
	 STROMALIGN(sizeof(cl_uint) * (nitems)) +							\
	 STROMALIGN(sizeof(cl_uint) * __KDS_NSLOTS(nitems)) +				\
	 STROMALIGN(MAXALIGN(offsetof(kern_hashitem,						\
								  t.htup) + htup_sz) * (nitems)))

/* Length of the header postion of kern_data_store */
STATIC_INLINE(size_t)
KERN_DATA_STORE_HEAD_LENGTH(kern_data_store *kds)
{
	return STROMALIGN(offsetof(kern_data_store,
							   colmeta[kds->nr_colmeta]));
}
/* Base address of the data body */
STATIC_INLINE(char *)
KERN_DATA_STORE_BODY(kern_data_store *kds)
{
	return (char *)kds + KERN_DATA_STORE_HEAD_LENGTH(kds);
}

/* access function for row- and hash-format */
STATIC_INLINE(cl_uint *)
KERN_DATA_STORE_ROWINDEX(kern_data_store *kds)
{
	Assert(kds->format == KDS_FORMAT_ROW ||
		   kds->format == KDS_FORMAT_HASH);
	return (cl_uint *)KERN_DATA_STORE_BODY(kds);
}

/* access function for hash-format */
STATIC_INLINE(cl_uint *)
KERN_DATA_STORE_HASHSLOT(kern_data_store *kds)
{
	Assert(kds->format == KDS_FORMAT_HASH);
	return (cl_uint *)(KERN_DATA_STORE_BODY(kds) +
					   STROMALIGN(sizeof(cl_uint) * kds->nrooms));
}

/* access function for row- and hash-format */
STATIC_INLINE(kern_tupitem *)
KERN_DATA_STORE_TUPITEM(kern_data_store *kds, cl_uint kds_index)
{
	size_t	offset = KERN_DATA_STORE_ROWINDEX(kds)[kds_index];

	if (!offset)
		return NULL;
	return (kern_tupitem *)((char *)kds + __kds_unpack(offset));
}

/* access macro for row-format by tup-offset */
STATIC_INLINE(HeapTupleHeaderData *)
KDS_ROW_REF_HTUP(kern_data_store *kds,
				 cl_uint tup_offset,
				 ItemPointerData *p_self,
				 cl_uint *p_len)
{
	kern_tupitem   *tupitem;

	Assert(kds->format == KDS_FORMAT_ROW ||
		   kds->format == KDS_FORMAT_HASH);
	if (tup_offset == 0)
		return NULL;
	tupitem = (kern_tupitem *)((char *)(kds)
							   + __kds_unpack(tup_offset)
							   - offsetof(kern_tupitem, htup));
	if (p_self)
		*p_self = tupitem->htup.t_ctid;
	if (p_len)
		*p_len = tupitem->t_len;
	return &tupitem->htup;
}

STATIC_INLINE(kern_hashitem *)
KERN_HASH_FIRST_ITEM(kern_data_store *kds, cl_uint hash)
{
	cl_uint	   *slot = KERN_DATA_STORE_HASHSLOT(kds);
	size_t		offset = __kds_unpack(slot[hash % kds->nslots]);

	if (offset == 0)
		return NULL;
	Assert(offset < kds->length);
	return (kern_hashitem *)((char *)kds + offset);
}

STATIC_INLINE(kern_hashitem *)
KERN_HASH_NEXT_ITEM(kern_data_store *kds, kern_hashitem *khitem)
{
	size_t		offset;

	if (!khitem || khitem->next == 0)
		return NULL;
	offset = __kds_unpack(khitem->next);
	Assert(offset < kds->length);
	return (kern_hashitem *)((char *)kds + offset);
}

/* access macro for tuple-slot format */
STATIC_INLINE(size_t)
KERN_DATA_STORE_SLOT_LENGTH(kern_data_store *kds, cl_uint nitems)
{
	size_t	headsz = KERN_DATA_STORE_HEAD_LENGTH(kds);
	size_t	unitsz = LONGALIGN((sizeof(Datum) + sizeof(char)) * kds->ncols);

	return headsz + unitsz * nitems;
}

STATIC_INLINE(Datum *)
KERN_DATA_STORE_VALUES(kern_data_store *kds, cl_uint row_index)
{
	size_t	offset = KERN_DATA_STORE_SLOT_LENGTH(kds, row_index);

	return (Datum *)((char *)kds + offset);
}

STATIC_INLINE(cl_char *)
KERN_DATA_STORE_DCLASS(kern_data_store *kds, cl_uint row_index)
{
	Datum  *values = KERN_DATA_STORE_VALUES(kds, row_index);

	return (cl_char *)(values + kds->ncols);
}

/* access macro for block format */
#define KERN_DATA_STORE_PARTSZ(kds)				\
	Min(((kds)->nrows_per_block +				\
		 warpSize - 1) & ~(warpSize - 1),		\
		get_local_size())
#define KERN_DATA_STORE_BLOCK_BLCKNR(kds,kds_index)			\
	(((BlockNumber *)KERN_DATA_STORE_BODY(kds))[kds_index])
#define KERN_DATA_STORE_BLOCK_PGPAGE(kds,kds_index)			\
	((struct PageHeaderData *)								\
	 (KERN_DATA_STORE_BODY(kds) +							\
	  STROMALIGN(sizeof(BlockNumber) * (kds)->nrooms) +		\
	  BLCKSZ * kds_index))

/*
 * KDS_BLOCK_REF_HTUP
 *
 * It pulls a HeapTupleHeader by a pair of KDS and lp_offset; 
 */
STATIC_INLINE(HeapTupleHeaderData *)
KDS_BLOCK_REF_HTUP(kern_data_store *kds,
				   cl_uint lp_offset,
				   ItemPointerData *p_self,
				   cl_uint *p_len)
{
	/*
	 * NOTE: lp_offset is not packed offset!
	 * KDS_FORMAT_BLOCK will be never larger than 4GB.
	 */
	ItemIdData	   *lpp = (ItemIdData *)((char *)kds + lp_offset);
	cl_uint			head_size;
	cl_uint			block_id;
	BlockNumber		block_nr;
	PageHeaderData *pg_page;

	Assert(kds->format == KDS_FORMAT_BLOCK);
	if (lp_offset == 0)
		return NULL;
	head_size = (KERN_DATA_STORE_HEAD_LENGTH(kds) +
				 STROMALIGN(sizeof(BlockNumber) * kds->nrooms));
	Assert(lp_offset >= head_size &&
		   lp_offset <  head_size + BLCKSZ * kds->nitems);
	block_id = (lp_offset - head_size) / BLCKSZ;
	block_nr = KERN_DATA_STORE_BLOCK_BLCKNR(kds, block_id);
	pg_page = KERN_DATA_STORE_BLOCK_PGPAGE(kds, block_id);

	Assert(lpp >= pg_page->pd_linp &&
		   lpp -  pg_page->pd_linp <  PageGetMaxOffsetNumber(pg_page));
	if (p_self)
	{
		p_self->ip_blkid.bi_hi	= block_nr >> 16;
		p_self->ip_blkid.bi_lo	= block_nr & 0xffff;
		p_self->ip_posid		= lpp - pg_page->pd_linp;
	}
	if (p_len)
		*p_len = ItemIdGetLength(lpp);
	return (HeapTupleHeaderData *)PageGetItem(pg_page, lpp);
}

/* access functions for apache arrow format */
STATIC_INLINE(void *)
kern_fetch_simple_datum_arrow(kern_colmeta *cmeta,
							  char *base,
							  cl_uint index,
							  cl_uint unitsz)
{
	cl_char	   *nullmap = NULL;
	cl_char	   *values;

	if (cmeta->nullmap_offset)
	{
		nullmap = base + __kds_unpack(cmeta->nullmap_offset);
		if (att_isnull(index, nullmap))
			return NULL;
	}
	Assert(cmeta->values_offset > 0);
	Assert(cmeta->extra_offset == 0);
	Assert(cmeta->extra_length == 0);
	Assert(unitsz * (index+1) <= __kds_unpack(cmeta->values_length));
	values = base + __kds_unpack(cmeta->values_offset);
	return values + unitsz * index;
}

STATIC_INLINE(void *)
kern_fetch_varlena_datum_arrow(kern_colmeta *cmeta,
							   char *base,
							   cl_uint index,
							   cl_uint *p_length)
{
	cl_char	   *nullmap;
	cl_uint	   *offset;
	cl_char	   *extra;

	if (cmeta->nullmap_offset)
	{
		nullmap = base + __kds_unpack(cmeta->nullmap_offset);
		if (att_isnull(index, nullmap))
			return NULL;
	}
	Assert(cmeta->values_offset > 0 &&
		   cmeta->extra_offset > 0 &&
		   sizeof(cl_uint) * (index+1) <= __kds_unpack(cmeta->values_length));
	offset = (cl_uint *)(base + __kds_unpack(cmeta->values_offset));
	extra = base + __kds_unpack(cmeta->extra_offset);

	Assert(offset[index] <= offset[index+1] &&
		   offset[index+1] <= __kds_unpack(cmeta->extra_length));
	*p_length = offset[index+1] - offset[index];
	return (extra + offset[index]);
}

/*
 * kern_parambuf
 *
 * Const and Parameter buffer. It stores constant values during a particular
 * scan, so it may make sense if it is obvious length of kern_parambuf is
 * less than constant memory (NOTE: not implemented yet).
 */
typedef struct kern_parambuf
{
	/*
	 * Fields of system information on execution
	 */
	cl_long		xactStartTimestamp;	/* timestamp when transaction start */
	cl_uint		xactIdVector;		/* offset to xidvector */

	/* variable length parameters / constants */
	cl_uint		length;		/* total length of parambuf */
	cl_uint		nparams;	/* number of parameters */
	cl_uint		poffset[FLEXIBLE_ARRAY_MEMBER];	/* offset of params */
} kern_parambuf;

STATIC_INLINE(void *)
kparam_get_value(kern_parambuf *kparams, cl_uint pindex)
{
	if (pindex >= kparams->nparams)
		return NULL;
	if (kparams->poffset[pindex] == 0)
		return NULL;
	return (char *)kparams + kparams->poffset[pindex];
}

STATIC_INLINE(cl_bool)
pointer_on_kparams(void *ptr, kern_parambuf *kparams)
{
	return kparams && ((char *)ptr >= (char *)kparams &&
					   (char *)ptr <  (char *)kparams + kparams->length);
}

/*
 * PostgreSQL varlena related definitions
 *
 * Unlike host code, device code cannot touch external and/or compressed
 * toast datum. All the format device code can understand is usual
 * in-memory form; 4-bytes length is put on the head and contents follows.
 * So, it is a responsibility of host code to decompress the toast values
 * if device code may access compressed varlena.
 * In case when device code touches unsupported format, calculation result
 * shall be postponed to calculate on the host side.
 *
 * Note that it is harmless to have external and/or compressed toast datam
 * unless it is NOT referenced in the device code. It can understand the
 * length of these values, unlike contents.
 */
typedef struct varlena		varlena;
#ifndef POSTGRES_H
struct varlena {
	cl_char		vl_len_[4];	/* Do not touch this field directly! */
	cl_char		vl_dat[1];
};

#define VARHDRSZ			((int) sizeof(cl_int))
#define VARDATA(PTR)		VARDATA_4B(PTR)
#define VARSIZE(PTR)		VARSIZE_4B(PTR)
#define VARSIZE_EXHDR(PTR)	(VARSIZE(PTR) - VARHDRSZ)

#define VARSIZE_SHORT(PTR)	VARSIZE_1B(PTR)
#define VARDATA_SHORT(PTR)	VARDATA_1B(PTR)

typedef union
{
	struct						/* Normal varlena (4-byte length) */
	{
		cl_uint		va_header;
		cl_char		va_data[1];
    }		va_4byte;
	struct						/* Compressed-in-line format */
	{
		cl_uint		va_header;
		cl_uint		va_rawsize;	/* Original data size (excludes header) */
		cl_char		va_data[1];	/* Compressed data */
	}		va_compressed;
} varattrib_4b;

typedef struct
{
	cl_uchar	va_header;
	cl_char		va_data[1];		/* Data begins here */
} varattrib_1b;

/* inline portion of a short varlena pointing to an external resource */
typedef struct
{
	cl_uchar    va_header;		/* Always 0x80 or 0x01 */
	cl_uchar	va_tag;			/* Type of datum */
	cl_char		va_data[1];		/* Data (of the type indicated by va_tag) */
} varattrib_1b_e;

typedef enum vartag_external
{
	VARTAG_INDIRECT = 1,
	VARTAG_ONDISK = 18
} vartag_external;

#define VARHDRSZ_SHORT			offsetof(varattrib_1b, va_data)
#define VARATT_SHORT_MAX		0x7F

typedef struct varatt_external
{
	cl_int		va_rawsize;		/* Original data size (includes header) */
	cl_int		va_extsize;		/* External saved size (doesn't) */
	cl_int		va_valueid;		/* Unique ID of value within TOAST table */
	cl_int		va_toastrelid;	/* RelID of TOAST table containing it */
} varatt_external;

typedef struct varatt_indirect
{
	hostptr_t	pointer;	/* Host pointer to in-memory varlena */
} varatt_indirect;

#define VARTAG_SIZE(tag) \
	((tag) == VARTAG_INDIRECT ? sizeof(varatt_indirect) :	\
	 (tag) == VARTAG_ONDISK ? sizeof(varatt_external) :		\
	 0 /* should not happen */)

#define VARHDRSZ_EXTERNAL		offsetof(varattrib_1b_e, va_data)
#define VARTAG_EXTERNAL(PTR)	VARTAG_1B_E(PTR)
#define VARSIZE_EXTERNAL(PTR)	\
	(VARHDRSZ_EXTERNAL + VARTAG_SIZE(VARTAG_EXTERNAL(PTR)))

/*
 * compressed varlena format
 */
typedef struct toast_compress_header
{
	cl_int		vl_len_;	/* varlena header (do not touch directly!) */
	cl_int		rawsize;
} toast_compress_header;

#define TOAST_COMPRESS_HDRSZ		((cl_int)sizeof(toast_compress_header))
#define TOAST_COMPRESS_RAWSIZE(ptr)				\
	(((toast_compress_header *) (ptr))->rawsize)
#define TOAST_COMPRESS_RAWDATA(ptr)				\
	(((char *) (ptr)) + TOAST_COMPRESS_HDRSZ)
#define TOAST_COMPRESS_SET_RAWSIZE(ptr, len)	\
	(((toast_compress_header *) (ptr))->rawsize = (len))

/* basic varlena macros */
#define VARATT_IS_4B(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x01) == 0x00)
#define VARATT_IS_4B_U(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x03) == 0x00)
#define VARATT_IS_4B_C(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x03) == 0x02)
#define VARATT_IS_1B(PTR) \
	((((varattrib_1b *) (PTR))->va_header & 0x01) == 0x01)
#define VARATT_IS_1B_E(PTR) \
	((((varattrib_1b *) (PTR))->va_header) == 0x01)
#define VARATT_IS_COMPRESSED(PTR)		VARATT_IS_4B_C(PTR)
#define VARATT_IS_EXTERNAL(PTR)			VARATT_IS_1B_E(PTR)
#define VARATT_IS_EXTERNAL_ONDISK(PTR)		\
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_ONDISK)
#define VARATT_IS_EXTERNAL_INDIRECT(PTR)	\
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_INDIRECT)
#define VARATT_IS_SHORT(PTR)			VARATT_IS_1B(PTR)
#define VARATT_IS_EXTENDED(PTR)			(!VARATT_IS_4B_U(PTR))
#define VARATT_NOT_PAD_BYTE(PTR) 		(*((cl_uchar *) (PTR)) != 0)

#define VARSIZE_4B(PTR)						\
	((__Fetch(&((varattrib_4b *)(PTR))->va_4byte.va_header)>>2) & 0x3FFFFFFF)
#define VARSIZE_1B(PTR) \
	((((varattrib_1b *) (PTR))->va_header >> 1) & 0x7F)
#define VARTAG_1B_E(PTR) \
	(((varattrib_1b_e *) (PTR))->va_tag)

#define VARRAWSIZE_4B_C(PTR)	\
	__Fetch(&((varattrib_4b *) (PTR))->va_compressed.va_rawsize)

#define VARSIZE_ANY_EXHDR(PTR) \
	(VARATT_IS_1B_E(PTR) ? VARSIZE_EXTERNAL(PTR)-VARHDRSZ_EXTERNAL : \
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR)-VARHDRSZ_SHORT :			 \
	  VARSIZE_4B(PTR)-VARHDRSZ))

#define VARSIZE_ANY(PTR)							\
	(VARATT_IS_1B_E(PTR) ? VARSIZE_EXTERNAL(PTR) :	\
	 (VARATT_IS_1B(PTR) ? VARSIZE_1B(PTR) :			\
	  VARSIZE_4B(PTR)))

#define VARDATA_4B(PTR)	(((varattrib_4b *) (PTR))->va_4byte.va_data)
#define VARDATA_1B(PTR)	(((varattrib_1b *) (PTR))->va_data)
#define VARDATA_ANY(PTR) \
	(VARATT_IS_1B(PTR) ? VARDATA_1B(PTR) : VARDATA_4B(PTR))

#define SET_VARSIZE(PTR, len)						\
	(((varattrib_4b *)(PTR))->va_4byte.va_header = (((cl_uint) (len)) << 2))
#endif	/* POSTGRES_H */

#ifndef ARRAY_H
/*
 * Definitions of array internal of PostgreSQL
 */
typedef struct
{
	/*
	 * NOTE: We assume 4bytes varlena header for array type. It allows
	 * aligned references to the array elements. Unlike CPU side, we
	 * cannot have extra malloc to ensure 4bytes varlena header. It is
	 * the reason why our ScalarArrayOp implementation does not support
	 * array data type referenced by Var node; which is potentially has
	 * short format.
	 */
	cl_uint		vl_len_;		/* don't touch this field */
	cl_int		ndim;			/* # of dimensions */
	cl_int		dataoffset;		/* offset to data, or 0 if no bitmap */
	cl_uint		elemtype;		/* element type OID */
} ArrayType;

typedef struct
{
	cl_int		ndim;			/* # of dimensions */
	cl_int		dataoffset;		/* offset to data, or 0 if no bitmap */
	cl_uint		elemtype;		/* element type OID */
} ArrayTypeData;

#define ARR_SIZE(a)			VARSIZE_ANY(a)
#define ARR_BODY(a)			((ArrayTypeData *)VARDATA_ANY(a))
#define ARR_NDIM(a)			__Fetch(&ARR_BODY(a)->ndim)
#define ARR_DATAOFFSET(a)	__Fetch(&ARR_BODY(a)->dataoffset)
#define ARR_HASNULL(a)		(ARR_DATAOFFSET(a) != 0)
#define ARR_ELEMTYPE(a)		__Fetch(&ARR_BODY(a)->elemtype)
#define ARR_DIMS(a)												\
	((int *)((char *)VARDATA_ANY(a) + sizeof(ArrayTypeData)))
#define ARR_LBOUND(a)	(ARR_DIMS(a) + ARR_NDIM(a))
#define ARR_NULLBITMAP(a)										\
	(ARR_HASNULL(a) ? (char *)(ARR_DIMS(a) + 2 * ARR_NDIM(a)) : (char *)NULL)
#define ARR_DATA_PTR(a)											\
	((char *)VARDATA_ANY(a) +									\
	 (ARR_HASNULL(a) ? (ARR_DATAOFFSET(a) - VARHDRSZ)			\
	  : (sizeof(ArrayTypeData) + 2 * sizeof(int) * ARR_NDIM(a))))

/*
 * The total array header size (in bytes) for an array with the specified
 * number of dimensions and total number of items.
 * NOTE: This macro assume 4-bytes varlena header
 */
#define ARR_OVERHEAD_NONULLS(ndims)					\
	MAXALIGN(sizeof(ArrayType) + 2 * sizeof(int) * (ndims))
#define ARR_OVERHEAD_WITHNULLS(ndims, nitems)		\
	MAXALIGN(sizeof(ArrayType) + 2 * sizeof(int) * (ndims) +	\
			 ((nitems) + 7) / 8)

#endif /* ARRAY_H */

/* ----------------------------------------------------------------
 *
 * About GPU Projection Support
 *
 * A typical projection code path is below:
 *
 * 1. Extract values from heap-tuple or column-store onto tup_dclass[] and
 *    tup_values[] array, and calculate length of the new heap-tuple.
 * 2. Allocation of the destination buffer, per threads-group
 * 3. Write out the heap-tuple
 *
 * Step-1 is usually handled by auto-generated code. In some case, it is not
 * reasonable to extract values to in-storage format prior to allocation of
 * the destination buffer, like a long text value that references a source
 * buffer in Apache Arrow.
 * Right now, we pay attention on simple varlena (Binary of Arrow that is
 * bytes in PG, and Utf8 of Arrow that is text in PG), and array of fixed-
 * length values (List of Arrow).
 * If tup_values[] hold a pointer to pg_varlena_t or pg_array_t, not raw-
 * varlena image, tup_dclass[] will have special flag to inform indirect
 * reference to the value.
 *
 * pg_XXXX_datum_ref() routine of types are responsible to transform disk
 * format to internal representation.
 * pg_XXXX_datum_store() routine of types are also responsible to transform
 * internal representation to disk format. We need to pay attention on
 * projection stage. If and when GPU code tries to store expressions which
 * are not simple Var, Const or Param, these internal representation must
 * be written to extra-buffer first.
 *
 * Also note that KDS_FORMAT_SLOT is designed to have compatible layout to
 * pair of tup_dclass[] / tup_values[] array if all the items have NULL or
 * NORMAL state. Other state should be normalized prior to CPU writeback.
 *
 * ----------------------------------------------------------------
 */
#define DATUM_CLASS__NORMAL		0	/* datum is normal value */
#define DATUM_CLASS__NULL		1	/* datum is NULL */
#define DATUM_CLASS__VARLENA	2	/* datum is pg_varlena_t reference */
#define DATUM_CLASS__ARRAY		3	/* datum is pg_array_t reference */
#define DATUM_CLASS__COMPOSITE	4	/* datum is pg_composite_t reference */
#define DATUM_CLASS__GEOMETRY	5	/* datum is pg_geometry_t reference */

/*
 * device functions in cuda_common.fatbin
 */
#ifdef __CUDACC__
DEVICE_FUNCTION(cl_uint)
pg_hash_any(const cl_uchar *k, cl_int keylen);
#endif /* __CUDACC__ */

/*
 * Macro to extract a heap-tuple
 *
 * usage:
 * char   *addr;
 *
 * EXTRACT_HEAP_TUPLE_BEGIN(kds, htup, addr)
 *  -> addr shall point the device pointer of the first field, or NULL
 * EXTRACT_HEAP_TUPLE_NEXT(addr)
 *  -> addr shall point the device pointer of the second field, or NULL
 *     :
 * EXTRACT_HEAP_TUPLE_END()
 *
 * EXTRACT_HEAP_READ_XXXX()
 *  -> load raw values to dclass[]/values[], and update extras[]
 */
#define EXTRACT_HEAP_TUPLE_BEGIN(ADDR,kds,htup)							\
	do {																\
		kern_colmeta   *__cmeta;										\
		cl_uint			__colidx = 0;									\
		cl_uint			__ncols;										\
		cl_uchar	   *__nullmap = NULL;								\
		char		   *__pos;											\
																		\
		if (!(htup))													\
			__ncols = 0;	/* to be considered as NULL */				\
		else															\
		{																\
			if (((htup)->t_infomask & HEAP_HASNULL) != 0)				\
				__nullmap = (htup)->t_bits;								\
			__ncols = Min((kds)->ncols,									\
						  (htup)->t_infomask2 & HEAP_NATTS_MASK);		\
			__pos = (char *)(htup) + (htup)->t_hoff;					\
			assert(__pos == (char *)MAXALIGN(__pos));					\
		}																\
		if (__colidx < __ncols &&										\
			(!__nullmap || !att_isnull(__colidx, __nullmap)))			\
		{																\
			__cmeta = &((kds)->colmeta[__colidx]);						\
			(ADDR) = __pos;												\
			__pos += (__cmeta->attlen > 0 ?								\
					  __cmeta->attlen :									\
					  VARSIZE_ANY(__pos));								\
		}																\
		else															\
			(ADDR) = NULL

#define EXTRACT_HEAP_TUPLE_NEXT(ADDR,kds)								\
		__colidx++;														\
		if (__colidx < __ncols &&										\
			(!__nullmap || !att_isnull(__colidx, __nullmap)))			\
		{																\
			__cmeta = &((kds)->colmeta[__colidx]);						\
																		\
			if (__cmeta->attlen > 0)									\
				__pos = (char *)TYPEALIGN(__cmeta->attalign, __pos);	\
			else if (!VARATT_NOT_PAD_BYTE(__pos))						\
				__pos = (char *)TYPEALIGN(__cmeta->attalign, __pos);	\
			(ADDR) = __pos;												\
			__pos += (__cmeta->attlen > 0 ?								\
					  __cmeta->attlen :									\
					  VARSIZE_ANY(__pos));								\
		}																\
		else															\
			(ADDR) = NULL

#define EXTRACT_HEAP_TUPLE_END()										\
	} while(0)

#define EXTRACT_HEAP_READ_8BIT(ADDR,ATT_DCLASS,ATT_VALUES)	 \
	do {													 \
		if (!(ADDR))										 \
			(ATT_DCLASS) = DATUM_CLASS__NULL;				 \
		else												 \
		{													 \
			(ATT_DCLASS) = DATUM_CLASS__NORMAL;				 \
			(ATT_VALUES) = *((cl_uchar *)(ADDR));			 \
		}												 	 \
	} while(0)

#define EXTRACT_HEAP_READ_16BIT(ADDR,ATT_DCLASS,ATT_VALUES)	 \
	do {													 \
		if (!(ADDR))										 \
			(ATT_DCLASS) = DATUM_CLASS__NULL;				 \
		else												 \
		{													 \
			(ATT_DCLASS) = DATUM_CLASS__NORMAL;				 \
			(ATT_VALUES) = *((cl_ushort *)(ADDR));			 \
		}												 	 \
	} while(0)

#define EXTRACT_HEAP_READ_32BIT(ADDR,ATT_DCLASS,ATT_VALUES)	 \
	do {													 \
		if (!(ADDR))										 \
			(ATT_DCLASS) = DATUM_CLASS__NULL;				 \
		else												 \
		{													 \
			(ATT_DCLASS) = DATUM_CLASS__NORMAL;				 \
			(ATT_VALUES) = *((cl_uint *)(ADDR));			 \
		}												 	 \
	} while(0)

#define EXTRACT_HEAP_READ_64BIT(ADDR,ATT_DCLASS,ATT_VALUES)	 \
	do {													 \
		if (!(ADDR))										 \
			(ATT_DCLASS) = DATUM_CLASS__NULL;				 \
		else												 \
		{													 \
			(ATT_DCLASS) = DATUM_CLASS__NORMAL;				 \
			(ATT_VALUES) = *((cl_ulong *)(ADDR));			 \
		}												 	 \
	} while(0)

#define EXTRACT_HEAP_READ_POINTER(ADDR,ATT_DCLASS,ATT_VALUES)	\
	do {											\
		if (!(ADDR))											\
			(ATT_DCLASS) = DATUM_CLASS__NULL;					\
		else													\
		{														\
			(ATT_DCLASS) = DATUM_CLASS__NORMAL;					\
			(ATT_VALUES) = PointerGetDatum(ADDR);				\
		}														\
	} while(0)

/*
 * Similar macro to extract IndexTuple
 */
#define EXTRACT_INDEX_TUPLE_BEGIN(ADDR,KDS,itup)					\
	do {															\
		const kern_colmeta *__cmeta = (KDS)->colmeta;				\
		cl_uint		__ncols = (KDS)->ncols;							\
		cl_uint		__colidx = 0;									\
		cl_uchar   *__nullmap = NULL;								\
		char	   *__pos;											\
																	\
		if (!(itup))												\
			__ncols = 0;											\
		else if (((itup)->t_info & INDEX_NULL_MASK) == 0)			\
			__pos = itup->data;										\
		else														\
		{															\
			__nullmap = (cl_uchar *)(itup)->data;					\
			__pos = (itup)->data + MAXALIGN(BITMAPLEN(__ncols));	\
		}															\
		if (__colidx < __ncols &&									\
			(!__nullmap || !att_isnull(__colidx, __nullmap)))		\
		{															\
			(ADDR) = __pos;											\
			__pos += (__cmeta->attlen > 0 ?							\
					  __cmeta->attlen :								\
					  VARSIZE_ANY(__pos));							\
		}															\
		else														\
			(ADDR) = NULL

#define EXTRACT_INDEX_TUPLE_NEXT(ADDR,KDS)							\
		__colidx++;													\
		if (__colidx < __ncols &&									\
			(!__nullmap || !att_isnull(__colidx, __nullmap)))		\
		{															\
			__cmeta = &(KDS)->colmeta[__colidx];					\
																	\
			if (__cmeta->attlen > 0)								\
				__pos = (char *)TYPEALIGN(__cmeta->attalign, __pos); \
			else if (!VARATT_NOT_PAD_BYTE(__pos))					 \
				__pos = (char *)TYPEALIGN(__cmeta->attalign, __pos); \
			(ADDR) = __pos;											\
			__pos += (__cmeta->attlen > 0 ?							\
					  __cmeta->attlen :								\
					  VARSIZE_ANY(__pos));							\
		}															\
		else														\
			(ADDR) = NULL
		
#define EXTRACT_INDEX_TUPLE_END()									\
	} while(0)

#ifdef __CUDACC__
/*
 * device functions to decompress a toast datum
 */
DEVICE_FUNCTION(size_t)
toast_raw_datum_size(kern_context *kcxt, varlena *attr);
DEVICE_FUNCTION(cl_int)
pglz_decompress(const char *source, cl_int slen,
				char *dest, cl_int rawsize);
DEVICE_FUNCTION(cl_bool)
toast_decompress_datum(char *buffer, cl_uint buflen,
					   const varlena *datum);
/*
 * device functions to reference a particular datum in a tuple
 */
DEVICE_FUNCTION(void *)
kern_get_datum_tuple(kern_colmeta *colmeta,
					 HeapTupleHeaderData *htup,
					 cl_uint colidx);

struct GstoreFdwSysattr;	/* not to include cuda_gstore.h here */
DEVICE_FUNCTION(void *)
kern_get_datum_column(kern_data_store *kds,
					  kern_data_extra *extra,
					  cl_uint colidx, cl_uint rowidx);
DEVICE_FUNCTION(cl_bool)
kern_check_visibility_column(kern_context *kcxt,
							 kern_data_store *kds,
							 cl_uint rowidx,
							 struct GstoreFdwSysattr *p_sysattr);
/*
 * device functions to form/deform HeapTuple
 */
DEVICE_FUNCTION(cl_uint)
__compute_heaptuple_size(kern_context *kcxt,
						 kern_colmeta *__cmeta,
						 cl_bool heap_hasoid,
						 cl_uint ncols,
						 cl_char *tup_dclass,
						 Datum   *tup_values);
DEVICE_FUNCTION(void)
deform_kern_heaptuple(cl_int	nattrs,
					  kern_colmeta *tup_attrs,
					  HeapTupleHeaderData *htup,
					  cl_char  *tup_dclass,
					  Datum	   *tup_values);
DEVICE_FUNCTION(cl_uint)
__form_kern_heaptuple(kern_context *kcxt,
					  void	   *buffer,			/* out */
					  cl_int	ncols,			/* in */
					  kern_colmeta *colmeta,	/* in */
					  cl_uint	comp_typeid,	/* in */
					  cl_int	comp_typmod,	/* in */
					  ItemPointerData *tup_self,/* in */
					  cl_char  *tup_dclass,		/* in */
					  Datum	   *tup_values);	/* in */
/*
 * support function for KDS_FORMAT_SLOT
 */
DEVICE_FUNCTION(cl_uint)
kds_slot_compute_extra(kern_context *kcxt,
					   kern_data_store *kds,
					   cl_char *tup_dclass,
					   Datum   *tup_values);
DEVICE_FUNCTION(void)
kds_slot_store_values(kern_context *kcxt,
					  kern_data_store *kds_dst,
					  cl_uint  dst_index,
					  char    *dst_extra,
					  cl_char *tup_dclass,
					  Datum   *tup_values);
/*
 * Reduction Operations
 */
DEVICE_FUNCTION(cl_uint)
pgstromStairlikeSum(cl_uint my_value, cl_uint *total_sum);
DEVICE_FUNCTION(cl_uint)
pgstromStairlikeBinaryCount(int predicate, cl_uint *total_count);
#endif	/* __CUDACC__ */

/* base type definitions and templates */
#include "cuda_basetype.h"
/* numeric functions support (must be here) */
#include "cuda_numeric.h"
/* text functions support (must be here) */
#include "cuda_textlib.h"
/* time functions support (must be here) */
#include "cuda_timelib.h"
/* static inline and c++ template functions */
#include "cuda_utils.h"

#endif	/* CUDA_COMMON_H */
