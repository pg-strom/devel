/*
 * arrow_ipc.h
 *
 * Definitions for Apache Arrow IPC stuff.
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
#ifndef ARROW_IPC_H
#define ARROW_IPC_H
#ifdef __PGSTROM_MODULE__
#include "pg_strom.h"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "arrow_defs.h"

/* several primitive definitions */
#ifndef offsetof
//#define offsetof(type,field)		((long) &((type *)0UL)->field)
#endif
#ifndef lengthof
//#define lengthof(array)				(sizeof(array) / sizeof((array)[0]))
#endif

#ifndef TYPEALIGN
#define TYPEALIGN(ALIGNVAL,LEN)					\
	(((uint64_t)(LEN) + ((ALIGNVAL) - 1)) & ~((uint64_t)((ALIGNVAL) - 1)))
#endif
#define ARROWALIGN(LEN)			TYPEALIGN(64,(LEN))

#ifndef Oid
typedef unsigned int	Oid;
#endif

typedef struct SQLbuffer		SQLbuffer;
typedef struct SQLtable			SQLtable;
typedef struct SQLfield			SQLfield;
typedef struct SQLdictionary	SQLdictionary;
typedef union  SQLtype			SQLtype;
typedef struct SQLtype__pgsql	SQLtype__pgsql;
typedef struct SQLtype__mysql	SQLtype__mysql;

struct SQLbuffer
{
	char	   *data;
	uint32_t	usage;
	uint32_t	length;
};

struct SQLtype__pgsql
{
	Oid			typeid;
	int			typmod;
	const char *typname;
	const char *typnamespace;
	short		typlen;
	bool		typbyval;
	char		typtype;
	uint8_t		typalign;
};

struct SQLtype__mysql
{
	int			typeid;
};

union SQLtype
{
	SQLtype__pgsql	pgsql;
	SQLtype__mysql	mysql;
};

struct SQLfield
{
	char	   *field_name;		/* name of the column, element or sub-field */
	SQLtype		sql_type;		/* attributes of SQL type */
	SQLfield   *element;		/* valid, if array type */
	int			nfields;		/* # of sub-fields of composite type */
	SQLfield   *subfields;	/* valid, if composite type */
	SQLdictionary *enumdict;	/* valid, if enum type */

	ArrowType	arrow_type;		/* type in apache arrow */
	const char *arrow_typename;	/* typename in apache arrow */
	/* data save as Apache Arrow datum */
	size_t	(*put_value)(SQLfield *attr, const char *addr, int sz);
	/* data buffers of the field */
	long		nitems;			/* number of rows */
	long		nullcount;		/* number of null values */
	SQLbuffer	nullmap;		/* null bitmap */
	SQLbuffer	values;			/* main storage of values */
	SQLbuffer	extra;			/* extra buffer for varlena */
	size_t		__curr_usage__;	/* current buffer usage */
	/* custom metadata(optional) */
	ArrowKeyValue *customMetadata;
	int			numCustomMetadata;
};
static inline size_t
sql_field_put_value(SQLfield *column, const char *addr, int sz)
{
	return (column->__curr_usage__ = column->put_value(column, addr, sz));
}

#ifndef FLEXIBLE_ARRAY_MEMBER
#define FLEXIBLE_ARRAY_MEMBER
#endif

struct SQLtable
{
	const char *filename;		/* output filename */
	int			fdesc;			/* output file descriptor */
	ArrowBlock *recordBatches;	/* recordBatches written in the past */
	int			numRecordBatches;
	ArrowBlock *dictionaries;	/* dictionaryBatches written in the past */
	int			numDictionaries;
	int			numFieldNodes;	/* # of FieldNode vector elements */
	int			numBuffers;		/* # of Buffer vector elements */
	ArrowKeyValue *customMetadata; /* custom metadata, if any */
	int			numCustomMetadata;
	SQLdictionary *sql_dict_list; /* list of SQLdictionary */
	size_t		segment_sz;		/* threshold of the memory usage */
	size_t		nitems;			/* number of items */
	int			nfields;		/* number of attributes */
	SQLfield columns[FLEXIBLE_ARRAY_MEMBER];
};

typedef struct hashItem		hashItem;
struct hashItem
{
	struct hashItem	*next;
	uint32_t	hash;
	uint32_t	index;
	uint32_t	label_sz;
	char		label[FLEXIBLE_ARRAY_MEMBER];
};

struct SQLdictionary
{
	struct SQLdictionary *next;
	int64_t		dict_id;
	SQLbuffer	values;
	SQLbuffer	extra;
	int			nloaded;	/* # of items loaded from existing file */
	int			nitems;
	int			nslots;		/* width of hash slot */
	hashItem   *hslots[FLEXIBLE_ARRAY_MEMBER];
};

/* arrow_write.c */
extern ssize_t	writeArrowSchema(SQLtable *table);
extern void		writeArrowDictionaryBatches(SQLtable *table);
extern int		writeArrowRecordBatch(SQLtable *table);
extern ssize_t	writeArrowFooter(SQLtable *table);
extern size_t	estimateArrowBufferLength(SQLfield *column, size_t nitems);

/* arrow_nodes.c */
extern void		__initArrowNode(ArrowNode *node, ArrowNodeTag tag);
#define initArrowNode(PTR,NAME)					\
	__initArrowNode((ArrowNode *)(PTR),ArrowNodeTag__##NAME)
extern char	   *dumpArrowNode(ArrowNode *node);
extern void		copyArrowNode(ArrowNode *dest, const ArrowNode *src);
extern void		readArrowFileDesc(int fdesc, ArrowFileInfo *af_info);
extern char	   *arrowTypeName(ArrowField *field);

/* arrow_pgsql.c */
extern int		assignArrowTypePgSQL(SQLfield *column,
									 const char *field_name,
									 Oid typeid,
									 int typmod,
									 const char *typname,
									 const char *typnamespace,
									 short typlen,
									 bool typbyval,
									 char typtype,
									 char typalign,
									 Oid typrelid,
									 Oid typelem,
									 const char *tz_name,
									 ArrowField *arrow_field);
/*
 * Error messages, and misc definitions for pg2arrow
 */
#ifdef __PGSTROM_MODULE__
#define Elog(fmt, ...)			elog(ERROR,(fmt),##__VA_ARGS__)
#else /* __PGSTROM_MODULE__ */
#define Elog(fmt, ...)								\
	do {											\
		fprintf(stderr,"%s:%d  " fmt "\n",			\
				__FILE__,__LINE__, ##__VA_ARGS__);	\
		exit(1);									\
	} while(0)
#endif /* __PGSTROM_MODULE__ */

/*
 * SQLbuffer related routines
 */
extern void	   *palloc(size_t sz);
extern void	   *palloc0(size_t sz);
extern char	   *pstrdup(const char *orig);
extern void	   *repalloc(void *ptr, size_t sz);

static inline void
sql_buffer_init(SQLbuffer *buf)
{
	buf->data = NULL;
	buf->usage = 0;
	buf->length = 0;
}

static inline void
sql_buffer_expand(SQLbuffer *buf, size_t required)
{
	if (buf->length < required)
	{
		void	   *data;
		size_t		length;

		if (buf->data == NULL)
		{
			length = (1UL << 20);	/* start from 1MB */
			while (length < required)
				length *= 2;
			data = palloc(length);
			if (!data)
				Elog("palloc: out of memory (sz=%zu)", length);
			buf->data   = data;
			buf->usage  = 0;
			buf->length = length;
		}
		else
		{
			length = buf->length;
			while (length < required)
				length *= 2;
			data = repalloc(buf->data, length);
			if (!data)
				Elog("repalloc: out of memory (sz=%zu)", length);
			buf->data = data;
			buf->length = length;
		}
	}
}

static inline void
sql_buffer_append(SQLbuffer *buf, const void *src, size_t len)
{
	sql_buffer_expand(buf, buf->usage + len);
	memcpy(buf->data + buf->usage, src, len);
	buf->usage += len;
	assert(buf->usage <= buf->length);
}

static inline void
sql_buffer_append_zero(SQLbuffer *buf, size_t len)
{
	sql_buffer_expand(buf, buf->usage + len);
	memset(buf->data + buf->usage, 0, len);
	buf->usage += len;
	assert(buf->usage <= buf->length);
}

static inline void
sql_buffer_setbit(SQLbuffer *buf, size_t __index)
{
	size_t		index = __index >> 3;
	int			mask  = (1 << (__index & 7));

	sql_buffer_expand(buf, index + 1);
	((uint8_t *)buf->data)[index] |= mask;
	if (buf->usage < index + 1)
		buf->usage = index + 1;
}

static inline void
sql_buffer_clrbit(SQLbuffer *buf, size_t __index)
{
	size_t		index = __index >> 3;
	int			mask  = (1 << (__index & 7));

	sql_buffer_expand(buf, index + 1);
	((uint8_t *)buf->data)[index] &= ~mask;
	if (buf->usage < index + 1)
		buf->usage = index + 1;
}

static inline void
sql_buffer_clear(SQLbuffer *buf)
{
	buf->usage = 0;
}

static inline void
sql_buffer_copy(SQLbuffer *dest, const SQLbuffer *orig)
{
	sql_buffer_init(dest);
	if (orig->data)
	{
		assert(orig->usage <= orig->length);
		sql_buffer_expand(dest, orig->length);
		memcpy(dest->data, orig->data, orig->usage);
		dest->usage = orig->usage;
	}
}
#endif	/* ARROW_IPC_H */
