/*
 * pcap2arrow.c
 *
 * multi-thread ultra fast packet capture and translator to Apache Arrow.
 *
 * Portions Copyright (c) 2021, HeteroDB Inc
 */
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pcap.h>
#include <pfring.h>		/* install libpcap-devel */
#include <pthread.h>	/* install pfring; see https://packages.ntop.org/ */
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "arrow_ipc.h"

#if 1
#define Assert(x)					assert(x)
#else
#define Assert(x)
#endif

#define __PCAP_PROTO__IPv4			0x0001
#define __PCAP_PROTO__IPv6			0x0002
#define __PCAP_PROTO__TCP			0x0010
#define __PCAP_PROTO__UDP			0x0020
#define __PCAP_PROTO__ICMP			0x0040

#define PCAP_PROTO__RAW_IPv4		(__PCAP_PROTO__IPv4)
#define PCAP_PROTO__TCP_IPv4		(__PCAP_PROTO__IPv4 | __PCAP_PROTO__TCP)
#define PCAP_PROTO__UDP_IPv4		(__PCAP_PROTO__IPv4 | __PCAP_PROTO__UDP)
#define PCAP_PROTO__ICMP_IPv4		(__PCAP_PROTO__IPv4 | __PCAP_PROTO__ICMP)
#define PCAP_PROTO__RAW_IPv6		(__PCAP_PROTO__IPv6)
#define PCAP_PROTO__TCP_IPv6		(__PCAP_PROTO__IPv6 | __PCAP_PROTO__TCP)
#define PCAP_PROTO__UDP_IPv6		(__PCAP_PROTO__IPv6 | __PCAP_PROTO__UDP)
#define PCAP_PROTO__ICMP_IPv6		(__PCAP_PROTO__IPv6 | __PCAP_PROTO__ICMP)
#define PCAP_PROTO__DEFAULT			(PCAP_PROTO__TCP_IPv4 |	\
									 PCAP_PROTO__UDP_IPv4 |	\
									 PCAP_PROTO__ICMP_IPv4)

#define PCAP_SWITCH__NEVER			0
#define PCAP_SWITCH__PER_MINUTE		1
#define PCAP_SWITCH__PER_HOUR		2
#define PCAP_SWITCH__PER_DAY		3
#define PCAP_SWITCH__PER_WEEK		4
#define PCAP_SWITCH__PER_MONTH		5

/* command-line options */
static char			   *input_devname = NULL;
static char			   *output_filename = "/tmp/pcap_%i_%y%m%d_%H%M%S.arrow";
static int				protocol_mask = PCAP_PROTO__DEFAULT;
static int				num_threads = -1;
static int				num_pcap_threads = -1;
static char			   *bpf_filter_rule = NULL;
static size_t			output_filesize_limit = ULONG_MAX;			/* No Limit */
static size_t			record_batch_threshold = (128UL << 20);		/* 128MB */
static bool				force_overwrite = false;
static bool				enable_direct_io = false;
static bool				only_headers = false;
static bool				composite_options = false;
static int				print_stat_interval = -1;

/*
 * definition of output Arrow files
 */
typedef struct
{
	int					refcnt;
	SQLtable			table;
} arrowFileDesc;
#define PCAP_SCHEMA_MAX_NFIELDS		50

#define MACADDR_LEN		6
#define IP4ADDR_LEN		4
#define IP6ADDR_LEN		16

static pthread_mutex_t *arrow_file_desc_locks;
static arrowFileDesc  **arrow_file_desc_array = NULL;
static uint64_t			arrow_file_desc_selector = 0;
static int				arrow_file_desc_nums = 1;

/* static variables for worker threads */
static pthread_mutex_t	arrow_workers_mutex;
static pthread_cond_t	arrow_workers_cond;
static bool			   *arrow_workers_completed;
static SQLtable		  **arrow_chunks_array;			/* chunk buffer per-thread */
static sem_t			pcap_worker_sem;
#ifndef DIRECT_IO_ALIGN
#define DIRECT_IO_ALIGN(x)		(((x) + 511UL) & ~511UL)
#endif /* DIRECT_IO_ALIGN */

/* static variable for PF-RING capture mode */
static pfring		  **pfring_desc_array = NULL;
static uint64_t			pfring_desc_selector = 0;
static int				pfring_desc_nums = -1;

/* static variables for PCAP file scan mode */
#define PCAP_MAGIC__HOST		0xa1b2c3d4U
#define PCAP_MAGIC__SWAP		0xd4c3b2a1U
#define PCAP_MAGIC__HOST_NS		0xa1b23c4dU
#define PCAP_MAGIC__SWAP_NS		0x4d3cb2a1U

typedef struct
{
	pcap_t			   *pcap_handle;
	FILE			   *pcap_filp;
	const char		   *pcap_filename;
	char				pcap_errbuf[PCAP_ERRBUF_SIZE];
} pcapFileDesc;

static pcapFileDesc	   *pcap_file_desc_array = NULL;
static volatile int		pcap_file_desc_selector = 0;
static int				pcap_file_desc_nums = 0;

/* capture statistics */
static uint64_t			stat_raw_packet_length = 0;
static uint64_t			stat_ip4_packet_count = 0;
static uint64_t			stat_ip6_packet_count = 0;
static uint64_t			stat_tcp_packet_count = 0;
static uint64_t			stat_udp_packet_count = 0;
static uint64_t			stat_icmp_packet_count = 0;

/* other static variables */
static long				PAGESIZE;
static long				NCPUS;
static __thread long	worker_id = -1;
static volatile bool	do_shutdown = false;
#ifndef PAGE_ALIGN
#define PAGE_ALIGN(x)	(((uint64_t)(x) + PAGESIZE - 1) & ~(PAGESIZE - 1))
#endif /* PAGE_ALIGN */
#ifndef LONGALIGN
#define LONGALIGN(x)	(((uint64_t)(x) + 7UL) & ~7UL)
#endif
#ifndef INTALIGN
#define INTALIGN(x)		(((uint64_t)(x) + 3UL) & ~3UL)
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __ntoh16(x)		__builtin_bswap16(x)
#define __ntoh32(x)		__builtin_bswap32(x)
#define __ntoh64(x)		__builtin_bswap64(x)
#else
#define __ntoh16(x)		(x)
#define __ntoh32(x)		(x)
#define __ntoh64(x)		(x)
#endif

static inline void
pthreadMutexInit(pthread_mutex_t *mutex)
{
	if ((errno = pthread_mutex_init(mutex, NULL)) != 0)
		Elog("failed on pthread_mutex_init: %m");
}

static inline void
pthreadMutexLock(pthread_mutex_t *mutex)
{
	if ((errno = pthread_mutex_lock(mutex)) != 0)
		Elog("failed on pthread_mutex_lock: %m");
}

static inline void
pthreadMutexUnlock(pthread_mutex_t *mutex)
{
	if ((errno = pthread_mutex_unlock(mutex)) != 0)
        Elog("failed on pthread_mutex_unlock: %m");
}

static inline void
pthreadCondInit(pthread_cond_t *cond)
{
	if ((errno = pthread_cond_init(cond, NULL)) != 0)
        Elog("failed on pthread_cond_init: %m");
}

static inline void
pthreadCondWait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if ((errno = pthread_cond_wait(cond, mutex)) != 0)
		Elog("failed on pthread_cond_wait: %m");
}

static inline void
pthreadCondBroadcast(pthread_cond_t *cond)
{
	if ((errno = pthread_cond_broadcast(cond)) != 0)
		Elog("failed on pthread_cond_broadcast: %m");
}

/*
 * atomic operations
 */
static inline uint64_t
atomicRead64(const uint64_t *addr)
{
	return __atomic_load_n(addr, __ATOMIC_SEQ_CST);
}

static inline uint64_t
atomicAdd64(uint64_t *addr, uint64_t value)
{
	return __atomic_fetch_add(addr, value, __ATOMIC_SEQ_CST);
}

/*
 * SIGINT handler
 */
static void
on_sigint_handler(int signal)
{
	int		errno_saved = errno;
	int		i;

	do_shutdown = true;
	if (pfring_desc_array)
	{
		for (i=0; i < pfring_desc_nums; i++)
			pfring_breakloop(pfring_desc_array[i]);
	}
	if (pcap_file_desc_array)
	{
		for (i=0; i < pcap_file_desc_nums; i++)
		{
			pcap_t *pcap_handle = pcap_file_desc_array[i].pcap_handle;

			if (pcap_handle)
				pcap_breakloop(pcap_handle);
		}
	}
	errno = errno_saved;
}

/* ----------------------------------------------------------------
 *
 * Routines for PCAP Arrow Schema Definition
 *
 * ----------------------------------------------------------------
 */
static inline size_t
__buffer_usage_inline_type(SQLfield *column)
{
	size_t		usage;

	usage = ARROWALIGN(column->values.usage);
	if (column->nullcount > 0)
		usage += ARROWALIGN(column->nullmap.usage);
	return usage;
}

static inline size_t
__buffer_usage_varlena_type(SQLfield *column)
{
	size_t		usage;

	usage = (ARROWALIGN(column->values.usage) +
			 ARROWALIGN(column->extra.usage));
	if (column->nullcount > 0)
		usage += ARROWALIGN(column->nullmap.usage);
	return usage;
}

static inline void
__put_inline_null_value(SQLfield *column, size_t index, int sz)
{
	column->nullcount++;
	sql_buffer_clrbit(&column->nullmap, index);
	sql_buffer_append_zero(&column->values, sz);
}

static size_t
put_uint8_value(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(!addr || sz == sizeof(uint8_t));
	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint8_t));
	else
	{
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, addr, sizeof(uint8_t));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_uint16_value(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(!addr || sz == sizeof(uint16_t));
	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint16_t));
	else
	{
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, addr, sizeof(uint16_t));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_uint16_value_bswap(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(!addr || sz == sizeof(uint16_t));
	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint16_t));
	else
	{
		uint16_t	value = __ntoh16(*((uint16_t *)addr));

		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, &value, sz);
	}
	return __buffer_usage_inline_type(column);
}

#if 0
static size_t
put_uint32_value(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(!addr || sz == sizeof(uint32_t));
	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint32_t));
	else
	{
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, addr, sizeof(uint32_t));
	}
	return __buffer_usage_inline_type(column);
}
#endif

static size_t
put_uint32_value_bswap(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(!addr || sz == sizeof(uint32_t));
	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint32_t));
	else
	{
		uint32_t	value = __ntoh32(*((uint32_t *)addr));

		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, &value, sz);
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_timestamp_us_value(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;
	uint64_t	value;

	if (!addr)
		__put_inline_null_value(column, index, sizeof(uint64_t));
	else
	{
		Assert(sz == sizeof(struct timeval));
		value = (((struct timeval *)addr)->tv_sec * 1000000L +
				 ((struct timeval *)addr)->tv_usec);
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, &value, sizeof(uint64_t));
	}
    return __buffer_usage_inline_type(column);
}

static inline size_t
__put_fixed_size_binary_value_common(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	Assert(column->arrow_type.FixedSizeBinary.byteWidth == sz);
	if (!addr)
		__put_inline_null_value(column, index, sz);
	else
	{
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->values, addr, sz);
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_fixed_size_binary_macaddr_value(SQLfield *column, const char *addr, int sz)
{
	Assert(!addr || sz == MACADDR_LEN);
	return __put_fixed_size_binary_value_common(column, addr, MACADDR_LEN);
}

static size_t
put_fixed_size_binary_ip4addr_value(SQLfield *column, const char *addr, int sz)
{
	Assert(!addr || sz == IP4ADDR_LEN);
	return __put_fixed_size_binary_value_common(column, addr, IP4ADDR_LEN);
}

static size_t
put_fixed_size_binary_ip6addr_value(SQLfield *column, const char *addr, int sz)
{
	Assert(!addr || sz == IP6ADDR_LEN);
	return __put_fixed_size_binary_value_common(column, addr, IP6ADDR_LEN);
}

static size_t
put_variable_value(SQLfield *column, const char *addr, int sz)
{
	size_t		index = column->nitems++;

	if (index == 0)
		sql_buffer_append_zero(&column->values, sizeof(uint32_t));
	if (!addr)
	{
		column->nullcount++;
		sql_buffer_clrbit(&column->nullmap, index);
		sql_buffer_append(&column->values,
						  &column->extra.usage, sizeof(uint32_t));
	}
	else
	{
		sql_buffer_setbit(&column->nullmap, index);
		sql_buffer_append(&column->extra, addr, sz);
		sql_buffer_append(&column->values,
						  &column->extra.usage, sizeof(uint32_t));
	}
	return __buffer_usage_varlena_type(column);
}

typedef struct
{
	uint8_t		option_type;
	int			option_sz;
	const void *option_addr;
} option_item;

static size_t
put_composite_option_items(SQLfield *column, const char *addr, int sz)
{
	const option_item *ipv6_option = (const option_item *) addr;
	SQLfield   *subfields = column->subfields;
	size_t		row_index = column->nitems++;

	if (!addr)
	{
		column->nullcount++;
		sql_buffer_clrbit(&column->nullmap, row_index);
		sql_field_put_value(&subfields[0], NULL, 0);
		sql_field_put_value(&subfields[1], NULL, 0);
	}
	else
	{
		Assert(sz == sizeof(option_item));
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_field_put_value(&subfields[0],
							(const char *)&ipv6_option->option_type,
							sizeof(uint8_t));
		sql_field_put_value(&subfields[1],
							(const char *)ipv6_option->option_addr,
							ipv6_option->option_sz);
	}
	return (__buffer_usage_inline_type(column) +
			subfields[0].__curr_usage__ +
			subfields[1].__curr_usage__);
}

static size_t
put_array_option_items(SQLfield *column, const char *addr, int sz)
{
	SQLfield   *element = column->element;
	size_t		row_index = column->nitems++;

	if (row_index == 0)
		sql_buffer_append_zero(&column->values, sizeof(int32_t));
	if (!addr || sz == 0)
	{
		column->nullcount++;
		sql_buffer_clrbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &element->nitems, sizeof(int32_t));
	}
	else
	{
		const option_item *ipv6_options = (const option_item *) addr;
		int		i, nitems = sz / sizeof(option_item);

		Assert(sz == sizeof(option_item) * nitems);
		for (i=0; i < nitems; i++)
		{
			sql_field_put_value(element,
								(const char *)&ipv6_options[i],
								sizeof(option_item));
		}
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &element->nitems, sizeof(int32_t));
	}
	return __buffer_usage_inline_type(column) + element->__curr_usage__;
}

static void
arrowFieldAddCustomMetadata(SQLfield *column,
							const char *key,
							const char *value)
{
	ArrowKeyValue *kv;

	if (column->numCustomMetadata == 0)
	{
		Assert(column->customMetadata == NULL);
		column->customMetadata = palloc(sizeof(ArrowKeyValue));
	}
	else
	{
		size_t	sz = sizeof(ArrowKeyValue) * (column->numCustomMetadata + 1);

		Assert(column->customMetadata != NULL);
		column->customMetadata = repalloc(column->customMetadata, sz);
	}
	kv = &column->customMetadata[column->numCustomMetadata++];
	initArrowNode(&kv->node, KeyValue);
	kv->key = pstrdup(key);
	kv->_key_len = strlen(key);
	kv->value = pstrdup(value);
	kv->_value_len = strlen(value);
}

static void
arrowFieldInitAsUint8(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Int);
	column->arrow_type.Int.bitWidth = 8;
	column->arrow_type.Int.is_signed = false;
	column->put_value = put_uint8_value;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsUint16(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Int);
	column->arrow_type.Int.bitWidth = 16;
	column->arrow_type.Int.is_signed = false;
	column->put_value = put_uint16_value;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsUint16Bswap(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Int);
	column->arrow_type.Int.bitWidth = 16;
	column->arrow_type.Int.is_signed = false;
	column->put_value = put_uint16_value_bswap;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}

#if 0
static void
arrowFieldInitAsUint32(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Int);
	column->arrow_type.Int.bitWidth = 32;
	column->arrow_type.Int.is_signed = false;
	column->put_value = put_uint32_value;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}
#endif

static void
arrowFieldInitAsUint32Bswap(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Int);
	column->arrow_type.Int.bitWidth = 32;
	column->arrow_type.Int.is_signed = false;
	column->put_value = put_uint32_value_bswap;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsTimestampUs(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, Timestamp);
	column->arrow_type.Timestamp.unit = ArrowTimeUnit__MicroSecond;
	/* no timezone setting, right now */
	column->put_value = put_timestamp_us_value;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsMacAddr(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, FixedSizeBinary);
	column->arrow_type.FixedSizeBinary.byteWidth = MACADDR_LEN;
	column->put_value = put_fixed_size_binary_macaddr_value;
	column->field_name = pstrdup(field_name);
	arrowFieldAddCustomMetadata(column, "pg_type", "pg_catalog.macaddr");

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsIP4Addr(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, FixedSizeBinary);
	column->arrow_type.FixedSizeBinary.byteWidth = IP4ADDR_LEN;
	column->put_value = put_fixed_size_binary_ip4addr_value;
	column->field_name = pstrdup(field_name);
	arrowFieldAddCustomMetadata(column, "pg_type", "pg_catalog.inet");

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsIP6Addr(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, FixedSizeBinary);
	column->arrow_type.FixedSizeBinary.byteWidth = IP6ADDR_LEN;
	column->put_value = put_fixed_size_binary_ip6addr_value;
	column->field_name = pstrdup(field_name);
	arrowFieldAddCustomMetadata(column, "pg_type", "pg_catalog.inet");

	table->numFieldNodes++;
	table->numBuffers += 2;
}

static void
arrowFieldInitAsBinary(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];

	memset(column, 0, sizeof(SQLfield));
    initArrowNode(&column->arrow_type, Binary);
	column->put_value = put_variable_value;
	column->field_name = pstrdup(field_name);

	table->numFieldNodes++;
	table->numBuffers += 3;
}

/*
 * OptionItems is List::<Uint8,Binary>; array of composite type
 */
static void
arrowFieldInitAsOptionItems(SQLtable *table, int cindex, const char *field_name)
{
	SQLfield   *column = &table->columns[cindex];
	SQLfield   *element = palloc0(sizeof(SQLfield));
	SQLfield   *subfields = palloc0(2 * sizeof(SQLfield));
	char		namebuf[100];

	/* subfields of the composite type */
	initArrowNode(&subfields[0].arrow_type, Int);
	subfields[0].arrow_type.Int.bitWidth = 8;
	subfields[0].arrow_type.Int.is_signed = false;
	subfields[0].put_value = put_uint8_value;
	subfields[0].field_name = "opt_code";

	initArrowNode(&subfields[1].arrow_type, Binary);
	subfields[1].put_value = put_variable_value;
	subfields[1].field_name = "opt_data";

	/* the composite type */
	snprintf(namebuf, sizeof(namebuf), "__%s", field_name);
	initArrowNode(&element->arrow_type, Struct);
	element->put_value = put_composite_option_items;
	element->field_name = pstrdup(namebuf);
	element->nfields = 2;
	element->subfields = subfields;

	/* list of the composite type */
	memset(column, 0, sizeof(SQLfield));
	initArrowNode(&column->arrow_type, List);
	column->put_value = put_array_option_items;
	column->field_name = pstrdup(field_name);
	column->element = element;

	table->numFieldNodes += 4;
    table->numBuffers += (2 + 3 + 1 + 2);
}

/* basic ethernet frame */
static int arrow_cindex__timestamp			= -1;
static int arrow_cindex__dst_mac			= -1;
static int arrow_cindex__src_mac			= -1;
static int arrow_cindex__ether_type			= -1;
/* IPv4 headers */
static int arrow_cindex__tos				= -1;
static int arrow_cindex__ip_length			= -1;
static int arrow_cindex__identifier			= -1;
static int arrow_cindex__fragment			= -1;
static int arrow_cindex__ttl				= -1;
static int arrow_cindex__ip_checksum		= -1;
static int arrow_cindex__src_addr			= -1;
static int arrow_cindex__dst_addr			= -1;
static int arrow_cindex__ip_options			= -1;
/* IPv6 headers */
static int arrow_cindex__traffic_class		= -1;
static int arrow_cindex__flow_label			= -1;
static int arrow_cindex__hop_limit			= -1;
static int arrow_cindex__src_addr6			= -1;
static int arrow_cindex__dst_addr6			= -1;
static int arrow_cindex__ip6_options		= -1;
/* transport layer common */
static int arrow_cindex__protocol			= -1;
static int arrow_cindex__src_port			= -1;
static int arrow_cindex__dst_port			= -1;
/* TCP headers */
static int arrow_cindex__seq_nr				= -1;
static int arrow_cindex__ack_nr				= -1;
static int arrow_cindex__tcp_flags			= -1;
static int arrow_cindex__window_sz			= -1;
static int arrow_cindex__tcp_checksum		= -1;
static int arrow_cindex__urgent_ptr			= -1;
static int arrow_cindex__tcp_options		= -1;
/* UDP headers */
static int arrow_cindex__udp_length			= -1;
static int arrow_cindex__udp_checksum		= -1;
/* ICMP headers */
static int arrow_cindex__icmp_type			= -1;
static int arrow_cindex__icmp_code			= -1;
static int arrow_cindex__icmp_checksum		= -1;
/* Payload */
static int arrow_cindex__payload			= -1;

static int
arrowPcapSchemaInit(SQLtable *table)
{
	int		j = 0;

#define __ARROW_FIELD_INIT(__NAME, __TYPE)					\
	do {													\
		if (arrow_cindex__##__NAME < 0)						\
			arrow_cindex__##__NAME = j;						\
		else												\
			Assert(arrow_cindex__##__NAME == j);			\
		arrowFieldInitAs##__TYPE(table, j++, (#__NAME));	\
	} while(0)

	/* timestamp and mac-address */
    __ARROW_FIELD_INIT(timestamp,	TimestampUs);
    __ARROW_FIELD_INIT(dst_mac,		MacAddr);
    __ARROW_FIELD_INIT(src_mac,		MacAddr);
    __ARROW_FIELD_INIT(ether_type,	Uint16);	/* byte swap by caller */

	/* IPv4 */
	if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
	{
		__ARROW_FIELD_INIT(tos,			Uint8);
		__ARROW_FIELD_INIT(ip_length,	Uint16Bswap);
		__ARROW_FIELD_INIT(identifier,	Uint16Bswap);
		__ARROW_FIELD_INIT(fragment,	Uint16Bswap);
		__ARROW_FIELD_INIT(ttl,			Uint8);
		__ARROW_FIELD_INIT(ip_checksum,	Uint16Bswap);
		__ARROW_FIELD_INIT(src_addr,	IP4Addr);
		__ARROW_FIELD_INIT(dst_addr,	IP4Addr);
		if (composite_options)
			__ARROW_FIELD_INIT(ip_options, OptionItems);
		else
			__ARROW_FIELD_INIT(ip_options, Binary);
	}
	/* IPv6 */
	if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
	{
		__ARROW_FIELD_INIT(traffic_class, Uint8);
		__ARROW_FIELD_INIT(flow_label,  Uint32Bswap);
		__ARROW_FIELD_INIT(hop_limit,   Uint8);
		__ARROW_FIELD_INIT(src_addr6,	IP6Addr);
		__ARROW_FIELD_INIT(dst_addr6,	IP6Addr);
		if (composite_options)
			__ARROW_FIELD_INIT(ip6_options, OptionItems);
		else
			__ARROW_FIELD_INIT(ip6_options, Binary);
	}
	/* IPv4 or IPv6 */
	if ((protocol_mask & (__PCAP_PROTO__IPv4 |
						  __PCAP_PROTO__IPv6)) != 0)
	{
		__ARROW_FIELD_INIT(protocol,    Uint8);
	}
	
	/* TCP or UDP */
	if ((protocol_mask & (__PCAP_PROTO__TCP |
						  __PCAP_PROTO__UDP)) != 0)
	{
		__ARROW_FIELD_INIT(src_port,	Uint16);	/* byte swap by caller */
		__ARROW_FIELD_INIT(dst_port,	Uint16);	/* byte swap by caller */
	}
	/* TCP */
	if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
	{
		__ARROW_FIELD_INIT(seq_nr,		Uint32Bswap);
		__ARROW_FIELD_INIT(ack_nr,		Uint32Bswap);
		__ARROW_FIELD_INIT(tcp_flags,	Uint16);	/* byte swap by caller */
		__ARROW_FIELD_INIT(window_sz,	Uint16Bswap);
		__ARROW_FIELD_INIT(tcp_checksum,Uint16Bswap);
		__ARROW_FIELD_INIT(urgent_ptr,	Uint16Bswap);
		if (composite_options)
			__ARROW_FIELD_INIT(tcp_options, OptionItems);
		else
			__ARROW_FIELD_INIT(tcp_options,	Binary);
	}
	/* UDP */
	if ((protocol_mask & __PCAP_PROTO__UDP) == __PCAP_PROTO__UDP)
	{
		__ARROW_FIELD_INIT(udp_length,   Uint16Bswap);
		__ARROW_FIELD_INIT(udp_checksum, Uint16Bswap);
	}
	/* ICMP */
	if ((protocol_mask & __PCAP_PROTO__ICMP) == __PCAP_PROTO__ICMP)
	{
		__ARROW_FIELD_INIT(icmp_type,	  Uint8);
		__ARROW_FIELD_INIT(icmp_code,	  Uint8);
		__ARROW_FIELD_INIT(icmp_checksum, Uint16Bswap);
	}
	/* remained data - payload */
	if (!only_headers)
		__ARROW_FIELD_INIT(payload,		  Binary);
#undef __ARROW_FIELD_INIT
	table->nfields = j;

	return j;
}

#define __FIELD_PUT_VALUE_DECL									\
	SQLfield   *__field;										\
	size_t      usage = 0
#define __FIELD_PUT_VALUE(NAME,ADDR,SZ)							\
	Assert(arrow_cindex__##NAME >= 0);							\
	__field = &chunk->columns[arrow_cindex__##NAME];			\
	usage += sql_field_put_value(__field, (const char *)(ADDR),(SZ))

/*
 * handlePacketRawEthernet
 */
static const u_char *
handlePacketRawEthernet(SQLtable *chunk,
						struct pfring_pkthdr *hdr,
						const u_char *buf, uint16_t *p_ether_type)
{
	__FIELD_PUT_VALUE_DECL;
	struct __raw_ether {
		u_char		dst_mac[6];
		u_char		src_mac[6];
		uint16_t	ether_type;
	}		   *raw_ether = (struct __raw_ether *)buf;

	__FIELD_PUT_VALUE(timestamp, &hdr->ts, sizeof(hdr->ts));
	if (hdr->caplen < sizeof(struct __raw_ether))
	{
		__FIELD_PUT_VALUE(dst_mac, NULL, 0);
		__FIELD_PUT_VALUE(src_mac, NULL, 0);
		__FIELD_PUT_VALUE(ether_type, NULL, 0);
		return NULL;
	}
	__FIELD_PUT_VALUE(dst_mac, raw_ether->dst_mac, MACADDR_LEN);
	__FIELD_PUT_VALUE(src_mac, raw_ether->src_mac, MACADDR_LEN);
	*p_ether_type = __ntoh16(raw_ether->ether_type);
	__FIELD_PUT_VALUE(ether_type, p_ether_type, sizeof(uint16_t));

	chunk->usage = usage;	/* raw-ethernet shall be 1st call */
	
	return buf + sizeof(struct __raw_ether);
}

/*
 * handlePacketIPv4Header
 */
static const u_char *
handlePacketIPv4Header(SQLtable *chunk,
					   const u_char *buf, size_t sz, int *p_proto)
{
	__FIELD_PUT_VALUE_DECL;
	struct __ipv4_head {
		uint8_t		version;	/* 4bit of version means header-size */
		uint8_t		tos;
		uint16_t	ip_length;
		uint16_t	identifier;
		uint16_t	fragment;
		uint8_t		ttl;
		uint8_t		protocol;
		uint16_t	ip_checksum;
		uint32_t	src_addr;
		uint32_t	dst_addr;
		u_char		ip_options[0];
	}		   *ipv4 = (struct __ipv4_head *)buf;
	uint16_t	head_sz;

	if (!buf || sz < 20)
		goto fillup_by_null;
	/* 1st octet is IP version (4) and header size */
	if ((ipv4->version & 0xf0) != 0x40)
		goto fillup_by_null;
	head_sz = 4 * (ipv4->version & 0x0f);
	if (head_sz > sz)
		goto fillup_by_null;

	*p_proto = ipv4->protocol;
	__FIELD_PUT_VALUE(tos,         &ipv4->tos,         sizeof(uint8_t));
	__FIELD_PUT_VALUE(ip_length,   &ipv4->ip_length,   sizeof(uint16_t));
	__FIELD_PUT_VALUE(identifier,  &ipv4->identifier,  sizeof(uint16_t));
	__FIELD_PUT_VALUE(fragment,    &ipv4->fragment,    sizeof(uint16_t));
	__FIELD_PUT_VALUE(ttl,         &ipv4->ttl,         sizeof(uint8_t));
	__FIELD_PUT_VALUE(ip_checksum, &ipv4->ip_checksum, sizeof(uint16_t));
	__FIELD_PUT_VALUE(src_addr,    &ipv4->src_addr,    sizeof(uint32_t));
	__FIELD_PUT_VALUE(dst_addr,    &ipv4->dst_addr,    sizeof(uint32_t));
	if (head_sz <= offsetof(struct __ipv4_head, ip_options))
	{
		__FIELD_PUT_VALUE(ip_options, NULL, 0);
	}
	else if (composite_options)
	{
		option_item 	ipv4_options[40];
		int				nitems = 0;
		const u_char   *pos = ipv4->ip_options;
		const u_char   *end = buf + head_sz;

		/* https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml */
		while (pos < end)
		{
			int			code = *pos++;

			if (code == 0)	/* End of Options List */
				break;
			if (code == 1)	/* No Operation */
				continue;
			/* Other options have length field in the 2nd octet */
			if (pos < end)
			{
				option_item	   *item = &ipv4_options[nitems++];
				item->option_type = code;
				item->option_sz = (*pos++) - 2;
				item->option_addr = pos;
				pos += item->option_sz;
			}
		}

		if (nitems == 0)
		{
			__FIELD_PUT_VALUE(ip_options, NULL, 0);
		}
		else
		{
			__FIELD_PUT_VALUE(ip_options, ipv4_options,
							  sizeof(option_item) * nitems);
		}
	}
	else
	{
		__FIELD_PUT_VALUE(ip_options, ipv4->ip_options,
						  head_sz - offsetof(struct __ipv4_head, ip_options));
	}
	chunk->usage += usage;

	return buf + head_sz;

fillup_by_null:
	__FIELD_PUT_VALUE(tos, NULL, 0);
	__FIELD_PUT_VALUE(ip_length, NULL, 0);
	__FIELD_PUT_VALUE(identifier, NULL, 0);
	__FIELD_PUT_VALUE(fragment, NULL, 0);
	__FIELD_PUT_VALUE(ttl, NULL, 0);
	__FIELD_PUT_VALUE(ip_checksum, NULL, 0);
	__FIELD_PUT_VALUE(src_addr, NULL, 0);
	__FIELD_PUT_VALUE(dst_addr, NULL, 0);
	__FIELD_PUT_VALUE(ip_options, NULL, 0);
	chunk->usage += usage;

	return NULL;
}

/*
 * handlePacketIPv6Options
 */
static const u_char *
handlePacketIPv6Options(SQLtable *chunk,
						uint8_t next,
						const u_char *pos,
						const u_char *end,
						int *p_proto)
{
	__FIELD_PUT_VALUE_DECL;
	option_item ipv6_options[256];
	int		sz, nitems = 0;

	/* walk on the IPv6 options headers */
	while (pos < end)
	{
		option_item *item;

		switch (next)
		{
			case 0:		/* Hop-by-Hop */
			case 43:	/* Routine */
			case 44:	/* Fragment */
			case 60:	/* Destination Options */
			case 135:	/* Mobility */
			case 139:	/* Host Identity Protocol */
			case 140:	/* Shim6 Protocol */
				{
					const struct {
						uint8_t		next;
						uint8_t		length;
						char		data[1];
					}  *opts = (const void *)pos;
					sz = 8 * opts->length + 8;
					if (pos + sz > end)
						break;
					item = &ipv6_options[nitems++];
					item->option_type = next;
					item->option_sz = (sz - 2);
					item->option_addr = opts->data;
					pos += sz;
					next = opts->next;
				}
				break;

			case 51:	/* Authentication Header (AH) */
				{
					const struct {
						uint8_t		next;
						uint8_t		length;
						uint16_t	reserved;
						char		data[1];
					}  *__ah = (const void *)pos;
					sz = 4 * __ah->length + 8;
					if (pos + sz > end)
						break;
					item = &ipv6_options[nitems++];
					item->option_type = next;
					item->option_sz = sz - 4;
					item->option_addr = __ah->data;
					pos += LONGALIGN(sz);
					next = __ah->next;
				}
				break;

			default:
				goto out;
		}
	}
out:
	if (pos == end)
	{
		__FIELD_PUT_VALUE(ip6_options, NULL, 0);
	}
	else if (composite_options)
	{
		__FIELD_PUT_VALUE(ip6_options, ipv6_options,
						  sizeof(ipv6_options) * nitems);
	}
	else
	{
		__FIELD_PUT_VALUE(ip6_options, pos, end - pos);
	}
	chunk->usage += usage;
	return pos;
}

/*
 * handlePacketIPv6Header
 */
static const u_char *
handlePacketIPv6Header(SQLtable *chunk,
					   const u_char *buf, size_t sz, int *p_proto)
{
	__FIELD_PUT_VALUE_DECL;
	struct __ipv6_head {
		uint8_t		v0;
		uint8_t		v1;
		uint8_t		v2;
		uint8_t		v3;
		uint16_t	length;
		uint8_t		next;
		uint8_t		hop_limit;
		uint8_t		src_addr6[IP6ADDR_LEN];
		uint8_t		dst_addr6[IP6ADDR_LEN];
		u_char		data[1];
	}  *ipv6 = (struct __ipv6_head *) buf;
	uint8_t			traffic_class;
	uint32_t		flow_label;
	const u_char   *end = buf + sz;

	if (!buf || sz < 40)
		goto fillup_by_null;

	if ((ipv6->v0 & 0xf0) != 0x60)
		goto fillup_by_null;
	traffic_class = ((ipv6->v0 & 0x0f) << 4) | ((ipv6->v1 & 0xf0) >> 4);
	flow_label = (((uint32_t)(ipv6->v1 & 0x0f) << 16) |
				  ((uint32_t)(ipv6->v2 << 8)) |
				  ((uint32_t)(ipv6->v3)));

	__FIELD_PUT_VALUE(traffic_class, &traffic_class, sizeof(uint8_t));
    __FIELD_PUT_VALUE(flow_label,  &flow_label, sizeof(uint32_t));
    __FIELD_PUT_VALUE(hop_limit,   &ipv6->hop_limit, sizeof(uint8_t));
    __FIELD_PUT_VALUE(src_addr6,   &ipv6->src_addr6, IP6ADDR_LEN);
    __FIELD_PUT_VALUE(dst_addr6,   &ipv6->dst_addr6, IP6ADDR_LEN);
	return handlePacketIPv6Options(chunk, ipv6->next, ipv6->data, end, p_proto);

fillup_by_null:
	__FIELD_PUT_VALUE(traffic_class, NULL, 0);
	__FIELD_PUT_VALUE(flow_label,    NULL, 0);
	__FIELD_PUT_VALUE(hop_limit,     NULL, 0);
	__FIELD_PUT_VALUE(src_addr6,     NULL, 0);
	__FIELD_PUT_VALUE(dst_addr6,     NULL, 0);
	__FIELD_PUT_VALUE(ip6_options,   NULL, 0);
	return NULL;
}

/*
 * handlePacketTcpHeader
 */
static const u_char *
handlePacketTcpHeader(SQLtable *chunk,
					  const u_char *buf, size_t sz, int proto,
					  int *p_src_port, int *p_dst_port)
{
	__FIELD_PUT_VALUE_DECL;
	struct __tcp_head {
		uint16_t	src_port;
		uint16_t	dst_port;
		uint32_t	seq_nr;
		uint32_t	ack_nr;
		uint16_t	tcp_flags;
		uint16_t	window_sz;
		uint16_t	tcp_checksum;
		uint16_t	urgent_ptr;
		u_char		tcp_options[0];
	}		   *tcp = (struct __tcp_head *)buf;
	uint16_t	tcp_flags;
	uint16_t	head_sz;

	if (!buf || sz < offsetof(struct __tcp_head, tcp_options))
		goto fillup_by_null;
	tcp_flags = __ntoh16(tcp->tcp_flags);
	head_sz = sizeof(uint32_t) * ((tcp_flags & 0xf000) >> 12);
	if (head_sz > sz)
		goto fillup_by_null;
	tcp_flags &= 0x0fff;

	*p_src_port = __ntoh16(tcp->src_port);
	*p_dst_port = __ntoh16(tcp->dst_port);

	__FIELD_PUT_VALUE(seq_nr,       &tcp->seq_nr,       sizeof(uint32_t));
	__FIELD_PUT_VALUE(ack_nr,       &tcp->ack_nr,       sizeof(uint32_t));
	__FIELD_PUT_VALUE(tcp_flags,    &tcp_flags,         sizeof(uint16_t));
	__FIELD_PUT_VALUE(window_sz,    &tcp->window_sz,    sizeof(uint16_t));
	__FIELD_PUT_VALUE(tcp_checksum, &tcp->tcp_checksum, sizeof(uint16_t));
	__FIELD_PUT_VALUE(urgent_ptr,   &tcp->urgent_ptr,   sizeof(uint16_t));
	if (head_sz <= offsetof(struct __tcp_head, tcp_options))
	{
		__FIELD_PUT_VALUE(tcp_options, NULL, 0);
	}
	else if (composite_options)
	{
		option_item		tcp_options[40];
		int				nitems = 0;
		const u_char   *pos = tcp->tcp_options;
		const u_char   *end = buf + head_sz;

		/* https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml */
		while (pos < end)
		{
			int			code = *pos++;

			if (code == 0)	/* End of Options List */
				break;
			if (code == 1)	/* No Operations */
				continue;
			/* Other options have length field in the 2nd octet */
			if (pos < end)
			{
				option_item	   *item = &tcp_options[nitems++];
				item->option_type = code;
				item->option_sz = (*pos++) - 2;
				item->option_addr = pos;
				pos += item->option_sz;
			}
		}

		if (nitems == 0)
		{
			__FIELD_PUT_VALUE(tcp_options, NULL, 0);
		}
		else
		{
			__FIELD_PUT_VALUE(tcp_options, tcp_options,
							  sizeof(option_item) * nitems);
		}
	}
	else
	{
		__FIELD_PUT_VALUE(tcp_options, tcp->tcp_options,
						  head_sz - offsetof(struct __tcp_head, tcp_options));
	}
	chunk->usage += usage;

	return buf + head_sz;

fillup_by_null:
	__FIELD_PUT_VALUE(seq_nr, NULL, 0);
	__FIELD_PUT_VALUE(ack_nr, NULL, 0);
	__FIELD_PUT_VALUE(tcp_flags, NULL, 0);
	__FIELD_PUT_VALUE(window_sz, NULL, 0);
	__FIELD_PUT_VALUE(tcp_checksum, NULL, 0);
	__FIELD_PUT_VALUE(urgent_ptr, NULL, 0);
	__FIELD_PUT_VALUE(tcp_options, NULL, 0);
	chunk->usage += usage;
	return NULL;
}

/*
 * handlePacketUdpHeader
 */
static const u_char *
handlePacketUdpHeader(SQLtable *chunk,
					  const u_char *buf, size_t sz, int proto,
					  int *p_src_port, int *p_dst_port)
{
	__FIELD_PUT_VALUE_DECL;
	struct __udp_head {
		uint16_t	src_port;
		uint16_t	dst_port;
		uint16_t	udp_length;
		uint16_t	udp_checksum;
	}		   *udp = (struct __udp_head *) buf;

	if (!buf || sz < sizeof(struct __udp_head))
		goto fillup_by_null;
	*p_src_port = __ntoh16(udp->src_port);
	*p_dst_port = __ntoh16(udp->dst_port);
	__FIELD_PUT_VALUE(udp_length,   &udp->udp_length,   sizeof(uint16_t));
	__FIELD_PUT_VALUE(udp_checksum, &udp->udp_checksum, sizeof(uint16_t));
	chunk->usage += usage;
	return buf + sizeof(struct __udp_head);

fillup_by_null:
	__FIELD_PUT_VALUE(udp_length,   NULL, 0);
	__FIELD_PUT_VALUE(udp_checksum, NULL, 0);
	chunk->usage += usage;
	return NULL;
}

/*
 * handlePacketIcmpHeader
 */
static const u_char *
handlePacketIcmpHeader(SQLtable *chunk,
					   const u_char *buf, size_t sz, int proto)
{
	__FIELD_PUT_VALUE_DECL;
	struct __icmp_head {
		uint8_t		icmp_type;
		uint8_t		icmp_code;
		uint16_t	icmp_checksum;
	}		   *icmp = (struct __icmp_head *) buf;

	if (!buf || sz < sizeof(struct __icmp_head))
		goto fillup_by_null;

	__FIELD_PUT_VALUE(icmp_type,     &icmp->icmp_type, sizeof(uint8_t));
	__FIELD_PUT_VALUE(icmp_code,     &icmp->icmp_code, sizeof(uint8_t));
	__FIELD_PUT_VALUE(icmp_checksum, &icmp->icmp_checksum, sizeof(uint16_t));
	chunk->usage += usage;
	return buf + sizeof(struct __icmp_head);

fillup_by_null:
	__FIELD_PUT_VALUE(icmp_type,     NULL, 0);
	__FIELD_PUT_VALUE(icmp_code,     NULL, 0);
	__FIELD_PUT_VALUE(icmp_checksum, NULL, 0);
	chunk->usage += usage;
	return NULL;
}

/*
 * handlePacketMiscFields
 */
static void
handlePacketMiscFields(SQLtable *chunk, int proto, int src_port, int dst_port)
{
	__FIELD_PUT_VALUE_DECL;

	if ((protocol_mask & (__PCAP_PROTO__IPv4 | __PCAP_PROTO__IPv6)) != 0)
	{
		if (proto < 0)
		{
			__FIELD_PUT_VALUE(protocol, NULL, 0);
		}
		else
		{
			__FIELD_PUT_VALUE(protocol, &proto, sizeof(uint8_t));
		}
	}

	if ((protocol_mask & (__PCAP_PROTO__TCP | __PCAP_PROTO__UDP)) != 0)
	{
		if (src_port < 0)
		{
			__FIELD_PUT_VALUE(src_port, NULL, 0);
		}
		else
		{
			__FIELD_PUT_VALUE(src_port, &src_port, sizeof(uint16_t));
		}

		if (dst_port < 0)
		{
			__FIELD_PUT_VALUE(dst_port, NULL, 0);
		}
		else
		{
			__FIELD_PUT_VALUE(dst_port, &dst_port, sizeof(uint16_t));
		}
	}
	chunk->usage += usage;
}

/*
 * handlePacketPayload
 */
static void
handlePacketPayload(SQLtable *chunk, const u_char *buf, size_t sz)
{
	__FIELD_PUT_VALUE_DECL;
	
	if (buf && sz > 0)
	{
		__FIELD_PUT_VALUE(payload, buf, sz);
	}
	else
	{
		__FIELD_PUT_VALUE(payload, NULL, 0);
	}
	chunk->usage += usage;
}

/*
 * arrowOpenOutputFile
 */
static arrowFileDesc *
arrowOpenOutputFile(void)
{
	static int	output_file_seqno = 1;
	time_t		tv = time(NULL);
	struct tm	tm;
	char	   *path, *pos;
	int			off, sz = 256;
	int			retry_count = 0;
	int			fdesc;
	int			flags;
	arrowFileDesc *outfd;

	/* build a filename */
	localtime_r(&tv, &tm);
retry:
	do {
		off = 0;
		path = alloca(sz);

		for (pos = output_filename; *pos != '\0' && off < sz; pos++)
		{
			if (*pos == '%')
			{
				pos++;
				switch (*pos)
				{
					case 'i':
						off += snprintf(path+off, sz-off,
										"%s", (input_devname ?
											   input_devname : "file"));

						break;
					case 'Y':
						off += snprintf(path+off, sz-off,
										"%04d", tm.tm_year + 1900);
						break;
					case 'y':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_year % 100);
						break;
					case 'm':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_mon + 1);
						break;
					case 'd':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_mday);
						break;
					case 'H':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_hour);
						break;
					case 'M':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_min);
						break;
					case 'S':
						off += snprintf(path+off, sz-off,
										"%02d", tm.tm_sec);
						break;
					case 'q':
						off += snprintf(path+off, sz-off,
										"%d", output_file_seqno++);
						break;
					default:
						Elog("unexpected output file format '%%%c'", *pos);
				}
			}
			else
			{
				path[off++] = *pos;
			}
		}
		if (retry_count > 0)
			off += snprintf(path+off, sz-off,
							".%d", retry_count);
		if (off < sz)
			path[off++] = '\0';
	} while (off >= sz);

	/* open file */
	flags = O_RDWR | O_CREAT;
	if (!force_overwrite)
		flags |= O_EXCL;

	fdesc = open(path, flags, 0644);
	if (fdesc < 0)
	{
		if (errno == EEXIST)
		{
			retry_count++;
			goto retry;
		}
		Elog("failed to open('%s'): %m", path);
	}

	/* Setup arrowFileDesc */
	outfd = palloc0(offsetof(arrowFileDesc,
							 table.columns[PCAP_SCHEMA_MAX_NFIELDS]));
	outfd->refcnt = 0;
	outfd->table.fdesc = fdesc;
	outfd->table.filename = pstrdup(path);
	arrowPcapSchemaInit(&outfd->table);

	/* Write Header */
	arrowFileWrite(&outfd->table, "ARROW1\0\0", 8);
	writeArrowSchema(&outfd->table);

	/* Turn on O_DIRECT if --direct-io is given */
	if (enable_direct_io)
	{
		int		flags = fcntl(fdesc, F_GETFL);

		flags |= O_DIRECT;
		if (fcntl(fdesc, F_SETFL, &flags) != 0)
			Elog("failed on fcntl('%s', F_SETFL, O_DIRECT): %m", path);
		outfd->table.f_pos = DIRECT_IO_ALIGN(outfd->table.f_pos);
	}
	return outfd;
}

/*
 * arrowCloseOutputFile
 */
static void
arrowCloseOutputFile(arrowFileDesc *outfd)
{
	if (outfd->table.numRecordBatches == 0)
	{
		if (unlink(outfd->table.filename) != 0)
			Elog("failed on unlink('%s'): %m", outfd->table.filename);
	}
	else
	{
		/* turn off direct-io, if O_DIRECT is set */
		if (enable_direct_io)
		{
			int		flags = fcntl(outfd->table.fdesc, F_GETFL);

			flags &= ~O_DIRECT;
			if (fcntl(outfd->table.fdesc, F_SETFL, flags) != 0)
				Elog("failed on fcntl('%s', F_SETFL, %d): %m",
					 outfd->table.filename, flags);
		}
		if (lseek(outfd->table.fdesc, outfd->table.f_pos, SEEK_SET) < 0)
			Elog("failed on lseek('%s'): %m", outfd->table.filename);
		writeArrowFooter(&outfd->table);
	}
	close(outfd->table.fdesc);
}

/*
 * arrowFileDirectWriteIOV
 */
static void
arrowFileDirectWriteIOV(SQLtable *chunk, size_t length)
{
	static __thread char   *dio_buffer = NULL;
	static __thread size_t	dio_buffer_sz = 0;
	char	   *pos;
	int			i, gap;

	Assert(length == DIRECT_IO_ALIGN(length));
	/* DIO buffer allocation on the demand */
	if (!dio_buffer)
	{
		dio_buffer_sz = PAGE_ALIGN(length) + (1UL << 21);	/* 2MB margin */
		dio_buffer = mmap(NULL, dio_buffer_sz,
						  PROT_READ | PROT_WRITE,
						  MAP_PRIVATE | MAP_ANONYMOUS,
						  -1, 0);
		if (dio_buffer == MAP_FAILED)
			Elog("failed on mmap(sz=%zu): %m", dio_buffer_sz);
	}
	else if (length > dio_buffer_sz)
	{
		size_t		sz = PAGE_ALIGN(length) + (1UL << 21);	/* 2MB margin */

		dio_buffer = mremap(dio_buffer, dio_buffer_sz, sz, MREMAP_MAYMOVE);
		if (dio_buffer == MAP_FAILED)
			Elog("failed on mremap(sz=%zu -> %zu): %m", dio_buffer_sz, sz);
		dio_buffer_sz = sz;
	}

	/* setup DIO buffer */
	pos = dio_buffer;
	for (i=0; i < chunk->__iov_cnt; i++)
	{
		struct iovec *iov = &chunk->__iov[i];

		memcpy(pos, iov->iov_base, iov->iov_len);
		pos += iov->iov_len;
	}
	Assert(pos <= dio_buffer + length);
	gap = (dio_buffer + length) - pos;
	if (gap > 0)
		memset(pos, 0, gap);

	/* issue direct i/o */
	arrowFileWrite(chunk, dio_buffer, length);

	chunk->__iov_cnt = 0;	/* rewind iovec */
}

/*
 * arrowChunkWriteOut
 */
static void
arrowChunkWriteOut(SQLtable *chunk)
{
	arrowFileDesc *outfd = NULL;
	ArrowBlock	block;
	size_t		meta_sz;
	size_t		length;
	int			f_index;
	bool		close_file = false;

	/*
	 * writeArrowXXXX() routines setup iov array if table->fdesc < 0.
	 */
	Assert(chunk->fdesc < 0);
	length = setupArrowRecordBatchIOV(chunk);
	if (enable_direct_io)
		length = DIRECT_IO_ALIGN(length);

	/*
	 * attach file descriptor
	 */
	f_index = atomicAdd64(&arrow_file_desc_selector, 1) % arrow_file_desc_nums;
	pthreadMutexLock(&arrow_file_desc_locks[f_index]);
	for (;;)
	{
		outfd = arrow_file_desc_array[f_index];
		if (outfd->table.f_pos < output_filesize_limit)
		{
			/* Ok, [base ... base + usage) is reserved */
			chunk->fdesc    = outfd->table.fdesc;
			chunk->filename = outfd->table.filename;
			chunk->f_pos    = outfd->table.f_pos;

			outfd->table.f_pos += length;
			outfd->refcnt++;
			break;
		}
		else
		{
			/* exceeds the limit, so switch the output file */
			arrow_file_desc_array[f_index] = arrowOpenOutputFile();
			if (outfd->refcnt == 0)
			{
				pthreadMutexUnlock(&arrow_file_desc_locks[f_index]);
				/* ...and close the file, if nobody is writing */
				arrowCloseOutputFile(outfd);
				pthreadMutexLock(&arrow_file_desc_locks[f_index]);
			}
		}
	}
	pthreadMutexUnlock(&arrow_file_desc_locks[f_index]);

	/* ok, write out record batch (see writeArrowRecordBatch) */
	Assert(chunk->__iov_cnt > 0 &&
		   chunk->__iov[0].iov_len <= length);
	meta_sz = chunk->__iov[0].iov_len;

	memset(&block, 0, sizeof(ArrowBlock));
	initArrowNode(&block, Block);
	block.offset = chunk->f_pos;
	block.metaDataLength = meta_sz;
	block.bodyLength = length - meta_sz;

	if (!enable_direct_io)
	{
		/* write-out using pwritev */
		arrowFileWriteIOV(chunk);
	}
	else
	{
		/* write-out by direct-io */
		arrowFileDirectWriteIOV(chunk, length);
	}

	/*
	 * Ok, append ArrowBlock and detach file descriptor
	 */
	pthreadMutexLock(&arrow_file_desc_locks[f_index]);
	if (!outfd->table.recordBatches)
		outfd->table.recordBatches = palloc0(sizeof(ArrowBlock) * 40);
	else
	{
		length = sizeof(ArrowBlock) * (outfd->table.numRecordBatches + 1);
		outfd->table.recordBatches = repalloc(outfd->table.recordBatches, length);
	}
	outfd->table.recordBatches[outfd->table.numRecordBatches++] = block;

	Assert(outfd->refcnt > 0);
	if (--outfd->refcnt == 0 && arrow_file_desc_array[f_index] != outfd)
		close_file = true;
	pthreadMutexUnlock(&arrow_file_desc_locks[f_index]);
	if (close_file)
		arrowCloseOutputFile(outfd);

	/* reset chunk buffer */
	chunk->fdesc = -1;
	chunk->filename = NULL;
	chunk->f_pos = 0;
}

/*
 * arrowMergeChunkWriteOut
 */
static inline int
__arrowMergeChunkOneOptions(option_item *__option_items,
							SQLfield *element,
							uint32_t start, uint32_t end)
{
	uint32_t	index;
	int			nitems = 0;
	SQLfield   *sopt_type = &element->subfields[0];
	SQLfield   *sopt_data = &element->subfields[1];

	Assert(element->nitems == sopt_type->nitems &&
		   element->nitems == sopt_data->nitems);
	
	if (element->nullcount != 0 ||
		sopt_type->nullcount != 0 ||
		sopt_data->nullcount != 0)
		Elog("Data corruption? IPv4/IPv6/Tcp options should contains not NULLs");
	
	for (index=start; index < end; index++)
	{
		option_item *item = &__option_items[nitems++];
		uint32_t	off;

		item->option_type = ((uint8_t *)sopt_type->values.data)[index];
		off = ((uint32_t *)sopt_data->values.data)[index];
		item->option_sz = ((uint32_t *)sopt_data->values.data)[index+1] - off;
		item->option_addr = (sopt_data->extra.data + off);
	}
	return nitems;
}

static inline void
__arrowMergeChunkOneRow(SQLtable *dchunk,
						SQLtable *schunk, size_t index)
{
	size_t		usage = 0;
	int			j;

	Assert(dchunk->nfields == schunk->nfields);
	for (j=0; j < schunk->nfields; j++)
	{
		option_item	__option_items[256];
		SQLfield   *dcolumn = &dchunk->columns[j];
		SQLfield   *scolumn = &schunk->columns[j];
		void	   *addr;
		size_t		sz, off;
		uint64_t	val;
		uint32_t	start, end;
		int			nitems;
		struct timeval ts_buf;

		Assert(schunk->nitems == scolumn->nitems);
		if (scolumn->nullcount > 0 &&
			(scolumn->nullmap.data[index>>3] & (1<<(index&7))) == 0)
		{
			usage += dcolumn->put_value(dcolumn, NULL, 0);
			continue;
		}

		Assert(scolumn->arrow_type.node.tag == dcolumn->arrow_type.node.tag);
		switch (scolumn->arrow_type.node.tag)
		{
			case ArrowNodeTag__Timestamp:
				Assert(scolumn->arrow_type.Timestamp.unit == ArrowTimeUnit__MicroSecond);
				val = ((uint64_t *)scolumn->values.data)[index];
				ts_buf.tv_sec = val / 1000000;
				ts_buf.tv_usec = val % 1000000;
				sz = sizeof(struct timeval);
				addr = &ts_buf;
				break;

			case ArrowNodeTag__Int:
				sz = scolumn->arrow_type.Int.bitWidth / 8;
				Assert(sz == sizeof(uint8_t)  ||
					   sz == sizeof(uint16_t) ||
					   sz == sizeof(uint32_t) ||
					   sz == sizeof(uint64_t));
				addr = scolumn->values.data + sz * index;
				break;

			case ArrowNodeTag__Binary:
				off = ((uint32_t *)scolumn->values.data)[index];
				sz = ((uint32_t *)scolumn->values.data)[index+1] - off;
				addr = scolumn->extra.data + off;
				break;

			case ArrowNodeTag__FixedSizeBinary:
				Assert(scolumn->arrow_type.FixedSizeBinary.byteWidth ==
					   dcolumn->arrow_type.FixedSizeBinary.byteWidth);
				sz = scolumn->arrow_type.FixedSizeBinary.byteWidth;
				addr = scolumn->values.data + sz * index;
				break;

			case ArrowNodeTag__List:
				/* List::Struct<Uint8,Binary> */
				start = ((uint32_t *)scolumn->values.data)[index];
				end = ((uint32_t *)scolumn->values.data)[index+1];
				nitems = __arrowMergeChunkOneOptions(__option_items,
													 scolumn->element,
													 start, end);
				if (nitems == 0)
				{
					sz = 0;
					addr = NULL;
				}						
				else
				{
					sz = sizeof(option_item) * nitems;
					addr = __option_items;
				}
				break;
			default:
				Elog("Bug? unexpected ArrowType (tag: %d)",
					 scolumn->arrow_type.node.tag);
		}
		usage += dcolumn->put_value(dcolumn, addr, sz);
	}
	dchunk->nitems++;
	dchunk->usage = usage;
}

static void
arrowMergeChunkWriteOut(SQLtable *dchunk, SQLtable *schunk)
{
	size_t		i;
	
	for (i=0; i < schunk->nitems; i++)
	{
		/* merge one row */
		__arrowMergeChunkOneRow(dchunk, schunk, i);

		/* write out buffer */
		if (dchunk->usage >= record_batch_threshold)
		{
			arrowChunkWriteOut(dchunk);
			sql_table_clear(dchunk);
		}
	}
}

/*
 * __execCaptureOnePacket
 */
static inline void
__execCaptureOnePacket(SQLtable *chunk,
					   struct pfring_pkthdr *hdr, const u_char *pos)
{
	const u_char   *end = pos + hdr->caplen;
	const u_char   *next;
	uint16_t		ether_type;
	int				proto = -1;
	int				src_port = -1;
	int				dst_port = -1;

	pos = handlePacketRawEthernet(chunk, hdr, pos, &ether_type);
	if (!pos)
		goto fillup_by_null;
	if (print_stat_interval > 0)
		atomicAdd64(&stat_raw_packet_length, hdr->len);

	if (ether_type == 0x0800)		/* IPv4 */
	{
		if (print_stat_interval > 0)
			atomicAdd64(&stat_ip4_packet_count, 1);
		if ((protocol_mask & __PCAP_PROTO__IPv4) == 0)
			goto fillup_by_null;
		next = handlePacketIPv4Header(chunk, pos, end - pos, &proto);
		if (next)
			pos = next;
		if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
			handlePacketIPv6Header(chunk, NULL, 0, NULL);
	}
	else if (ether_type == 0x86dd)	/* IPv6 */
	{
		if (print_stat_interval > 0)
			atomicAdd64(&stat_ip6_packet_count, 1);
		if ((protocol_mask & __PCAP_PROTO__IPv6) == 0)
			goto fillup_by_null;
		next = handlePacketIPv6Header(chunk, pos, end - pos, &proto);
		if (next)
			pos = next;
		if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
			handlePacketIPv4Header(chunk, NULL, 0, NULL);
	}
	else
	{
		/* neither IPv4 nor IPv6 */
		goto fillup_by_null;
	}

	/* TCP */
	if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
	{
		if (proto == 0x06)
		{
			if (print_stat_interval > 0)
				atomicAdd64(&stat_tcp_packet_count, 1);
			next = handlePacketTcpHeader(chunk, pos, end - pos, proto,
										 &src_port, &dst_port);
			if (next)
				pos = next;
		}
		else
		{
			handlePacketTcpHeader(chunk, NULL, 0, proto, NULL, NULL);
		}
	}
	
	/* UDP */
	if ((protocol_mask & __PCAP_PROTO__UDP) != 0)
	{
		if (proto == 0x11)
		{
			if (print_stat_interval > 0)
				atomicAdd64(&stat_udp_packet_count, 1);
			next = handlePacketUdpHeader(chunk, pos, end - pos, proto,
										 &src_port, &dst_port);
			if (next)
				pos = next;
		}
		else
		{
			handlePacketUdpHeader(chunk, NULL, 0, proto, NULL, NULL);
		}
	}

	/* ICMP */
	if ((protocol_mask & __PCAP_PROTO__ICMP) != 0)
	{
		if (proto == 0x01)
		{
			if (print_stat_interval > 0)
				atomicAdd64(&stat_icmp_packet_count, 1);
			next = handlePacketIcmpHeader(chunk, pos, end - pos, proto);
			if (next)
				pos = next;
		}
		else
		{
			handlePacketIcmpHeader(chunk, NULL, 0, proto);
		}
	}
	/* other fields */
	handlePacketMiscFields(chunk, proto, src_port, dst_port);

	/* Payload */
	if (!only_headers)
		handlePacketPayload(chunk, pos, end - pos);
	chunk->nitems++;
	return;

fillup_by_null:
	if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
		handlePacketIPv4Header(chunk, NULL, 0, NULL);
	if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
		handlePacketIPv6Header(chunk, NULL, 0, NULL);
	if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
		handlePacketTcpHeader(chunk, NULL, 0, -1, NULL, NULL);
	if ((protocol_mask & __PCAP_PROTO__UDP) != 0)
		handlePacketUdpHeader(chunk, NULL, 0, -1, NULL, NULL);
	if ((protocol_mask & __PCAP_PROTO__ICMP) != 0)
		handlePacketIcmpHeader(chunk, NULL, 0, -1);
	handlePacketMiscFields(chunk, -1, -1, -1);
	if (!only_headers && pos != NULL)
		handlePacketPayload(chunk, pos, end - pos);
	chunk->nitems++;
}

/*
 * execCapturePackets
 */
static int
execCapturePackets(pfring *pd, SQLtable *chunk)
{
	struct pfring_pkthdr hdr;
	u_char		__buffer[65536];
	u_char	   *buffer = __buffer;
	int			rv;

	sql_table_clear(chunk);

	while (!do_shutdown)
	{
		rv = pfring_recv(pd, &buffer, sizeof(__buffer), &hdr, 1);
		if (rv > 0)
		{
			__execCaptureOnePacket(chunk, &hdr, buffer);
			if (chunk->usage >= record_batch_threshold)
				return 1;	/* write out the buffer */
		}
	}
	/* interrupted, thus chunk-buffer is partially filled up */
	return 0;
}

/*
 * final_merge_pending_chunks
 */
static void *
final_merge_pending_chunks(SQLtable *chunk)
{
	int		phase;

	Assert(worker_id >= 0 && worker_id < num_threads);
	/* merge pending chunks */
	for (phase = 0; (worker_id & ((1UL << (phase + 1)) - 1)) == 0; phase++)
	{
		int		buddy = worker_id + (1UL << phase);

		if (buddy >= num_threads)
			break;
		pthreadMutexLock(&arrow_workers_mutex);
		while (!arrow_workers_completed[buddy])
		{
			pthreadCondWait(&arrow_workers_cond,
							&arrow_workers_mutex);
		}
		pthreadMutexUnlock(&arrow_workers_mutex);

		arrowMergeChunkWriteOut(chunk, arrow_chunks_array[buddy]);
	}
	if (worker_id == 0 && chunk->nitems > 0)
		arrowChunkWriteOut(chunk);
	
	/* Ok, this worker exit */
	pthreadMutexLock(&arrow_workers_mutex);
	arrow_workers_completed[worker_id] = true;
	pthreadCondBroadcast(&arrow_workers_cond);
	pthreadMutexUnlock(&arrow_workers_mutex);

	return NULL;
}

/*
 * pfring_worker_main
 */
static void *
pfring_worker_main(void *__arg)
{
	SQLtable   *chunk;

	/* assign worker-id of this thread */
	worker_id = (long)__arg;
	chunk = arrow_chunks_array[worker_id];

	while (!do_shutdown)
	{
		int		status = -1;

		if (sem_wait(&pcap_worker_sem) != 0)
		{
			if (errno == EINTR)
				continue;
			Elog("worker-%ld: failed on sem_wait: %m", worker_id);
		}
		/*
		 * Ok, Go to packet capture
		 */
		if (!do_shutdown)
		{
			pfring	   *pd;
			int			index;

			index = atomicAdd64(&pfring_desc_selector, 1) % pfring_desc_nums;
			pd = pfring_desc_array[index];

			status = execCapturePackets(pd, chunk);
			Assert(status >= 0);
		}
		if (sem_post(&pcap_worker_sem) != 0)
            Elog("failed on sem_post: %m");

		if (status > 0)
			arrowChunkWriteOut(chunk);
	}
	return final_merge_pending_chunks(chunk);
}

/*
 * pcap_file_worker_main
 */
static void *
pcap_file_worker_main(void *__arg)
{
	SQLtable   *chunk;
	int			i;
	
	/* assign worker-id of this thread */
	worker_id = (long)__arg;
	chunk = arrow_chunks_array[worker_id];

	for (i = worker_id;
		 i < pcap_file_desc_nums && !do_shutdown;
		 i += num_threads)
	{
		pcapFileDesc   *pfdesc = &pcap_file_desc_array[i];
		const u_char   *buffer;

		pfdesc->pcap_handle =
			pcap_fopen_offline_with_tstamp_precision(pfdesc->pcap_filp,
													 PCAP_TSTAMP_PRECISION_MICRO,
													 pfdesc->pcap_errbuf);
		if (!pfdesc->pcap_handle)
			Elog("failed on open pcap file ('%s'): %s",
				 pfdesc->pcap_filename,
				 pfdesc->pcap_errbuf);

		while (!do_shutdown)
		{
			struct pcap_pkthdr hdr;
			struct pfring_pkthdr __hdr;

			buffer = pcap_next(pfdesc->pcap_handle, &hdr);
			if (!buffer)
				break;
			__hdr.ts = hdr.ts;
			__hdr.caplen = hdr.caplen;
			__hdr.len = hdr.len;
			__execCaptureOnePacket(chunk, &__hdr, buffer);
			if (chunk->usage >= record_batch_threshold)
			{
				arrowChunkWriteOut(chunk);
				sql_table_clear(chunk);
			}
		}
		/* close */
		pcap_close(pfdesc->pcap_handle);
    }
	return final_merge_pending_chunks(chunk);
}

/*
 * usage
 */
static int
usage(int status)
{
	fputs("usage: pcap2arrow [OPTIONS] [<pcap files>...]\n"
		  "\n"
		  "OPTIONS:\n"
		  "  -i|--input=DEVICE\n"
		  "       specifies a network device to capture packet.\n"
		  "     --num-queues=N_QUEUE : num of PF-RING queues.\n"
		  "  -o|--output=<output file; with format>\n"
		  "       filename format can contains:"
		  "         %i : interface name\n"
		  "         %Y : year in 4-digits\n"
		  "         %y : year in 2-digits\n"
		  "         %m : month in 2-digits\n"
		  "         %d : day in 2-digits\n"
		  "         %H : hour in 2-digits\n"
		  "         %M : minute in 2-digits\n"
		  "         %S : second in 2-digits\n"
		  "         %q : sequence number for each output files\n"
		  "       default is '/tmp/pcap_%i_%y%m%d_%H%M%S.arrow'\n"
		  "  -f|--force : overwrite file, even if exists\n"
		  "     --only-headers: disables capture of payload\n"
		  "     --parallel-write=N_FILES\n"
		  "       opens multiple output files simultaneously (default: 1)\n"
		  "     --chunk-size=SIZE : size of record batch (default: 128MB)\n"
		  "     --direct-io : enables O_DIRECT for write-i/o\n"
		  "  -l|--limit=LIMIT : (default: no limit)\n"
		  "  -p|--protocol=PROTO\n"
		  "       PROTO is a comma separated string contains\n"
		  "       the following tokens:\n"
		  "         tcp4, udp4, icmp4, ipv4, tcp6, udp6, icmp6, ipv6\n"
		  "       (default: 'tcp4,udp4,icmp4')\n"
		  "     --composite-options:\n"
		  "        write out IPv4,IPv6 and TCP options as an array of composite values\n"
		  "  -r|--rule=RULE : packet filtering rules\n"
		  "       (default: none; valid only capturing mode)\n"
		  "  -s|--stat=INTERVAL\n"
		  "       enables to print statistics per INTERVAL\n"
		  "  -t|--threads=N_THREADS\n"
		  "     --pcap-threads=N_THREADS\n"
		  "  -h|--help    : shows this message\n"
		  "\n"
		  "  Copyright (C) 2020-2021 HeteroDB,Inc <contact@heterodb.com>\n"
		  "  Copyright (C) 2020-2021 KaiGai Kohei <kaigai@kaigai.gr.jp>\n",
		  stderr);
	exit(status);
}

static void
parse_options(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"input",          required_argument, NULL, 'i'},
		{"output",         required_argument, NULL, 'o'},
		{"force",          no_argument,       NULL, 'f'},
		{"protocol",       required_argument, NULL, 'p'},
		{"threads",        required_argument, NULL, 't'},
		{"limit",          required_argument, NULL, 'l'},
		{"stat",           required_argument, NULL, 's'},
		{"rule",           required_argument, NULL, 'r'},
		{"pcap-threads",   required_argument, NULL, 1000},
		{"direct-io",      no_argument,       NULL, 1001},
		{"chunk-size",     required_argument, NULL, 1002},
		{"only-headers",   no_argument,       NULL, 1003},
		{"num-queues",     required_argument, NULL, 1004},
		{"parallel-write", required_argument, NULL, 1005},
		{"composite-options", no_argument,    NULL, 1006},
		{"help",           no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	int			code;
	char	   *pos;

	while ((code = getopt_long(argc, argv, "i:o:fp:t:l:s::r:h",
							   long_options, NULL)) >= 0)
	{
		char	   *token, *end;

		switch (code)
		{
			case 'i':	/* --input */
				if (input_devname)
					Elog("-i|--input was specified twice");
				input_devname = optarg;
				break;
			case 'o':	/* --output */
				output_filename = optarg;
				break;
			case 'f':	/* --force */
				force_overwrite = true;
				break;
			case 'p':	/* --protocol */
				protocol_mask = 0;
				for (token = strtok_r(optarg, ",", &pos);
					 token != NULL;
					 token = strtok_r(NULL, ",", &pos))
				{
					/* remove spaces */
					while (*token != '\0' && isspace(*token))
						token++;
					end = token + strlen(token) - 1;
					while (end >= token && isspace(*end))
						*end-- = '\0';
					if (strcmp(token, "ipv4") == 0)
						protocol_mask |= PCAP_PROTO__RAW_IPv4;
					else if (strcmp(token, "tcp4") == 0)
						protocol_mask |= PCAP_PROTO__TCP_IPv4;
					else if (strcmp(token, "udp4") == 0)
						protocol_mask |= PCAP_PROTO__UDP_IPv4;
					else if (strcmp(token, "icmp4") == 0)
						protocol_mask |= PCAP_PROTO__ICMP_IPv4;
					else if (strcmp(token, "ipv6") == 0)
						protocol_mask |= PCAP_PROTO__RAW_IPv6;
					else if (strcmp(token, "tcp6") == 0)
						protocol_mask |= PCAP_PROTO__TCP_IPv6;
					else if (strcmp(token, "udp6") == 0)
						protocol_mask |= PCAP_PROTO__UDP_IPv6;
					else if (strcmp(token, "icmp6") == 0)
						protocol_mask |= PCAP_PROTO__ICMP_IPv6;
					else
						Elog("unknown protocol [%s]", token);
				}
				break;
			case 't':	/* --threads */
				num_threads = strtol(optarg, &pos, 10);
				if (*pos != '\0')
					Elog("invalid -t|--threads argument: %s", optarg);
				if (num_threads < 1)
					Elog("invalid number of threads: %d", num_threads);
				break;

			case 'l':	/* limit */
				output_filesize_limit = strtol(optarg, &pos, 10);
				if (strcasecmp(pos, "k") == 0 || strcasecmp(pos, "kb") == 0)
					output_filesize_limit <<= 10;
				else if (strcasecmp(pos, "m") == 0 || strcasecmp(pos, "mb") == 0)
					output_filesize_limit <<= 20;
				else if (strcasecmp(pos, "g") == 0 || strcasecmp(pos, "gb") == 0)
					output_filesize_limit <<= 30;
				else if (*pos != '\0')
					Elog("unknown unit size '%s' in -l|--limit option",
						 optarg);
				if (output_filesize_limit < (64UL << 20))
					Elog("output filesize limit too small (should be > 64MB))");
				break;

			case 'r':	/* --rule */
				bpf_filter_rule = pstrdup(optarg);
				break;

			case 's':	/* --stat */
				print_stat_interval = strtol(optarg, &pos, 10);
				if (*pos != '\0')
					Elog("invalid -s|--stat argument [%s]", optarg);
				if (print_stat_interval <= 0)
					Elog("invalid interval to print statistics [%s]", optarg);
				break;

			case 1000:	/* --pcap-threads */
				num_pcap_threads = strtol(optarg, &pos, 10);
				if (*pos != '\0')
					Elog("invalid --pcap-threads argument: %s", optarg);
				if (num_pcap_threads < 1)
					Elog("invalid number of pcap-threads: %d", num_pcap_threads);
				break;

			case 1001:	/* --direct-io */
				enable_direct_io = true;
				break;

			case 1002:	/* --chunk-size */
				record_batch_threshold = strtol(optarg, &pos, 10);
				if (strcasecmp(pos, "k") == 0 || strcasecmp(pos, "kb") == 0)
					record_batch_threshold <<= 10;
				else if (strcasecmp(pos, "m") == 0 || strcasecmp(pos, "mb") == 0)
					record_batch_threshold <<= 20;
				else if (strcasecmp(pos, "g") == 0 || strcasecmp(pos, "gb") == 0)
					record_batch_threshold <<= 30;
				else
					Elog("unknown unit size '%s' in -s|--chunk-size option",
						 optarg);
				break;

			case 1003:	/* --only-headers */
				only_headers = true;
				break;

			case 1004:	/* --num-queues */
				pfring_desc_nums = strtol(optarg, &pos, 10);
				if (*pos != '\0' || pfring_desc_nums < 1)
					Elog("invalid --num-queues argument: %s", optarg);
				break;

			case 1005:	/* --parallel-write */
				arrow_file_desc_nums = strtol(optarg, &pos, 10);
				if (*pos != '\0' || arrow_file_desc_nums < 1)
					Elog("invalid --parallel-write argument: %s", optarg);
				break;

			case 1006:	/* --composite-options */
				composite_options = true;
				break;

			default:
				usage(code == 'h' ? 0 : 1);
				break;
		}
	}

	if (input_devname)
	{
		if (argc != optind)
			Elog("cannot use input device and PCAP files together");
	}
	else if (optind < argc)
	{
		int		i, nfiles = argc - optind;

		pcap_file_desc_array = palloc0(sizeof(pcapFileDesc) * nfiles);
		for (i=0; i < nfiles; i++)
		{
			pcapFileDesc   *pfdesc = &pcap_file_desc_array[i];
			const char	   *filename = argv[optind + i];
			FILE		   *filp;

			filp = fopen(filename, "rb");
			if (!filp)
				Elog("failed to open '%s': %m", filename);
			pfdesc->pcap_filp = filp;
			pfdesc->pcap_filename = pstrdup(filename);
		}
		pcap_file_desc_nums = nfiles;
	}
	else
	{
		/* input from stdin... */
		pcapFileDesc   *pfdesc = palloc0(sizeof(pcapFileDesc));

		pfdesc->pcap_filp = stdin;
		pfdesc->pcap_filename = "/dev/stdin";

		pcap_file_desc_nums = 1;
		pcap_file_desc_array = pfdesc;
	}

	for (pos = output_filename; *pos != '\0'; pos++)
	{
		if (*pos == '%')
		{
			pos++;
			switch (*pos)
			{
				case 'q':
				case 'i':
				case 'Y':
				case 'y':
				case 'm':
				case 'd':
				case 'H':
				case 'M':
				case 'S':
					/* ok supported */
					break;
				default:
					Elog("unknown format string '%c' in '%s'",
						 *pos, output_filename);
					break;
			}
		}
	}

	/*
	 * number of threads have different default; depending on the input
	 */
	if (input_devname)
	{
		if (pfring_desc_nums < 0)
			pfring_desc_nums = 4;
		if (num_threads < 0)
			num_threads = 2 * NCPUS;
		if (num_pcap_threads < 0)
			num_pcap_threads = 6 * pfring_desc_nums;
	}
	else
	{
		if (num_threads < 0)
			num_threads = pcap_file_desc_nums;
		if (num_pcap_threads >= 0)
			Elog("--pcap-threads cannot be used with PCAP input files");
		if (pfring_desc_nums >= 0)
			Elog("--num-queues cannot be used with PCAP input files");
		if (print_stat_interval > 0)
			Elog("-s|--stat should be used with -i|--input=DEV option");
	}
}

static void
pcap_print_stat(bool is_final_call)
{
	static int		print_stat_count = 0;
	static uint64_t last_raw_packet_length = 0;
	static uint64_t last_ip4_packet_count = 0;
	static uint64_t last_ip6_packet_count = 0;
	static uint64_t last_tcp_packet_count = 0;
	static uint64_t last_udp_packet_count = 0;
	static uint64_t last_icmp_packet_count = 0;
	static pfring_stat last_pfring_stat = {0,0,0};
	uint64_t curr_raw_packet_length = atomicRead64(&stat_raw_packet_length);
	uint64_t curr_ip4_packet_count = atomicRead64(&stat_ip4_packet_count);
	uint64_t curr_ip6_packet_count = atomicRead64(&stat_ip6_packet_count);
	uint64_t curr_tcp_packet_count = atomicRead64(&stat_tcp_packet_count);
	uint64_t curr_udp_packet_count = atomicRead64(&stat_udp_packet_count);
	uint64_t curr_icmp_packet_count = atomicRead64(&stat_icmp_packet_count);
	uint64_t diff_raw_packet_length;
	pfring_stat	curr_pfring_stat, temp;
	char		linebuf[1024];
	char	   *pos = linebuf;
	time_t		t = time(NULL);
	struct tm	tm;
	int			i;

	localtime_r(&t, &tm);
	pfring_stats(pfring_desc_array[0], &curr_pfring_stat);
	for (i=1; i < pfring_desc_nums; i++)
	{
		pfring_stats(pfring_desc_array[i], &temp);
		curr_pfring_stat.recv += temp.recv;
		curr_pfring_stat.drop += temp.drop;
	}

	if (is_final_call)
	{
		printf("Stats total:\n"
			   "Recv packets: %lu\n"
			   "Drop packets: %lu\n"
			   "Total bytes: %lu\n",
			   curr_pfring_stat.recv,
			   curr_pfring_stat.drop,
			   curr_raw_packet_length);
		if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
			printf("IPv4 packets: %lu\n", curr_ip4_packet_count);
		if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
			printf("IPv6 packets: %lu\n", curr_ip6_packet_count);
		if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
			printf("TCP packets: %lu\n", curr_tcp_packet_count);
		if ((protocol_mask & __PCAP_PROTO__UDP) != 0)
			printf("UDP packets: %lu\n", curr_udp_packet_count);
		if ((protocol_mask & __PCAP_PROTO__ICMP) != 0)
			printf("ICMP packets: %lu\n", curr_icmp_packet_count);
		return;
	}
	
	if ((print_stat_count++ % 10) == 0)
	{
		pos += sprintf(pos,
					   "%04d-%02d-%02d   <# Recv> <# Drop> <Total Sz>",
					   tm.tm_year + 1900,
                       tm.tm_mon + 1,
                       tm.tm_mday);
		if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
			pos += sprintf(pos, " <# IPv4>");
		if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
			pos += sprintf(pos, " <# IPv6>");
		if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
			pos += sprintf(pos, "  <# TCP>");
		if ((protocol_mask & __PCAP_PROTO__UDP) != 0)
			pos += sprintf(pos, "  <# UDP>");
		if ((protocol_mask & __PCAP_PROTO__ICMP) != 0)
			pos += sprintf(pos, " <# ICMP>");

		puts(linebuf);
		pos = linebuf;
	}

	pos += sprintf(pos,
				   " %02d:%02d:%02d   % 8ld % 8ld",
				   tm.tm_hour,
				   tm.tm_min,
				   tm.tm_sec,
				   curr_pfring_stat.recv - last_pfring_stat.recv,
				   curr_pfring_stat.drop - last_pfring_stat.drop);
	diff_raw_packet_length = curr_raw_packet_length - last_raw_packet_length;
	if (diff_raw_packet_length < 10000UL)
		pos += sprintf(pos, "  % 8ldB", diff_raw_packet_length);
	else if (diff_raw_packet_length < 10240000UL)
		pos += sprintf(pos, " % 8.2fKB",
					   (double)diff_raw_packet_length / 1024.0);
	else if (diff_raw_packet_length < 10485760000UL)
		pos += sprintf(pos, " % 8.2fMB",
					   (double)diff_raw_packet_length / 1048576.0);
	else
		pos += sprintf(pos, " % 8.2fGB",
					   (double)diff_raw_packet_length / 1073741824.0);
	
	if ((protocol_mask & __PCAP_PROTO__IPv4) != 0)
		pos += sprintf(pos, " % 8ld", (curr_ip4_packet_count -
									   last_ip4_packet_count));
	if ((protocol_mask & __PCAP_PROTO__IPv6) != 0)
		pos += sprintf(pos, " % 8ld", (curr_ip6_packet_count -
									   last_ip6_packet_count));
	if ((protocol_mask & __PCAP_PROTO__TCP) != 0)
		pos += sprintf(pos, " % 8ld", (curr_tcp_packet_count -
									   last_tcp_packet_count));
	if ((protocol_mask & __PCAP_PROTO__UDP) != 0)
		pos += sprintf(pos, " % 8ld", (curr_udp_packet_count -
									   last_udp_packet_count));
	if ((protocol_mask & __PCAP_PROTO__ICMP) != 0)
		pos += sprintf(pos, " % 8ld", (curr_icmp_packet_count -
									   last_icmp_packet_count));
	puts(linebuf);

	last_raw_packet_length	= curr_raw_packet_length;
	last_ip4_packet_count	= curr_ip4_packet_count;
	last_ip6_packet_count	= curr_ip6_packet_count;
	last_tcp_packet_count	= curr_tcp_packet_count;
	last_udp_packet_count	= curr_udp_packet_count;
	last_icmp_packet_count	= curr_icmp_packet_count;
	last_pfring_stat		= curr_pfring_stat;
}

/*
 * init_pfring_device_input - open the network device using PF-RING
 */
static void
init_pfring_input(void)
{
	uint32_t	cluster_id = (uint32_t)getpid();
	int			i, rv;
	
	pfring_desc_array = palloc0(sizeof(pfring *) * pfring_desc_nums);
	for (i=0; i < pfring_desc_nums; i++)
	{
		pfring *pd;

		pd = pfring_open(input_devname, 65536,
						 PF_RING_REENTRANT |
						 PF_RING_TIMESTAMP |
						 PF_RING_PROMISC);
		if (!pd)
			Elog("failed on pfring_open: %m - "
				 "pf_ring not loaded or interface %s is down?",
				 input_devname);

		rv = pfring_set_application_name(pd, "pcap2arrow");
		if (rv)
			Elog("failed on pfring_set_application_name");

		//NOTE: Is rx_only_direction right?
		rv = pfring_set_direction(pd, rx_only_direction);
		if (rv)
			Elog("failed on pfring_set_direction");

		rv = pfring_set_poll_duration(pd, 50);
		if (rv)
			Elog("failed on pfring_set_poll_duration");

		rv = pfring_set_socket_mode(pd, recv_only_mode);
		if (rv)
			Elog("failed on pfring_set_socket_mode");

		if (bpf_filter_rule)
		{
			rv = pfring_set_bpf_filter(pd, bpf_filter_rule);
			if (rv)
				Elog("failed on pfring_set_bpf_filter");
		}

		rv = pfring_set_cluster(pd, cluster_id, cluster_round_robin);
		if (rv)
			Elog("failed on pfring_set_cluster");

		rv = pfring_enable_ring(pd);
		if (rv)
			Elog("failed on pfring_enable_ring");

		pfring_desc_array[i] = pd;
	}
}

int main(int argc, char *argv[])
{
	pthread_t  *workers;
	long		i, rv;

	/* init misc variables */
	PAGESIZE = sysconf(_SC_PAGESIZE);
	NCPUS = sysconf(_SC_NPROCESSORS_ONLN);

	/* parse command line options */
	parse_options(argc, argv);
	/* chunk-buffer pre-allocation */
	arrow_chunks_array = palloc0(sizeof(SQLtable *) * num_threads);
	for (i=0; i < num_threads; i++)
	{
		SQLtable   *chunk;

		chunk = palloc0(offsetof(SQLtable,
								 columns[PCAP_SCHEMA_MAX_NFIELDS]));
		arrowPcapSchemaInit(chunk);
		chunk->fdesc = -1;
		arrow_chunks_array[i] = chunk;
	}

	if (input_devname)
		init_pfring_input();

	/* open the output files, and related initialization */
	arrow_file_desc_locks = palloc0(sizeof(pthread_mutex_t) * arrow_file_desc_nums);
	arrow_file_desc_array = palloc0(sizeof(arrowFileDesc *) * arrow_file_desc_nums);
	for (i=0; i < arrow_file_desc_nums; i++)
	{
		pthreadMutexInit(&arrow_file_desc_locks[i]);
		arrow_file_desc_array[i] = arrowOpenOutputFile();
	}

	if (num_pcap_threads >= 0)
	{
		if (sem_init(&pcap_worker_sem, 0, num_pcap_threads) != 0)
			Elog("failed on sem_init: %m");
	}
	/* ctrl-c handler */
	signal(SIGINT, on_sigint_handler);
	signal(SIGTERM, on_sigint_handler);
	
	/* launch worker threads */
	pthreadMutexInit(&arrow_workers_mutex);
	pthreadCondInit(&arrow_workers_cond);
	arrow_workers_completed = palloc0(sizeof(bool) * num_threads);

	workers = alloca(sizeof(pthread_t) * num_threads);
	for (i=0; i < num_threads; i++)
	{
		rv = pthread_create(&workers[i], NULL,
							input_devname ?
							pfring_worker_main :
							pcap_file_worker_main, (void *)i);
		if (rv != 0)
			Elog("failed on pthread_create: %s", strerror(rv));
	}
	/* print statistics */
	if (pfring_desc_array && print_stat_interval > 0)
	{
		sleep(print_stat_interval);
		while (!do_shutdown)
		{
			pcap_print_stat(false);
			sleep(print_stat_interval);
		}
		pcap_print_stat(true);
	}
	/* wait for completion */
	for (i=0; i < num_threads; i++)
	{
		rv = pthread_join(workers[i], NULL);
		if (rv != 0)
			Elog("failed on pthread_join: %s", strerror(rv));
	}
	/* close the output files */
	for (i=0; i < arrow_file_desc_nums; i++)
		arrowCloseOutputFile(arrow_file_desc_array[i]);
	return 0;
}

/*
 * memory allocation handlers
 */
void *
palloc(size_t sz)
{
	void   *ptr = malloc(sz);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}

void *
palloc0(size_t sz)
{
	void   *ptr = malloc(sz);

	if (!ptr)
		Elog("out of memory");
	memset(ptr, 0, sz);
	return ptr;
}

char *
pstrdup(const char *str)
{
	char   *ptr = strdup(str);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}

void *
repalloc(void *old, size_t sz)
{
	char   *ptr = realloc(old, sz);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}
