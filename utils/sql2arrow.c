/*
 * sql2arrow.c - main logic of xxx2arrow command
 *
 * Copyright 2020 (C) KaiGai Kohei <kaigai@heterodb.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the PostgreSQL License. See the LICENSE file.
 */
#include "sql2arrow.h"
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

/* command options */
static char	   *sqldb_command = NULL;
static char	   *output_filename = NULL;
static char	   *append_filename = NULL;
static size_t	batch_segment_sz = 0;
static char	   *sqldb_hostname = NULL;
static char	   *sqldb_port_num = NULL;
static char	   *sqldb_username = NULL;
static char	   *sqldb_password = NULL;
static char	   *sqldb_database = NULL;
static char	   *dump_arrow_filename = NULL;
static int		shows_progress = 0;
static userConfigOption *sqldb_session_configs = NULL;

/*
 * loadArrowDictionaryBatches
 */
static SQLdictionary *
__loadArrowDictionaryBatchOne(const char *message_head,
							  ArrowDictionaryBatch *dbatch)
{
	SQLdictionary  *dict;
	ArrowBuffer	   *v_buffer = &dbatch->data.buffers[1];
	ArrowBuffer	   *e_buffer = &dbatch->data.buffers[2];
	uint32_t		   *values = (uint32_t *)(message_head + v_buffer->offset);
	char		   *extra = (char *)(message_head + e_buffer->offset);
	int				i;

	dict = palloc0(offsetof(SQLdictionary, hslots[1024]));
	dict->dict_id = dbatch->id;
	sql_buffer_init(&dict->values);
	sql_buffer_init(&dict->extra);
	dict->nloaded = dbatch->data.length;
	dict->nitems  = dbatch->data.length;
	dict->nslots = 1024;

	for (i=0; i < dict->nloaded; i++)
	{
		hashItem   *hitem;
		uint32_t		len = values[i+1] - values[i];
		char	   *pos = extra + values[i];
		uint32_t		hindex;

		hitem = palloc(offsetof(hashItem, label[len+1]));
		hitem->hash = hash_any((unsigned char *)pos, len);
		hitem->index = i;
		hitem->label_sz = len;
		memcpy(hitem->label, pos, len);
		hitem->label[len] = '\0';
		
		hindex = hitem->hash % dict->nslots;
		hitem->next = dict->hslots[hindex];
		dict->hslots[hindex] = hitem;
	}
	assert(dict->nitems == dict->nloaded);
	return dict;
}

static SQLdictionary *
loadArrowDictionaryBatches(int fdesc, ArrowFileInfo *af_info)
{
	SQLdictionary *dictionary_list = NULL;
	size_t		mmap_sz;
	char	   *mmap_head = NULL;
	int			i;

	if (af_info->footer._num_dictionaries == 0)
		return NULL;	/* no dictionaries */
	mmap_sz = TYPEALIGN(sysconf(_SC_PAGESIZE), af_info->stat_buf.st_size);
	mmap_head = mmap(NULL, mmap_sz,
					 PROT_READ, MAP_SHARED,
					 fdesc, 0);
	if (mmap_head == MAP_FAILED)
		Elog("failed on mmap(2): %m");
	for (i=0; i < af_info->footer._num_dictionaries; i++)
	{
		ArrowBlock	   *block = &af_info->footer.dictionaries[i];
		ArrowDictionaryBatch *dbatch;
		SQLdictionary  *dict;
		char		   *message_head;
		char		   *message_body;

		dbatch = &af_info->dictionaries[i].body.dictionaryBatch;
		if (dbatch->node.tag != ArrowNodeTag__DictionaryBatch ||
			dbatch->data._num_nodes != 1 ||
			dbatch->data._num_buffers != 3)
			Elog("DictionaryBatch (dictionary_id=%ld) has unexpected format",
				 dbatch->id);
		message_head = mmap_head + block->offset;
		message_body = message_head + block->metaDataLength;
		dict = __loadArrowDictionaryBatchOne(message_body, dbatch);
		dict->next = dictionary_list;
		dictionary_list = dict;
	}
	munmap(mmap_head, mmap_sz);

	return dictionary_list;
}

/*
 * MEMO: Program termision may lead file corruption if arrow file is
 * already overwritten with --append mode. The callback below tries to
 * revert the arrow file using UNDO log; that is Footer portion saved
 * before any writing stuff.
 */
typedef struct
{
	int			append_fdesc;
	off_t		footer_offset;
	size_t		footer_length;
	char		footer_backup[FLEXIBLE_ARRAY_MEMBER];
} arrowFileUndoLog;

static arrowFileUndoLog	   *arrow_file_undo_log = NULL;

/*
 * fixup_append_file_on_exit
 */
static void
fixup_append_file_on_exit(int status, void *p)
{
	arrowFileUndoLog *undo = arrow_file_undo_log;
	ssize_t		count = 0;
	ssize_t		nbytes;

	if (status == 0 || !undo)
		return;
	/* avoid infinite recursion */
	arrow_file_undo_log = NULL;

	if (lseek(undo->append_fdesc,
			  undo->footer_offset, SEEK_SET) != undo->footer_offset)
	{
		fprintf(stderr, "failed on lseek(2) on applying undo log.\n");
		return;
	}

	while (count < undo->footer_length)
	{
		nbytes = write(undo->append_fdesc,
					   undo->footer_backup + count,
					   undo->footer_length - count);
		if (nbytes > 0)
			count += nbytes;
		else if (errno != EINTR)
		{
			fprintf(stderr, "failed on write(2) on applying undo log.\n");
			return;
		}
	}

	if (ftruncate(undo->append_fdesc,
				  undo->footer_offset + undo->footer_length) != 0)
	{
		fprintf(stderr, "failed on ftruncate(2) on applying undo log.\n");
		return;
	}
}

/*
 * fixup_append_file_on_signal
 */
static void
fixup_append_file_on_signal(int signum)
{
	fixup_append_file_on_exit(0x80 + signum, NULL);
	switch (signum)
	{
		/* SIG_DFL == Term */
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			exit(0x80 + signum);

		/* SIG_DFL == Core */
		default:
			fprintf(stderr, "unexpected signal (%d) was caught by %s\n",
					signum, __FUNCTION__);
		case SIGSEGV:
		case SIGBUS:
			abort();
	}
}

/*
 * setup_append_file
 */
static void
setup_append_file(SQLtable *table, ArrowFileInfo *af_info)
{
	arrowFileUndoLog *undo;
	uint32_t		nitems;
	ssize_t			nbytes;
	ssize_t			length;
	loff_t			offset;
	char		   *pos;
	char			buffer[64];

	/* restore DictionaryBatches already in the file */
	nitems = af_info->footer._num_dictionaries;
	table->numDictionaries = nitems;
	table->dictionaries = palloc0(sizeof(ArrowBlock) * nitems);
	memcpy(table->dictionaries,
		   af_info->footer.dictionaries,
		   sizeof(ArrowBlock) * nitems);

	/* restore RecordBatches already in the file */
	nitems = af_info->footer._num_recordBatches;
	table->numRecordBatches = nitems;
	table->recordBatches = palloc0(sizeof(ArrowBlock) * nitems);
	memcpy(table->recordBatches,
		   af_info->footer.recordBatches,
		   sizeof(ArrowBlock) * nitems);

	/* move to the file offset in front of the Footer portion */
	nbytes = sizeof(int32_t) + 6;		/* strlen("ARROW1") */
	offset = lseek(table->fdesc, -nbytes, SEEK_END);
	if (offset < 0)
		Elog("failed on lseek(%d, %zu, SEEK_END): %m",
			 table->fdesc, sizeof(int32_t) + 6);
	if (read(table->fdesc, buffer, nbytes) != nbytes)
		Elog("failed on read(2): %m");
	offset -= *((int32_t *)buffer);
	if (lseek(table->fdesc, offset, SEEK_SET) < 0)
		Elog("failed on lseek(%d, %zu, SEEK_SET): %m",
			 table->fdesc, offset);
	length = af_info->stat_buf.st_size - offset;

	/* makes Undo log to recover process termination */
	undo = palloc(offsetof(arrowFileUndoLog,
						   footer_backup[length]));
	undo->append_fdesc = table->fdesc;
	undo->footer_offset = offset;
	undo->footer_length = length;
	pos = undo->footer_backup;
	while (length > 0)
	{
		nbytes = pread(undo->append_fdesc,
					   pos, length, offset);
		if (nbytes > 0)
		{
			pos += nbytes;
			length -= nbytes;
			offset += nbytes;
		}
		else if (nbytes == 0)
			Elog("pread: unexpected EOF; arrow file corruption?");
		else if (nbytes < 0 && errno != EINTR)
			Elog("failed on pread(2): %m");
	}
	arrow_file_undo_log = undo;
	/* register callbacks for unexpected process termination */
	on_exit(fixup_append_file_on_exit, NULL);
	signal(SIGHUP,  fixup_append_file_on_signal);
	signal(SIGINT,  fixup_append_file_on_signal);
	signal(SIGTERM, fixup_append_file_on_signal);
	signal(SIGSEGV, fixup_append_file_on_signal);
	signal(SIGBUS,  fixup_append_file_on_signal);
}

/*
 * setup_output_file
 */
static void
setup_output_file(SQLtable *table, const char *output_filename)
{
	int		fdesc;
	ssize_t	nbytes;

	if (output_filename)
	{
		fdesc = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fdesc < 0)
			Elog("failed on open('%s'): %m", output_filename);
		table->fdesc = fdesc;
		table->filename = output_filename;
	}
	else
	{
		char	temp[200];

		strcpy(temp, "/tmp/XXXXXX.arrow");
		fdesc = mkostemps(temp, 6, O_RDWR | O_CREAT | O_TRUNC);
		if (fdesc < 0)
			Elog("failed on mkostemps('%s'): %m", temp);
		table->fdesc = fdesc;
		table->filename = pstrdup(temp);
		fprintf(stderr,
				"NOTICE: -o, --output=FILENAME option was not given,\n"
				"        so a temporary file '%s' was built instead.\n", temp);
	}
	/* write out header stuff */
	nbytes = write(table->fdesc, "ARROW1\0\0", 8);
	if (nbytes != 8)
		Elog("failed on write(2): %m");
	writeArrowSchema(table);
}

static void
shows_record_batch_progress(SQLtable *table, size_t nitems)
{
	if (shows_progress)
	{
		ArrowBlock *block;
		int			index = table->numRecordBatches - 1;

		assert(index >= 0);
		block = &table->recordBatches[index];
		printf("RecordBatch[%d]: "
			   "offset=%lu length=%lu (meta=%u, body=%lu) nitems=%zu\n",
			   index,
			   block->offset,
			   block->metaDataLength + block->bodyLength,
			   block->metaDataLength,
			   block->bodyLength,
			   nitems);
	}
}

static int
dumpArrowFile(const char *filename)
{
	ArrowFileInfo	af_info;
	int				i, fdesc;

	memset(&af_info, 0, sizeof(ArrowFileInfo));
	fdesc = open(filename, O_RDONLY);
	if (fdesc < 0)
		Elog("unable to open '%s': %m", filename);
	readArrowFileDesc(fdesc, &af_info);

	printf("[Footer]\n%s\n",
		   dumpArrowNode((ArrowNode *)&af_info.footer));

	for (i=0; i < af_info.footer._num_dictionaries; i++)
	{
		printf("[Dictionary Batch %d]\n%s\n%s\n", i,
			   dumpArrowNode((ArrowNode *)&af_info.footer.dictionaries[i]),
			   dumpArrowNode((ArrowNode *)&af_info.dictionaries[i]));
	}

	for (i=0; i < af_info.footer._num_recordBatches; i++)
	{
		printf("[Record Batch %d]\n%s\n%s\n", i,
			   dumpArrowNode((ArrowNode *)&af_info.footer.recordBatches[i]),
			   dumpArrowNode((ArrowNode *)&af_info.recordBatches[i]));
	}
	return 0;
}

static void
usage(void)
{
	fputs("Usage:\n"
#ifdef __PG2ARROW__
		  "  pg2arrow [OPTION] [database] [username]\n\n"
#else
		  "  mysql2arrow [OPTION] [database] [username]\n\n"
#endif
		  "General options:\n"
		  "  -d, --dbname=DBNAME   Database name to connect to\n"
		  "  -c, --command=COMMAND SQL command to run\n"
		  "  -t, --table=TABLENAME Table name to be dumped\n"
		  "      (-c and -t are exclusive, either of them must be given)\n"
		  "  -o, --output=FILENAME result file in Apache Arrow format\n"
		  "      --append=FILENAME result Apache Arrow file to be appended\n"
		  "      (--output and --append are exclusive. If neither of them\n"
		  "       are given, it creates a temporary file.)\n"
		  "\n"
		  "Arrow format options:\n"
		  "  -s, --segment-size=SIZE size of record batch for each\n"
		  "\n"
		  "Connection options:\n"
		  "  -h, --host=HOSTNAME  database server host\n"
		  "  -p, --port=PORT      database server port\n"
		  "  -u, --user=USERNAME  database user name\n"
#ifdef __PG2ARROW__
		  "  -w, --no-password    never prompt for password\n"
		  "  -W, --password       force password prompt\n"
#endif
#ifdef __MYSQL2ARROW__
		  "  -P, --password=PASS  Password to use when connecting to server\n"
#endif
		  "\n"
		  "Other options:\n"
		  "      --dump=FILENAME  dump information of arrow file\n"
		  "      --progress       shows progress of the job\n"
		  "      --set=NAME:VALUE config option to set before SQL execution\n"
		  "      --help           shows this message\n"
		  "\n"
		  "Report bugs to <pgstrom@heterodb.com>.\n",
		  stderr);
	exit(1);
}

static void
parse_options(int argc, char * const argv[])
{
	static struct option long_options[] = {
		{"dbname",       required_argument, NULL, 'd'},
		{"command",      required_argument, NULL, 'c'},
		{"table",        required_argument, NULL, 't'},
		{"output",       required_argument, NULL, 'o'},
		{"append",       required_argument, NULL, 1000},
		{"segment-size", required_argument, NULL, 's'},
		{"host",         required_argument, NULL, 'h'},
		{"port",         required_argument, NULL, 'p'},
		{"user",         required_argument, NULL, 'u'},
#ifdef __PG2ARROW__
		{"no-password",  no_argument,       NULL, 'w'},
		{"password",     no_argument,       NULL, 'W'},
#endif /* __PG2ARROW__ */
#ifdef __MYSQL2ARROW__
		{"password",     required_argument, NULL, 'P'},
#endif /* __MYSQL2ARROW__ */
		{"dump",         required_argument, NULL, 1001},
		{"progress",     no_argument,       NULL, 1002},
		{"set",          required_argument, NULL, 1003},
		{"help",         no_argument,       NULL, 9999},
		{NULL, 0, NULL, 0},
	};
	int			c;
	bool		meet_command = false;
	bool		meet_table = false;
	int			password_prompt = 0;
	const char *pos;
	userConfigOption *last_user_config = NULL;

	while ((c = getopt_long(argc, argv, "d:c:t:o:s:h:P:u:p:",
							long_options, NULL)) >= 0)
	{
		switch (c)
		{
			case 'd':
				if (sqldb_database)
					Elog("-d option was supplied twice");
				sqldb_database = optarg;
				break;

			case 'c':
				if (meet_command)
					Elog("-c option was supplied twice");
				if (meet_table)
					Elog("-c and -t options are exclusive");
				sqldb_command = optarg;
				break;

			case 't':
				if (meet_table)
					Elog("-t option was supplied twice");
				if (meet_command)
					Elog("-c and -t options are exclusive");
				sqldb_command = malloc(100 + strlen(optarg));
				if (!sqldb_command)
					Elog("out of memory");
				sprintf(sqldb_command, "SELECT * FROM %s", optarg);
				break;

			case 'o':
				if (output_filename)
					Elog("-o option was supplied twice");
				if (append_filename)
					Elog("-o and --append are exclusive");
				output_filename = optarg;
				break;

			case 1000:		/* --append */
				if (append_filename)
					Elog("--append option was supplied twice");
				if (output_filename)
					Elog("-o and --append are exclusive");
				append_filename = optarg;
				break;
				
			case 's':
				if (batch_segment_sz != 0)
					Elog("-s option was supplied twice");
				pos = optarg;
				while (isdigit(*pos))
					pos++;
				if (*pos == '\0')
					batch_segment_sz = atol(optarg);
				else if (strcasecmp(pos, "k") == 0 ||
						 strcasecmp(pos, "kb") == 0)
					batch_segment_sz = atol(optarg) * (1UL << 10);
				else if (strcasecmp(pos, "m") == 0 ||
						 strcasecmp(pos, "mb") == 0)
					batch_segment_sz = atol(optarg) * (1UL << 20);
				else if (strcasecmp(pos, "g") == 0 ||
						 strcasecmp(pos, "gb") == 0)
					batch_segment_sz = atol(optarg) * (1UL << 30);
				else
					Elog("segment size is not valid: %s", optarg);
				break;

			case 'h':
				if (sqldb_hostname)
					Elog("-h option was supplied twice");
				sqldb_hostname = optarg;
				break;

			case 'p':
				if (sqldb_port_num)
					Elog("-p option was supplied twice");
				sqldb_port_num = optarg;
				break;

			case 'u':
				if (sqldb_username)
					Elog("-u option was supplied twice");
				sqldb_username = optarg;
				break;
#ifdef __PG2ARROW__
			case 'w':
				if (password_prompt > 0)
					Elog("-w and -W options are exclusive");
				password_prompt = -1;
				break;
			case 'W':
				if (password_prompt < 0)
					Elog("-w and -W options are exclusive");
				password_prompt = 1;
				break;
#endif	/* __PG2ARROW__ */
#ifdef __MYSQL2ARROW__
			case 'P':
				if (sqldb_password)
					Elog("-p option was supplied twice");
				sqldb_password = optarg;
				break;
#endif /* __MYSQL2ARROW__ */
			case 1001:		/* --dump */
				if (dump_arrow_filename)
					Elog("--dump option was supplied twice");
				dump_arrow_filename = optarg;
				break;

			case 1002:		/* --progress */
				if (shows_progress)
					Elog("--progress option was supplied twice");
				shows_progress = 1;
				break;

			case 1003:		/* --set */
				{
					userConfigOption *conf;
					char   *pos, *tail;

					pos = strchr(optarg, ':');
					if (!pos)
						Elog("--set option should take NAME:VALUE");
					*pos++ = '\0';
					while (isspace(*pos))
                        pos++;
					while (tail > pos && isspace(*tail))
						tail--;
					conf = palloc0(sizeof(userConfigOption) +
								   strlen(optarg) + strlen(pos) + 40);
					sprintf(conf->query, "SET %s = '%s'", optarg, pos);
					if (last_user_config)
						last_user_config->next = conf;
					else
						sqldb_session_configs = conf;
					last_user_config = conf;
				}
				break;

			case 9999:		/* --help */
			default:
				usage();
				break;
		}
	}

	if (optind + 1 == argc)
	{
		if (sqldb_database)
			Elog("database name was supplied twice");
		sqldb_database = argv[optind];
	}
	else if (optind + 2 == argc)
	{
		if (sqldb_database)
			Elog("database name was supplied twice");
		if (sqldb_username)
			Elog("database user was specified twice");
		sqldb_database = argv[optind];
		sqldb_username = argv[optind + 1];
	}
	else if (optind != argc)
		Elog("too much command line arguments");
	/* password prompt, if -W option is supplied */
	if (password_prompt > 0)
	{
		assert(!sqldb_password);
		sqldb_password = pstrdup(getpass("Password: "));
	}
	/* --dump is exclusive other options */
	if (dump_arrow_filename)
	{
		if (sqldb_command || output_filename || append_filename)
			Elog("--dump option is exclusive with -c, -t, -o and --append");
		return;
	}
	if (!sqldb_command)
		Elog("Neither -c nor -t options are supplied");
	if (batch_segment_sz == 0)
		batch_segment_sz = (1UL << 28);		/* 256MB in default */
}

/*
 * Entrypoint of mysql2arrow
 */
int main(int argc, char * const argv[])
{
	int				append_fdesc = -1;
	ArrowFileInfo	af_info;
	void		   *sqldb_state;
	SQLtable	   *table;
	ArrowKeyValue  *kv;
	ssize_t			usage;
	SQLdictionary  *sql_dict_list = NULL;
	
	parse_options(argc, argv);

	/* special case if --dump=FILENAME */
	if (dump_arrow_filename)
		return dumpArrowFile(dump_arrow_filename);

	/* open connection */
	sqldb_state = sqldb_server_connect(sqldb_hostname,
									   sqldb_port_num,
									   sqldb_username,
									   sqldb_password,
									   sqldb_database,
									   sqldb_session_configs);
	/* read the original arrow file, if --append mode */
	if (append_filename)
	{
		append_fdesc = open(append_filename, O_RDWR, 0644);
		if (append_fdesc < 0)
			Elog("failed on open('%s'): %m", append_filename);
		readArrowFileDesc(append_fdesc, &af_info);
		sql_dict_list = loadArrowDictionaryBatches(append_fdesc, &af_info);
	}
	/* begin SQL command execution */
	table = sqldb_begin_query(sqldb_state,
							  sqldb_command,
							  append_filename ? &af_info : NULL,
							  sql_dict_list);
	if (!table)
		Elog("Empty results by the query: %s", sqldb_command);
	table->segment_sz = batch_segment_sz;

	/* save the SQL command as custom metadata */
	kv = palloc0(sizeof(ArrowKeyValue));
	initArrowNode(kv, KeyValue);
	kv->key = "sql_command";
	kv->_key_len = 11;
	kv->value = sqldb_command;
	kv->_value_len = strlen(sqldb_command);
	table->customMetadata = kv;
	table->numCustomMetadata = 1;
	
	/* open & setup result file */
	if (!append_filename)
		setup_output_file(table, output_filename);
	else
	{
		table->fdesc = append_fdesc;
		table->filename = append_filename;
		setup_append_file(table, &af_info);
	}
	/* write out dictionary batch, if any */
	writeArrowDictionaryBatches(table);
	/* main loop to fetch and write result */
	while ((usage = sqldb_fetch_results(sqldb_state, table)) >= 0)
	{
		if (usage > batch_segment_sz)
		{
			size_t		nitems = table->nitems;

			writeArrowRecordBatch(table);
			shows_record_batch_progress(table, nitems);
		}
	}
	if (table->nitems > 0)
	{
		size_t		nitems = table->nitems;

		writeArrowRecordBatch(table);
		shows_record_batch_progress(table, nitems);
	}
	/* write out footer portion */
	writeArrowFooter(table);

	/* cleanup */
	sqldb_close_connection(sqldb_state);
	close(table->fdesc);

	return 0;
}

/*
 * This hash function was written by Bob Jenkins
 * (bob_jenkins@burtleburtle.net), and superficially adapted
 * for PostgreSQL by Neil Conway. For more information on this
 * hash function, see http://burtleburtle.net/bob/hash/doobs.html,
 * or Bob's article in Dr. Dobb's Journal, Sept. 1997.
 *
 * In the current code, we have adopted Bob's 2006 update of his hash
 * function to fetch the data a word at a time when it is suitably aligned.
 * This makes for a useful speedup, at the cost of having to maintain
 * four code paths (aligned vs unaligned, and little-endian vs big-endian).
 * It also uses two separate mixing functions mix() and final(), instead
 * of a slower multi-purpose function.
 */

/* Get a bit mask of the bits set in non-uint32 aligned addresses */
#define UINT32_ALIGN_MASK (sizeof(uint32_t) - 1)

/* Rotate a uint32 value left by k bits - note multiple evaluation! */
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/*----------
 * mix -- mix 3 32-bit values reversibly.
 *
 * This is reversible, so any information in (a,b,c) before mix() is
 * still in (a,b,c) after mix().
 *
 * If four pairs of (a,b,c) inputs are run through mix(), or through
 * mix() in reverse, there are at least 32 bits of the output that
 * are sometimes the same for one pair and different for another pair.
 * This was tested for:
 * * pairs that differed by one bit, by two bits, in any combination
 *	 of top bits of (a,b,c), or in any combination of bottom bits of
 *	 (a,b,c).
 * * "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
 *	 the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
 *	 is commonly produced by subtraction) look like a single 1-bit
 *	 difference.
 * * the base values were pseudorandom, all zero but one bit set, or
 *	 all zero plus a counter that starts at zero.
 *
 * This does not achieve avalanche.  There are input bits of (a,b,c)
 * that fail to affect some output bits of (a,b,c), especially of a.  The
 * most thoroughly mixed value is c, but it doesn't really even achieve
 * avalanche in c.
 *
 * This allows some parallelism.  Read-after-writes are good at doubling
 * the number of bits affected, so the goal of mixing pulls in the opposite
 * direction from the goal of parallelism.  I did what I could.  Rotates
 * seem to cost as much as shifts on every machine I could lay my hands on,
 * and rotates are much kinder to the top and bottom bits, so I used rotates.
 *----------
 */
#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);	c += b; \
  b -= a;  b ^= rot(a, 6);	a += c; \
  c -= b;  c ^= rot(b, 8);	b += a; \
  a -= c;  a ^= rot(c,16);	c += b; \
  b -= a;  b ^= rot(a,19);	a += c; \
  c -= b;  c ^= rot(b, 4);	b += a; \
}

/*----------
 * final -- final mixing of 3 32-bit values (a,b,c) into c
 *
 * Pairs of (a,b,c) values differing in only a few bits will usually
 * produce values of c that look totally different.  This was tested for
 * * pairs that differed by one bit, by two bits, in any combination
 *	 of top bits of (a,b,c), or in any combination of bottom bits of
 *	 (a,b,c).
 * * "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
 *	 the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
 *	 is commonly produced by subtraction) look like a single 1-bit
 *	 difference.
 * * the base values were pseudorandom, all zero but one bit set, or
 *	 all zero plus a counter that starts at zero.
 *
 * The use of separate functions for mix() and final() allow for a
 * substantial performance increase since final() does not need to
 * do well in reverse, but is does need to affect all output bits.
 * mix(), on the other hand, does not need to affect all output
 * bits (affecting 32 bits is enough).  The original hash function had
 * a single mixing operation that had to satisfy both sets of requirements
 * and was slower as a result.
 *----------
 */
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c, 4); \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

/*
 * hash_any() -- hash a variable-length key into a 32-bit value
 *		k		: the key (the unaligned variable-length array of bytes)
 *		len		: the length of the key, counting by bytes
 *
 * Returns a uint32 value.  Every bit of the key affects every bit of
 * the return value.  Every 1-bit and 2-bit delta achieves avalanche.
 * About 6*len+35 instructions. The best hash table sizes are powers
 * of 2.  There is no need to do mod a prime (mod is sooo slow!).
 * If you need less than 32 bits, use a bitmask.
 *
 * This procedure must never throw elog(ERROR); the ResourceOwner code
 * relies on this not to fail.
 *
 * Note: we could easily change this function to return a 64-bit hash value
 * by using the final values of both b and c.  b is perhaps a little less
 * well mixed than c, however.
 */
uint64_t
hash_any(const unsigned char *k, int keylen)
{
	register uint32_t a, b, c, len;

	/* Set up the internal state */
	len = keylen;
	a = b = c = 0x9e3779b9 + len + 3923095;

	/* If the source pointer is word-aligned, we use word-wide fetches */
	if (((uintptr_t) k & UINT32_ALIGN_MASK) == 0)
	{
		/* Code path for aligned source data */
		register const uint32_t *ka = (const uint32_t *) k;

		/* handle most of the key */
		while (len >= 12)
		{
			a += ka[0];
			b += ka[1];
			c += ka[2];
			mix(a, b, c);
			ka += 3;
			len -= 12;
		}

		/* handle the last 11 bytes */
		k = (const unsigned char *) ka;
#ifdef WORDS_BIGENDIAN
		switch (len)
		{
			case 11:
				c += ((uint32_t) k[10] << 8);
				/* fall through */
			case 10:
				c += ((uint32_t) k[9] << 16);
				/* fall through */
			case 9:
				c += ((uint32_t) k[8] << 24);
				/* fall through */
			case 8:
				/* the lowest byte of c is reserved for the length */
				b += ka[1];
				a += ka[0];
				break;
			case 7:
				b += ((uint32_t) k[6] << 8);
				/* fall through */
			case 6:
				b += ((uint32_t) k[5] << 16);
				/* fall through */
			case 5:
				b += ((uint32_t) k[4] << 24);
				/* fall through */
			case 4:
				a += ka[0];
				break;
			case 3:
				a += ((uint32_t) k[2] << 8);
				/* fall through */
			case 2:
				a += ((uint32_t) k[1] << 16);
				/* fall through */
			case 1:
				a += ((uint32_t) k[0] << 24);
				/* case 0: nothing left to add */
		}
#else							/* !WORDS_BIGENDIAN */
		switch (len)
		{
			case 11:
				c += ((uint32_t) k[10] << 24);
				/* fall through */
			case 10:
				c += ((uint32_t) k[9] << 16);
				/* fall through */
			case 9:
				c += ((uint32_t) k[8] << 8);
				/* fall through */
			case 8:
				/* the lowest byte of c is reserved for the length */
				b += ka[1];
				a += ka[0];
				break;
			case 7:
				b += ((uint32_t) k[6] << 16);
				/* fall through */
			case 6:
				b += ((uint32_t) k[5] << 8);
				/* fall through */
			case 5:
				b += k[4];
				/* fall through */
			case 4:
				a += ka[0];
				break;
			case 3:
				a += ((uint32_t) k[2] << 16);
				/* fall through */
			case 2:
				a += ((uint32_t) k[1] << 8);
				/* fall through */
			case 1:
				a += k[0];
				/* case 0: nothing left to add */
		}
#endif							/* WORDS_BIGENDIAN */
	}
	else
	{
		/* Code path for non-aligned source data */

		/* handle most of the key */
		while (len >= 12)
		{
#ifdef WORDS_BIGENDIAN
			a += (k[3] +
				  ((uint32_t) k[2] << 8) +
				  ((uint32_t) k[1] << 16) +
				  ((uint32_t) k[0] << 24));
			b += (k[7] +
				  ((uint32_t) k[6] << 8) +
				  ((uint32_t) k[5] << 16) +
				  ((uint32_t) k[4] << 24));
			c += (k[11] +
				  ((uint32_t) k[10] << 8) +
				  ((uint32_t) k[9] << 16) +
				  ((uint32_t) k[8] << 24));
#else					/* !WORDS_BIGENDIAN */
			a += (k[0] +
				  ((uint32_t) k[1] << 8) +
				  ((uint32_t) k[2] << 16) +
				  ((uint32_t) k[3] << 24));
			b += (k[4] +
				  ((uint32_t) k[5] << 8) +
				  ((uint32_t) k[6] << 16) +
				  ((uint32_t) k[7] << 24));
			c += (k[8] +
				  ((uint32_t) k[9] << 8) +
				  ((uint32_t) k[10] << 16) +
				  ((uint32_t) k[11] << 24));
#endif					/* WORDS_BIGENDIAN */
			mix(a, b, c);
			k += 12;
			len -= 12;
		}

		/* handle the last 11 bytes */
#ifdef WORDS_BIGENDIAN
		switch (len)
		{
			case 11:
				c += ((uint32_t) k[10] << 8);
				/* fall through */
			case 10:
				c += ((uint32_t) k[9] << 16);
				/* fall through */
			case 9:
				c += ((uint32_t) k[8] << 24);
				/* fall through */
			case 8:
				/* the lowest byte of c is reserved for the length */
				b += k[7];
				/* fall through */
			case 7:
				b += ((uint32_t) k[6] << 8);
				/* fall through */
			case 6:
				b += ((uint32_t) k[5] << 16);
				/* fall through */
			case 5:
				b += ((uint32_t) k[4] << 24);
				/* fall through */
			case 4:
				a += k[3];
				/* fall through */
			case 3:
				a += ((uint32_t) k[2] << 8);
				/* fall through */
			case 2:
				a += ((uint32_t) k[1] << 16);
				/* fall through */
			case 1:
				a += ((uint32_t) k[0] << 24);
				/* case 0: nothing left to add */
		}
#else							/* !WORDS_BIGENDIAN */
		switch (len)
		{
			case 11:
				c += ((uint32_t) k[10] << 24);
				/* fall through */
			case 10:
				c += ((uint32_t) k[9] << 16);
				/* fall through */
			case 9:
				c += ((uint32_t) k[8] << 8);
				/* fall through */
			case 8:
				/* the lowest byte of c is reserved for the length */
				b += ((uint32_t) k[7] << 24);
				/* fall through */
			case 7:
				b += ((uint32_t) k[6] << 16);
				/* fall through */
			case 6:
				b += ((uint32_t) k[5] << 8);
				/* fall through */
			case 5:
				b += k[4];
				/* fall through */
			case 4:
				a += ((uint32_t) k[3] << 24);
				/* fall through */
			case 3:
				a += ((uint32_t) k[2] << 16);
				/* fall through */
			case 2:
				a += ((uint32_t) k[1] << 8);
				/* fall through */
			case 1:
				a += k[0];
				/* case 0: nothing left to add */
		}
#endif							/* WORDS_BIGENDIAN */
	}

	final(a, b, c);

	/* report the result */
	return c;
}





