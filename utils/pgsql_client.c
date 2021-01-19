/*
 * pgsql_client.c - MySQL specific portion for mysql2arrow command
 *
 * Copyright 2020 (C) KaiGai Kohei <kaigai@heterodb.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the PostgreSQL License. See the LICENSE file.
 */
#include "sql2arrow.h"
#include <limits.h>
#include <libpq-fe.h>

#define CURSOR_NAME		"curr_pg2arrow"
static char	   *server_timezone = NULL;

static void		pgsql_setup_composite_type(PGconn *conn,
										   SQLtable *root,
										   SQLfield *attr,
										   Oid comptype_relid,
										   ArrowField *arrow_field,
										   int *p_numFieldNodes,
										   int *p_numBuffers);
static void		pgsql_setup_array_element(PGconn *conn,
										  SQLtable *root,
										  SQLfield *attr,
										  Oid typelemid,
										  ArrowField *arrow_field,
										  int *p_numFieldNode,
										  int *p_numBuffers);

typedef struct
{
	PGconn	   *conn;
	PGresult   *res;
	uint32_t	nitems;
	uint32_t	index;
} PGSTATE;

static inline bool
pg_strtobool(const char *v)
{
	if (strcasecmp(v, "t") == 0 ||
		strcasecmp(v, "true") == 0 ||
		strcmp(v, "1") == 0)
		return true;
	else if (strcasecmp(v, "f") == 0 ||
			 strcasecmp(v, "false") == 0 ||
			 strcmp(v, "0") == 0)
		return false;
	Elog("unexpected boolean type literal: %s", v);
}

static inline char
pg_strtochar(const char *v)
{
	if (strlen(v) == 0)
		Elog("unexpected empty string");
	if (strlen(v) > 1)
		Elog("unexpected character string");
	return *v;
}

static PGconn *
pgsql_server_connect(const char *sqldb_hostname,
                     const char *sqldb_port_num,
                     const char *sqldb_username,
                     const char *sqldb_password,
                     const char *sqldb_database)
{
	PGconn	   *conn;
	const char *keys[20];
	const char *values[20];
	int			index = 0;
	int			status;

	if (sqldb_hostname)
	{
		keys[index] = "host";
		values[index] = sqldb_hostname;
		index++;
	}
	if (sqldb_port_num)
	{
		keys[index] = "port";
		values[index] = sqldb_port_num;
		index++;
	}
	if (sqldb_username)
	{
		keys[index] = "user";
		values[index] = sqldb_username;
		index++;
	}
	if (sqldb_password)
	{
		keys[index] = "password";
		values[index] = sqldb_password;
		index++;
	}
	if (sqldb_database)
	{
		keys[index] = "dbname";
		values[index] = sqldb_database;
		index++;
	}
	keys[index] = "application_name";
	values[index] = "pg2arrow";
	index++;
	/* terminal */
	keys[index] = NULL;
	values[index] = NULL;

	conn = PQconnectdbParams(keys, values, 0);
	if (!conn)
		Elog("out of memory");
	status = PQstatus(conn);
	if (status != CONNECTION_OK)
		Elog("failed on PostgreSQL connection: %s",
			 PQerrorMessage(conn));
	return conn;
}

/*
 * pgsql_next_result
 */
static PGresult *
pgsql_next_result(PGSTATE *pgstate)
{
	const char *query = "FETCH FORWARD 500000 FROM " CURSOR_NAME;
	PGconn	   *conn = pgstate->conn;
	PGresult   *res;

	if (pgstate->res)
	{
		PQclear(pgstate->res);
		pgstate->res = NULL;
	}
	res = PQexecParams(conn, query, 0, NULL, NULL, NULL, NULL,
					   1);  /* results in binary mode */
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		Elog("SQL execution failed: %s", PQresultErrorMessage(res));
	pgstate->nitems = PQntuples(res);
	pgstate->index  = 0;
	if (pgstate->nitems == 0)
	{
		PQclear(res);
		res = NULL;
	}
	pgstate->res = res;
	return res;
}

/*
 * pgsql_create_dictionary
 */
static SQLdictionary *
pgsql_create_dictionary(PGconn *conn, SQLtable *root,
						Oid enum_typeid,
						ArrowField *arrow_field)
{
	SQLdictionary *dict = NULL;
	PGresult   *res;
	char		query[4096];
	int			i, nitems;
	int64_t		dict_id = enum_typeid;

	if (arrow_field)
	{
		assert(arrow_field->dictionary);
		dict_id = arrow_field->dictionary->id;
	}

	for (dict = root->sql_dict_list; dict != NULL; dict = dict->next)
	{
		if (dict->dict_id == dict_id)
			break;
	}
	if (!dict)
	{
		dict = palloc0(offsetof(SQLdictionary, hslots[1024]));
		dict->dict_id = dict_id;
		sql_buffer_init(&dict->values);
		sql_buffer_init(&dict->extra);
		dict->nslots = 1024;

		dict->next = root->sql_dict_list;
		root->sql_dict_list = dict;
	}

	snprintf(query, sizeof(query),
			 "SELECT enumlabel"
			 "  FROM pg_catalog.pg_enum"
			 " WHERE enumtypid = %u", enum_typeid);
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		Elog("failed on pg_enum system catalog query: %s",
			 PQresultErrorMessage(res));
	nitems = PQntuples(res);
	for (i=0; i < nitems; i++)
	{
		const char *enumlabel = PQgetvalue(res, i, 0);
		hashItem   *hitem;
		uint32_t	hash, hindex;
		size_t		sz;

		if (PQgetisnull(res, i, 0) != 0)
			Elog("Unexpected result from pg_enum system catalog");

		sz = strlen(enumlabel);
		hash = hash_any((const unsigned char *)enumlabel, sz);
		hindex = hash % dict->nslots;
		for (hitem = dict->hslots[hindex]; hitem != NULL; hitem = hitem->next)
		{
			if (hitem->hash == hash &&
				hitem->label_sz == sz &&
				strcmp(hitem->label, enumlabel) == 0)
				break;
		}

		if (!hitem)
		{
			hitem = palloc0(offsetof(hashItem, label[sz+1]));
			hitem->hash = hash;
			hitem->index = dict->nitems++;
			hitem->label_sz = sz;
			strcpy(hitem->label, enumlabel);

			hitem->next = dict->hslots[hindex];
			dict->hslots[hindex] = hitem;

			sql_buffer_append(&dict->extra, enumlabel, sz);
			if (dict->values.usage == 0)
				sql_buffer_append_zero(&dict->values, sizeof(uint32_t));
			sql_buffer_append(&dict->values,
							  &dict->extra.usage, sizeof(uint32_t));
		}
	}
	PQclear(res);

	return dict;
}

/*
 * pgsql_setup_attribute
 */
static void
pgsql_setup_attribute(PGconn *conn,
					  SQLtable *root,
					  SQLfield *column,
					  const char *attname,
					  Oid atttypid,
					  int atttypmod,
					  int attlen,
					  char attbyval,
					  char attalign,
					  char typtype,
					  Oid typrelid,     /* valid, if composite type */
					  Oid typelemid,    /* valid, if array type */
					  const char *nspname,
					  const char *typname,
					  ArrowField *arrow_field,
					  int *p_numFieldNodes,
					  int *p_numBuffers)
{
	*p_numFieldNodes += 1;
	*p_numBuffers += assignArrowTypePgSQL(column,
										  attname,
										  atttypid,
										  atttypmod,
										  typname,
										  nspname,
										  attlen,
										  attbyval,
										  typtype,
										  attalign,
										  typrelid,
										  typelemid,
										  server_timezone,
										  arrow_field);
	if (typrelid != InvalidOid)
	{
		assert(typtype == 'c');
		pgsql_setup_composite_type(conn, root, column,
								   typrelid,
								   arrow_field,
								   p_numFieldNodes,
								   p_numBuffers);
	}
	else if (typelemid != InvalidOid)
	{
		pgsql_setup_array_element(conn, root, column,
								  typelemid,
								  arrow_field,
								  p_numFieldNodes,
								  p_numBuffers);
	}
	else if (typtype == 'e')
	{
		column->enumdict = pgsql_create_dictionary(conn, root, atttypid,
												   arrow_field);
	}
}

/*
 * pgsql_setup_composite_type
 */
static void
pgsql_setup_composite_type(PGconn *conn,
						   SQLtable *root,
						   SQLfield *attr,
						   Oid comptype_relid,
						   ArrowField *arrow_field,
						   int *p_numFieldNodes,
						   int *p_numBuffers)						   
{
	PGresult   *res;
	SQLfield *subfields;
	char		query[4096];
	int			j, nfields;

	snprintf(query, sizeof(query),
			 "SELECT attname, attnum, atttypid, atttypmod, attlen,"
			 "       attbyval, attalign, typtype, typrelid, typelem,"
			 "       nspname, typname"
			 "  FROM pg_catalog.pg_attribute a,"
			 "       pg_catalog.pg_type t,"
			 "       pg_catalog.pg_namespace n"
			 " WHERE t.typnamespace = n.oid"
			 "   AND a.atttypid = t.oid"
			 "   AND a.attrelid = %u", comptype_relid);
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		Elog("failed on pg_type system catalog query: %s",
			 PQresultErrorMessage(res));

	nfields = PQntuples(res);
	if (arrow_field &&
		arrow_field->_num_children != nfields)
		Elog("unexpected number of child fields in ArrowField");
	subfields = palloc0(sizeof(SQLfield) * nfields);
	for (j=0; j < nfields; j++)
	{
		const char *attname   = PQgetvalue(res, j, 0);
		const char *attnum    = PQgetvalue(res, j, 1);
		const char *atttypid  = PQgetvalue(res, j, 2);
		const char *atttypmod = PQgetvalue(res, j, 3);
		const char *attlen    = PQgetvalue(res, j, 4);
		const char *attbyval  = PQgetvalue(res, j, 5);
		const char *attalign  = PQgetvalue(res, j, 6);
		const char *typtype   = PQgetvalue(res, j, 7);
		const char *typrelid  = PQgetvalue(res, j, 8);
		const char *typelem   = PQgetvalue(res, j, 9);
		const char *nspname   = PQgetvalue(res, j, 10);
		const char *typname   = PQgetvalue(res, j, 11);
		ArrowField *sub_field = NULL;
		int			index     = atoi(attnum);

		if (index < 1 || index > nfields)
			Elog("attribute number is out of range");
		if (arrow_field)
			sub_field = &arrow_field->children[index-1];
		pgsql_setup_attribute(conn,
							  root,
							  &subfields[index-1],
							  attname,
							  atooid(atttypid),
							  atoi(atttypmod),
							  atoi(attlen),
							  pg_strtobool(attbyval),
							  pg_strtochar(attalign),
							  pg_strtochar(typtype),
							  atooid(typrelid),
							  atooid(typelem),
							  nspname,
							  typname,
							  sub_field,
							  p_numFieldNodes,
							  p_numBuffers);
	}
	attr->nfields = nfields;
	attr->subfields = subfields;
}

static void
pgsql_setup_array_element(PGconn *conn,
						  SQLtable *root,
						  SQLfield *attr,
						  Oid typelemid,
						  ArrowField *arrow_field,
						  int *p_numFieldNode,
						  int *p_numBuffers)
{
	SQLfield	   *element = palloc0(sizeof(SQLfield));
	PGresult	   *res;
	char			query[4096];
	const char     *nspname;
	const char	   *typname;
	const char	   *typlen;
	const char	   *typbyval;
	const char	   *typalign;
	const char	   *typtype;
	const char	   *typrelid;
	const char	   *typelem;
	ArrowField	   *elem_field = NULL;

	snprintf(query, sizeof(query),
			 "SELECT nspname, typname,"
			 "       typlen, typbyval, typalign, typtype,"
			 "       typrelid, typelem"
			 "  FROM pg_catalog.pg_type t,"
			 "       pg_catalog.pg_namespace n"
			 " WHERE t.typnamespace = n.oid"
			 "   AND t.oid = %u", typelemid);
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		Elog("failed on pg_type system catalog query: %s",
			 PQresultErrorMessage(res));
	if (PQntuples(res) != 1)
		Elog("unexpected number of result rows: %d", PQntuples(res));
	nspname  = PQgetvalue(res, 0, 0);
	typname  = PQgetvalue(res, 0, 1);
	typlen   = PQgetvalue(res, 0, 2);
	typbyval = PQgetvalue(res, 0, 3);
	typalign = PQgetvalue(res, 0, 4);
	typtype  = PQgetvalue(res, 0, 5);
	typrelid = PQgetvalue(res, 0, 6);
	typelem  = PQgetvalue(res, 0, 7);

	if (arrow_field)
	{
		if (arrow_field->_num_children != 1)
			Elog("unexpected number of child fields in ArrowField");
		elem_field = &arrow_field->children[0];
	}
	pgsql_setup_attribute(conn,
						  root,
						  element,
						  typname,
						  typelemid,
						  -1,
						  atoi(typlen),
						  pg_strtobool(typbyval),
						  pg_strtochar(typalign),
						  pg_strtochar(typtype),
						  atooid(typrelid),
						  atooid(typelem),
						  nspname,
						  typname,
						  elem_field,
						  p_numFieldNode,
						  p_numBuffers);
	attr->element = element;
}

/*
 * pgsql_create_buffer
 */
static SQLtable *
pgsql_create_buffer(PGconn *conn, PGresult *res,
					ArrowFileInfo *af_info,
					SQLdictionary *sql_dict_list)
{
	SQLtable   *table;
	int			j, nfields = PQnfields(res);

	table = palloc0(offsetof(SQLtable, columns[nfields]));
    table->nitems = 0;
    table->nfields = nfields;
	table->sql_dict_list = sql_dict_list;

	if (af_info &&
		af_info->footer.schema._num_fields != nfields)
		Elog("number of the fields mismatch");

	for (j=0; j < nfields; j++)
	{
		const char *attname = PQfname(res, j);
		Oid			atttypid = PQftype(res, j);
		int			atttypmod = PQfmod(res, j);
		PGresult   *__res;
		char		query[4096];
		const char *typlen;
		const char *typbyval;
		const char *typalign;
		const char *typtype;
		const char *typrelid;
		const char *typelem;
		const char *nspname;
		const char *typname;
		ArrowField *arrow_field = NULL;

		snprintf(query, sizeof(query),
				 "SELECT typlen, typbyval, typalign, typtype,"
				 "       typrelid, typelem, nspname, typname"
				 "  FROM pg_catalog.pg_type t,"
				 "       pg_catalog.pg_namespace n"
				 " WHERE t.typnamespace = n.oid"
				 "   AND t.oid = %u", atttypid);
		__res = PQexec(conn, query);
		if (PQresultStatus(__res) != PGRES_TUPLES_OK)
			Elog("failed on pg_type system catalog query: %s",
				 PQresultErrorMessage(res));
		if (PQntuples(__res) != 1)
			Elog("unexpected number of result rows: %d", PQntuples(__res));
		typlen   = PQgetvalue(__res, 0, 0);
		typbyval = PQgetvalue(__res, 0, 1);
		typalign = PQgetvalue(__res, 0, 2);
		typtype  = PQgetvalue(__res, 0, 3);
		typrelid = PQgetvalue(__res, 0, 4);
		typelem  = PQgetvalue(__res, 0, 5);
		nspname  = PQgetvalue(__res, 0, 6);
		typname  = PQgetvalue(__res, 0, 7);

		if (af_info)
			arrow_field = &af_info->footer.schema.fields[j];
		
		pgsql_setup_attribute(conn,
							  table,
							  &table->columns[j],
							  attname,
							  atttypid,
							  atttypmod,
							  atoi(typlen),
							  *typbyval,
							  *typalign,
							  *typtype,
							  atoi(typrelid),
							  atoi(typelem),
							  nspname,
							  typname,
							  arrow_field,
							  &table->numFieldNodes,
							  &table->numBuffers);
		PQclear(__res);
	}
	return table;
}

/*
 * sqldb_server_connect - open and init session
 */
void *
sqldb_server_connect(const char *sqldb_hostname,
                     const char *sqldb_port_num,
                     const char *sqldb_username,
                     const char *sqldb_password,
                     const char *sqldb_database,
                     userConfigOption *session_config_list)
{
	PGSTATE	   *pgstate;
	PGconn	   *conn;
	PGresult   *res;
	const char *query;
	userConfigOption *conf;

	conn = pgsql_server_connect(sqldb_hostname,
								sqldb_port_num,
								sqldb_username,
								sqldb_password,
								sqldb_database);
	/*
	 * preset user's config option
	 */
	for (conf = session_config_list; conf; conf = conf->next)
	{
		res = PQexec(conn, conf->query);
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
			Elog();
		PQclear(res);
	}

	/*
	 * ensure client encoding is UTF-8
	 *
	 * Even if user config tries to change client_encoding, pg2arrow
	 * must ensure text encoding is UTF-8.
	 */
	query = "set client_encoding = 'UTF8'";
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
		Elog("failed to change client_encoding to UTF-8: %s", query);
	PQclear(res);

	/*
	 * collect server timezone info
	 */
	query = "show timezone";
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK ||
		PQntuples(res) != 1 ||
		PQgetisnull(res, 0, 0))
		Elog("failed on getting server timezone configuration: %s", query);
	server_timezone = strdup(PQgetvalue(res, 0, 0));
	if (!server_timezone)
		Elog("out of memory");

	/* setup state object */
	pgstate = palloc0(sizeof(PGSTATE));
	pgstate->conn = conn;
	pgstate->res  = NULL;
	return pgstate;
}

/*
 * sqldb_begin_query
 */
SQLtable *
sqldb_begin_query(void *sqldb_state,
                  const char *sqldb_command,
                  ArrowFileInfo *af_info,
                  SQLdictionary *dictionary_list)
{
	PGSTATE	   *pgstate = sqldb_state;
	PGconn	   *conn = pgstate->conn;
	PGresult   *res;
	char	   *query;

	/* begin read-only transaction */
	res = PQexec(conn, "BEGIN READ ONLY");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
		Elog("unable to begin transaction: %s", PQresultErrorMessage(res));
	PQclear(res);

	/* declare cursor */
	query = palloc(strlen(sqldb_command) + 1024);
	sprintf(query, "DECLARE " CURSOR_NAME " BINARY CURSOR FOR %s",
			sqldb_command);
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
		Elog("unable to declare a SQL cursor: %s", PQresultErrorMessage(res));
	PQclear(res);

	/* fetch the first result */
	res = pgsql_next_result(pgstate);
	if (!res)
		return NULL;
	pgstate->res = res;

	return pgsql_create_buffer(conn, res, af_info, dictionary_list);
}

ssize_t
sqldb_fetch_results(void *sqldb_state, SQLtable *table)
{
	PGSTATE	   *pgstate = sqldb_state;
	PGresult   *res = pgstate->res;
	int			j, index = pgstate->index++;
	size_t		usage = 0;

	if (index >= pgstate->nitems)
	{
		res = pgsql_next_result(pgstate);
		if (!res)
			return -1;		/* end of the scan */
		index = pgstate->index++;
	}

	table->nitems++;
	for (j=0; j < table->nfields; j++)
	{
		SQLfield   *column = &table->columns[j];
		const char *addr;
		size_t		sz;

		/* data must be binary format */
		assert(PQfformat(res, j) == 1);
		if (PQgetisnull(res, index, j))
		{
			addr = NULL;
			sz = 0;
		}
		else
		{
			addr = PQgetvalue(res, index, j);
			sz = PQgetlength(res, index, j);
		}
		usage += sql_field_put_value(column, addr, sz);
		assert(table->nitems == column->nitems);
	}
	return usage;
}

void
sqldb_close_connection(void *sqldb_state)
{
	PGSTATE	   *pgstate = sqldb_state;
	PGconn	   *conn = pgstate->conn;
	PGresult   *res;

	if (pgstate->res)
		PQclear(pgstate->res);
	/* close the cursor */
	res = PQexec(conn, "CLOSE " CURSOR_NAME);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
		Elog("failed on close cursor '%s': %s", CURSOR_NAME,
			 PQresultErrorMessage(res));
	PQclear(res);
	/* close the connection */
	PQfinish(conn);
}
