#ifndef SQL2ARROW_H
#define SQL2ARROW_H
//#include "postgres.h"
#include "arrow_ipc.h"

typedef struct userConfigOption     userConfigOption;
struct userConfigOption
{
	userConfigOption *next;
	char		query[1];		/* SET xxx='xxx' command */
};

extern void *
sqldb_server_connect(const char *sqldb_hostname,
					 const char *sqldb_port_num,
					 const char *sqldb_username,
					 const char *sqldb_password,
					 const char *sqldb_database,
					 userConfigOption *session_config_list);
extern SQLtable *
sqldb_begin_query(void *sqldb_state,
				  const char *sqldb_command,
				  ArrowFileInfo *af_info,
				  SQLdictionary *dictionary_list);
extern ssize_t
sqldb_fetch_results(void *sqldb_state, SQLtable *table);

extern void
sqldb_close_connection(void *sqldb_state);

/* misc functions */
extern void	   *palloc(size_t sz);
extern void	   *palloc0(size_t sz);
extern char	   *pstrdup(const char *str);
extern void	   *repalloc(void *ptr, size_t sz);
extern uint64_t	hash_any(const unsigned char *k, int keylen);

#endif	/* SQL2ARROW_H */
