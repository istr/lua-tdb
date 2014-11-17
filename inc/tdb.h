#ifndef __TDB_H__
#define __TDB_H__

/* flags to tdb_store() */
#define TDB_REPLACE 1
#define TDB_INSERT 2
#define TDB_MODIFY 3

/* flags for tdb_open() - must be < 0xff */
#define TDB_DEFAULT         0 /* just a readability place holder */
#define TDB_CLEAR_IF_FIRST  1
/* #define TDB_INTERNAL        2 */ /* don't store on disk */ 
#define TDB_NOLOCK          4 /* don't do any locking */
/* #define TDB_NOMMAP          8 */ /* don't use mmap */
#define TDB_CONVERT        16 /* convert endian (internal use) */
/* #define TDB_BIGENDIAN      32 */ /* header is big-endian (internal use) */

#include <sys/stat.h> /* ino_t */
#ifdef LUA_BINDING
#	include <lua.h>
#endif

#define TDB_ERRCODE( code, ret ) ( ( tdb->ecode = (code) ), (ret) )
/* error codes */
enum TDB_ERROR {
	 TDB_SUCCESS
	,TDB_ERR_CORRUPT
	,TDB_ERR_IO
	,TDB_ERR_LOCK
	,TDB_ERR_OOM
	,TDB_ERR_EXISTS
	,TDB_ERR_NOLOCK
	,TDB_ERR_LOCK_TIMEOUT
	,TDB_ERR_NOEXIST
};

#ifndef u32
#	define u32 unsigned
#endif

#define MAX_LOCKEDHASH 32

typedef struct {
	char *dptr;
	size_t dsize;
} TDB_DATA;

typedef u32 tdb_len;
typedef u32 tdb_off;

/* this is stored at the front of every database */
struct tdb_header {
	char magic_food[32]; /* for /etc/magic */
	u32 version; /* version of the code */
	u32 hash_size; /* number of hash entries */
	tdb_off rwlocks;
	tdb_off reserved[31];
};

struct tdb_lock_type {
	u32 count;
	u32 ltype;
};

struct tdb_traverse_lock {
	struct tdb_traverse_lock *next;
	u32 off;
	u32 hash;
};


typedef struct tdb_context {
	void *map_ptr; /* where it is currently mapped */
	int fd; /* open file descriptor for the database */
	tdb_len map_size; /* how much space has been mapped */
	int read_only; /* opened read-only */
	struct tdb_lock_type *locked; /* array of chain locks */
	enum TDB_ERROR ecode; /* error code for last tdb error */
	struct tdb_header *header; /* the header */
	u32 flags; /* the flags passed to tdb_open */
	struct tdb_traverse_lock travlocks; /* current traversal locks */
	struct tdb_context *next; /* all tdbs to avoid multiple opens */
	dev_t device;  /* uniquely identifies this tdb */
	ino_t inode;   /* uniquely identifies this tdb */
	u32 (*hash_fn)(TDB_DATA *key);
	int open_flags; /* flags used in the open - needed by reopen */
	u32 lockedhash[MAX_LOCKEDHASH]; /* array of locked keys: first is #keys */
} TDB_CONTEXT;

typedef u32 (*tdb_hash_func) ( TDB_DATA *key );
typedef int (*tdb_traverse_func) ( TDB_CONTEXT *, TDB_DATA *, TDB_DATA *,
	void * );

int tdb_lockhash ( TDB_CONTEXT *tdb, u32 number, TDB_DATA *keys );
void tdb_unlockhash ( TDB_CONTEXT *tdb );
int tdb_lockall ( TDB_CONTEXT *tdb );
void tdb_unlockall ( TDB_CONTEXT *tdb );
int tdb_append ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *new_dbuf );
int tdb_store ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dbuf, int flag );
int tdb_insert ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dbuf, u32 space );
int tdb_delete ( TDB_CONTEXT *tdb, TDB_DATA *key );
int tdb_exists ( TDB_CONTEXT *tdb, TDB_DATA *key );
#ifdef LUA_BINDING
int tdb_fetch ( TDB_CONTEXT *tdb, TDB_DATA *key, lua_State *L );
int tdb_firstkey ( TDB_CONTEXT *tdb, lua_State *L );
int tdb_nextkey ( TDB_CONTEXT *tdb, TDB_DATA *key, lua_State *L );
#else
int tdb_fetch ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dst );
int tdb_firstkey ( TDB_CONTEXT *tdb, TDB_DATA *dst );
int tdb_nextkey ( TDB_CONTEXT *tdb, TDB_DATA *key, size_t dsize );
#endif
void tdb_clearkeylock ( TDB_CONTEXT *tdb ); 
int tdb_traverse ( TDB_CONTEXT *tdb, tdb_traverse_func fn, void *cdata );
int tdb_iterate ( TDB_CONTEXT *tdb, tdb_traverse_func fn, void *cdata );
void tdb_set_lock_alarm ( int *palarm );

TDB_CONTEXT * tdb_open ( const char *name,
		int hash_size,
		int tdb_flags,
		int open_flags,
		mode_t mode,
		tdb_hash_func hash_fn );

void tdb_close( TDB_CONTEXT *tdb );

/* Low level locking functions: use with care */
int tdb_chainlock ( TDB_CONTEXT *tdb, TDB_DATA *key );
int tdb_chainunlock ( TDB_CONTEXT *tdb, TDB_DATA *key );
int tdb_chainlock_read ( TDB_CONTEXT *tdb, TDB_DATA *key );

#endif /* tdb.h */

