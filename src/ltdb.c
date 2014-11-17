/* public domain */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "tdb.h"

#include "lua.h"
#include "lauxlib.h"

#ifdef SLN_TDBNAME
#	define LTDB_NAME SLN_TDBNAME
#else
#	define LTDB_NAME "tdb"
#endif
#define LTDB_TYPE "tdb handle"

#define box(L, u)	(*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))
#define unbox(L, i)	(*(void **)(lua_touserdata(L, i)))

typedef struct
{
	TDB_CONTEXT *tdb;
} LTdb;


static TDB_CONTEXT * get_tdb ( lua_State *L, int i )
{
	LTdb *lt = (LTdb *) luaL_checkudata( L, i, LTDB_TYPE );
	if ( lt->tdb )
		return lt->tdb;
	luaL_error( L, "tdb closed\n" );
	return 0;
}

/**************************************************************
	retrieval and modification
*/

static int ltdb_store ( lua_State *L, int flg )
{
	TDB_DATA k, v;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
   v.dptr = (char *) luaL_checklstring( L, 3, &v.dsize );
   if ( TDB_INSERT == flg && lua_isnumber( L, 4 ) ) {
		int spc = lua_tonumber( L, 4 );
		if ( tdb_insert( tdb, &k, &v, spc ) )
			return luaL_error( L, "tdb_insert failed (%d)\n", tdb->ecode );
	} else if ( tdb_store( tdb, &k, &v, flg ) )
		return luaL_error( L, "tdb_store failed (%d)\n", tdb->ecode );
	return 0;
}

static int ltdb_ins ( lua_State *L )
{
	return ltdb_store( L, TDB_INSERT );
}

static int ltdb_mod ( lua_State *L )
{
	return ltdb_store( L, TDB_MODIFY );
}

static int ltdb_rpl ( lua_State *L )
{
	return ltdb_store( L, TDB_REPLACE );
}

static int ltdb_append ( lua_State *L )
{
	TDB_DATA k, v;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
   v.dptr = (char *) luaL_checklstring( L, 3, &v.dsize );
	if ( tdb_append( tdb, &k, &v ) )
		return luaL_error( L, "tdb_append failed (%d)\n", tdb->ecode );
	return 0;
}

static int ltdb_del ( lua_State *L )
{
	TDB_DATA k;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
	if ( tdb_delete( tdb, &k ) )
		return luaL_error( L, "tdb_delete failed (%d)\n", tdb->ecode );
	return 0;
}

static int ltdb_fetch ( lua_State *L )
{
	TDB_DATA k;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
	return tdb_fetch( tdb, &k, L );
}

static int ltdb_exists ( lua_State *L )
{
	int b;
	TDB_DATA k;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
	b = tdb_exists( tdb, &k );
	lua_pushboolean( L, b );
	return 1;
}

/**************************************************************
	traversal
*/

static int ltdb_firstkey ( lua_State *L )
{
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	return tdb_firstkey( tdb, L );
}

static int ltdb_nextkey ( lua_State *L )
{
	TDB_DATA k;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
	return tdb_nextkey( tdb, &k, L );
}

static int ltdb_clearkeylock ( lua_State *L )
{
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	tdb_clearkeylock( tdb );
	return 0;
}

static int iter_aux( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *data,
	void *cdata )
{
	lua_State *L = (lua_State *) cdata;
	(void) tdb;
	lua_pushvalue(L, 2);
	lua_pushlstring( L, key->dptr, key->dsize );
	if ( data->dsize )
		lua_pushlstring( L, data->dptr, data->dsize );
	else
		lua_pushnil( L );
	lua_call( L, 2, 1 );
	if( !lua_isnil( L, -1 ) )
		return 1;
	lua_pop(L, 1);
	return 0;
}

typedef int (*ltdb_iterator) ( TDB_CONTEXT *, tdb_traverse_func, void * );

static int do_iterate ( lua_State *L, ltdb_iterator it )
{
	int ret = -1;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	if ( lua_isnoneornil( L, 2 ) )
		ret = it( tdb, 0, 0 );
	else if ( lua_isfunction( L, 2 ) ) {
		ret = it( tdb, iter_aux, L);
	}
	if ( 0 > ret )
		return luaL_error( L, "tdb iteration failed (%d)\n", tdb->ecode );
	lua_pushnumber( L, ret );
	return 1;
}

static int ltdb_traverse ( lua_State *L )
{
	return do_iterate( L, tdb_traverse );
}

static int ltdb_iterate ( lua_State *L )
{
	return do_iterate( L, tdb_iterate );
}

typedef struct {
#ifdef SLN_EXT_MATCH
	const char *s;
	int mode;
#else
	int i;    /* index of pattern */
#endif
	int init; /* index of init */
} M_pat;

typedef struct {
	lua_State *L;
	M_pat pat[2];
} M_cdata;

static int match_aux( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *data,
	void *cdata )
{
	M_cdata *mc = (M_cdata *) cdata;
	int i;
	TDB_DATA *td[2];
	(void) tdb;
	td[0] = key, td[1] = data;
	for ( i = 0; 2 > i; ++i ) {
#ifdef SLN_EXT_MATCH 
		if ( mc->pat[i].s ) {
#ifndef SLNUNICODE_AS_STRING
			if ( ! mc->pat[i].mode ) {
				if ( !sln_str_match( mc->L, td[i]->dptr, td[i]->dsize,
						mc->pat[i].s, mc->pat[i].init ) )
					return 0;
			} else
#endif
			if ( !sln_uni_match( mc->L, td[i]->dptr, td[i]->dsize,
					mc->pat[i].s, mc->pat[i].init, mc->pat[i].mode )
			)
				return 0;
		}
#else
		if ( mc->pat[i].i ) {
			int nil, narg = 2;
			lua_pushvalue( mc->L,  mc->pat[i].i + 1 ); /* matching function */
			lua_pushlstring( mc->L, td[i]->dptr, td[i]->dsize ); /* string */
			lua_pushvalue( mc->L, mc->pat[i].i ); /* pattern */
			if ( mc->pat[i].init ) {
				lua_pushvalue( mc->L, mc->pat[i].init ); /* init */
				++narg;
			}
			lua_call( mc->L, narg, 1 );
			nil = lua_isnil( mc->L, -1 );
			lua_pop( mc->L, 1 );
			if ( nil )
				return 0;
		}
#endif
	}
	lua_pushvalue( mc->L, 2);
	lua_pushlstring( mc->L, key->dptr, key->dsize );
	if ( data->dsize )
		lua_pushlstring( mc->L, data->dptr, data->dsize );
	else
		lua_pushnil( mc->L );
	lua_call( mc->L, 2, 1 );
	if( !lua_isnil( mc->L, -1 ) )
		return 1;
	lua_pop( mc->L, 1);
	return 0;
}

#ifdef SLN_EXT_MATCH 
/*
	match keys and / or values using sln_uni_match as matching function
	no captures are supported

	tdb:match( cb, key_pat, key_mode, key_init, data_pat, data_mode, data_init )
	args:
		cb:        callback function
		key_pat:   match pattern for key
		key_mode:  one of unicode.mode.*, default: ASCII
		key_init:  match start for key, default: 1
		data_pat:  match pattern for data
		data_mode: one of unicode.mode.*, default: ASCII
		data_init: match start for data, default: 1
		nolock:    do not lock the entire database, default: false
	key_pat or data_pat may be nil
*/
#else
/*
	match keys and / or values using the given matching function(s)
	no captures are supported

	tdb:match( cb, key_pat, key_func, key_init, data_pat, data_func, data_init )
	args:
		cb:        callback function
		key_pat:   match pattern for key
		key_func:  the matching function to use, string.match, unicode.*.match
		key_init:  match start for key
		data_pat:  match pattern for data
		data_func: the matching function to use, string.match, unicode.*.match
		data_init: match start for data
		nolock:    do not lock the entire database, default: false
	key_pat or data_pat may be nil
*/
#endif
static int ltdb_match ( lua_State *L )
{
	int ret, i = 3, j = 0, nolock;
	M_cdata mc;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	luaL_checktype( L, 2, LUA_TFUNCTION );
	do {
		if ( ! lua_isnoneornil( L, i ) ) {
#ifdef SLN_EXT_MATCH 
			mc.pat[j].s = luaL_checkstring( L, i++ );
			mc.pat[j].mode = luaL_optinteger( L, i++, 0 );
			mc.pat[j].init = luaL_optinteger( L, i++, 1 );
#else
			mc.pat[j].i = i;
			luaL_checkstring( L, i++ );
			luaL_checktype( L, i++ , LUA_TFUNCTION );
			if ( ! lua_isnoneornil( L, i ) ) {
				luaL_checknumber( L, i );
				mc.pat[j].init = i;
			} else
				mc.pat[j].init = 0;
			++i;
#endif
		} else {
#ifdef SLN_EXT_MATCH 
			mc.pat[j].s = 0;
#else
			mc.pat[j].i = 0;
#endif
			i += 3;
		}
	} while ( 2 > ++j );
	nolock = lua_toboolean( L, 9 );
	mc.L = L;
	ret = nolock
			? tdb_traverse( tdb, match_aux, &mc )
			: tdb_iterate( tdb, match_aux, &mc );
	if ( 0 > ret )
		return luaL_error( L, "tdb matching failed (%d)\n", tdb->ecode );
	lua_pushnumber( L, ret );
	return 1;
}

/**************************************************************
	locking
*/

static int gotalarm = 0;

static void ltdb_alarm ( int sig )
{
	(void) sig;
	gotalarm = 1;
}

static int set_alarm ( lua_State *L, struct sigaction *osa, int to )
{
	struct sigaction sa;
	sigemptyset( &sa.sa_mask );
	sa.sa_handler = ltdb_alarm;
	sa.sa_flags = 0;
	if ( sigaction( SIGALRM, &sa, osa ) )
		luaL_error( L, "could not set chainlock timeout\n" );
	gotalarm = 0;
	tdb_set_lock_alarm( &gotalarm );
	return alarm( to );
}

static void reset_alarm ( lua_State *L, struct sigaction *osa, int rest )
{
	alarm( rest );
	tdb_set_lock_alarm( 0 );
	if ( sigaction( SIGALRM, osa, 0 ) )
		luaL_error( L, "could not reset chainlock timeout\n" );
}

static int ltdb_lockhash ( lua_State *L )
{
	int nkeys, i, ret = 0, to = 0, alrm = 0;
	struct sigaction osa;
	TDB_DATA keys[ MAX_LOCKEDHASH ];
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	luaL_checktype( L, 2, LUA_TTABLE );
	if ( !( nkeys = luaL_getn( L, 2 ) ) || MAX_LOCKEDHASH < nkeys )
		return 0;
	if ( lua_isnumber( L, 3 ) )
		to = lua_tonumber( L, 3 );
	for ( i = 0; nkeys > i; i++ ) {
		lua_rawgeti( L, 2, i+1 );
		keys[i].dptr = (char *)luaL_checklstring(L, -1, &keys[i].dsize );
		lua_pop( L, 1 );
	}
	if ( to )
		alrm = set_alarm( L, &osa, to );
	ret = tdb_lockhash( tdb, nkeys, keys );
	if ( to ) 
		reset_alarm( L, &osa, alrm );
	if ( ret )
		luaL_error( L, "tdb_lockhash failed (%d)\n", tdb->ecode );
	return 0;
}

static int ltdb_unlockhash ( lua_State *L )
{
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	tdb_unlockhash( tdb );
	return 0;
}

static int ltdb_lockall ( lua_State *L )
{
	int to = 0, ret = 0, alrm = 0;
	struct sigaction osa;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	if ( lua_isnumber( L, 2 ) )
		to = lua_tonumber( L, 2 );
	if ( to )
		alrm = set_alarm( L, &osa, to );
	ret = tdb_lockall( tdb );
	if ( to ) 
		reset_alarm( L, &osa, alrm );
	if ( ret )
		return luaL_error( L, "tdb_lockall failed (%d)\n", tdb->ecode );
	return 0;
}

static int ltdb_unlockall ( lua_State *L )
{
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	tdb_unlockall( tdb );
	return 0;
}

typedef int (*ltdb_chainl) ( TDB_CONTEXT *, TDB_DATA * );

static int do_chainlock ( lua_State *L, ltdb_chainl x )
{
	int to = 0, ret = 0, alrm = 0;
	struct sigaction osa;
	TDB_DATA k;
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	k.dptr = (char *) luaL_checklstring( L, 2, &k.dsize );
	if ( lua_isnumber( L, 3 ) )
		to = lua_tonumber( L, 3 );
	if ( to )
		alrm = set_alarm( L, &osa, to );
	ret =  x( tdb, &k );
	if ( to ) 
		reset_alarm( L, &osa, alrm );
	if ( ret )
		return luaL_error( L, "tdb chainlock function failed (%d)\n",
				tdb->ecode );
	return 0;
}

static int ltdb_chainlock ( lua_State *L )
{
	return do_chainlock( L, tdb_chainlock );
}

static int ltdb_chainunlock ( lua_State *L )
{
	return do_chainlock( L, tdb_chainunlock );
}

static int ltdb_chainlock_read ( lua_State *L )
{
	return do_chainlock( L, tdb_chainlock_read );
}

/**************************************************************
	open / close
*/

static int ltdb_open ( lua_State *L )
{
	LTdb *lt;
	TDB_CONTEXT *tdb;
	int hash_size, tdb_flags, open_flags;
	mode_t mode;
	const char *fn;
	fn = luaL_checkstring( L, 1 );
	hash_size = luaL_optint( L, 2, 0 );
	tdb_flags = luaL_optint( L, 3, 0 );
	open_flags = luaL_optint( L, 4, O_RDONLY );
	mode = luaL_optint( L, 5, 0 );
	if ( ( tdb = tdb_open( fn, hash_size, tdb_flags, open_flags, mode, 0 ) ) )
	{
		lt = (LTdb *) lua_newuserdata( L, sizeof( *lt ) );
		lt->tdb = tdb;
		luaL_getmetatable( L, LTDB_TYPE );
		lua_setmetatable(L, -2);
		return 1;
	}
	return 0;
}

static int ltdb_close ( lua_State *L )
{
	LTdb *lt = (LTdb *) luaL_checkudata( L, 1, LTDB_TYPE );
	if ( lt->tdb ) {
		tdb_close( lt->tdb );
		lt->tdb = 0;
	}
	return 0;
}

/**************************************************************
	registry
*/

static int ltdb_tostring ( lua_State *L )
{
	char s[64];
	TDB_CONTEXT *tdb = get_tdb( L, 1 );
	lua_pushlstring( L, s, snprintf( s, sizeof(s), LTDB_TYPE " %p (%p)", tdb,
		lua_touserdata( L, 1 ) ) );
	return 1;
}

static struct luaL_reg ltdb_O[] =
{
	 { "__gc",		      ltdb_close }
	,{ "__tostring",     ltdb_tostring }
	,{ "close",          ltdb_close }
	,{ "insert",         ltdb_ins }
	,{ "modify",         ltdb_mod }
	,{ "replace",        ltdb_rpl }
	,{ "append",         ltdb_append }
	,{ "delete",         ltdb_del }
	,{ "fetch",          ltdb_fetch }
	,{ "get",            ltdb_fetch }
	,{ "exists",         ltdb_exists }
	,{ "firstkey",       ltdb_firstkey }
	,{ "nextkey",        ltdb_nextkey }
	,{ "clearlck",       ltdb_clearkeylock }
	,{ "traverse",       ltdb_traverse }
	,{ "iterate",        ltdb_iterate }
	,{ "match",          ltdb_match }
	,{ "lockhash",       ltdb_lockhash }
	,{ "unlockhash",     ltdb_unlockhash }
	,{ "lockall",        ltdb_lockall }
	,{ "unlockall",      ltdb_unlockall }
	,{ "chainlock",      ltdb_chainlock }
	,{ "chainunlock",    ltdb_chainunlock }
	,{ "chainlock_read",	ltdb_chainlock_read }
	,{ 0, 0 }
};

static struct luaL_reg ltdb_M[] =
{
	 { "open", ltdb_open }
	,{ 0, 0 }
};

static struct { const char *name; int value; } ltdb_F[] =
{
	 { "CLEAR_IF_FIRST", TDB_CLEAR_IF_FIRST }
	,{ "NOLOCK",         TDB_NOLOCK }
	,{ "O_CREAT",        O_CREAT }
	,{ "O_TRUNC",        O_TRUNC }
	,{ "O_RDONLY",       O_RDONLY }
	,{ "O_RDWR",         O_RDWR }
	,{ "O_WRONLY",       O_WRONLY }
	,{ 0, 0 }
};

int luaopen_tdb ( lua_State *L )
{
	int i;
	luaL_newmetatable( L, LTDB_TYPE );
	luaL_register( L, 0, ltdb_O );
	lua_pushliteral( L, "__index" );
	lua_pushvalue( L, -2 );
	lua_rawset( L, -3 );
	lua_pop( L, 1 );
	luaL_register( L, LTDB_NAME, ltdb_M );
	for( i = 0; ltdb_F[i].name; i++ ) {
		lua_pushstring( L, ltdb_F[i].name );
		lua_pushnumber( L, ltdb_F[i].value );
		lua_settable( L, -3 );
	}
	return 1;
}
