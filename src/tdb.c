
#if defined(HAVE_MREMAP) && !defined( __dietlibc__ )
#  define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "tdb.h"

#define TDB_SPINLOCK_SIZE(hash_size) 0

#define BUCKET(hash) ((hash) % tdb->header->hash_size)
#define DEFAULT_HASH_SIZE 131

#define TDB_VERSION    (0x26011967 + 6)
#define TDB_MAGIC      (0x26011999U)
#define TDB_FREE_MAGIC (~TDB_MAGIC)
#define TDB_DEAD_MAGIC (0xFEE1DEAD)
#define TDB_ALIGNMENT  4
#define TDB_ALIGN(x,a) (((x) + (a)-1) & ~((a)-1))
#define TDB_PAGE_SIZE 0x2000
#define MIN_REC_SIZE (2*sizeof(struct list_struct) + TDB_ALIGNMENT)
#define FREELIST_TOP (sizeof(struct tdb_header))
#define TDB_DEAD(r) ((r)->magic == TDB_DEAD_MAGIC)
#define TDB_BAD_MAGIC(r) ((r)->magic != TDB_MAGIC && !TDB_DEAD(r))
#define TDB_HASH_TOP(hash) (FREELIST_TOP + (BUCKET((hash))+1)*sizeof(tdb_off))
#define TDB_DATA_START(hash_size) (TDB_HASH_TOP((hash_size)-1) + TDB_SPINLOCK_SIZE(hash_size))

#define TDB_LOCKED 0x100

static const char TDB_MAGIC_FOOD[] = "TDB file\n";


#define TDB_BYTEREV(x) ( \
	  ( ( (x) & 0xff ) << 24 ) \
	| ( ( (x) & 0xFF00 ) << 8 ) \
	| ( ( (x) >> 8 ) & 0xFF00 ) \
	| ( (x) >> 24 ) )


#ifdef TDEBUG
#	include <stdio.h>
#	define TDB_DBG(args...) fprintf(stderr, ## args )
#else
#	define TDB_DBG(args...)
#endif

/* lock offsets */
#define GLOBAL_LOCK   0
#define ACTIVE_LOCK   4

#ifndef MAP_FILE
#	define MAP_FILE 0
#endif

#ifndef MAP_FAILED
#	define MAP_FAILED ((void *)-1)
#endif

/* free memory if the pointer is valid and zero the pointer */
#ifndef SAFE_FREE
#	define SAFE_FREE(x) do { if ((x)) {free((x)); (x)=0;} } while(0)
#endif

#define CLR_LOCKED(x) memset( (x), 0, sizeof((x)) )

/*
	the body of the database is made of one list_struct for the free space
	plus a separate data list for each hash value
*/
struct list_struct {
	tdb_off next;     /* offset of the next record in the list */
	tdb_len rec_len;  /* total byte length of record */
	tdb_len key_len;  /* byte length of key */
	tdb_len data_len; /* byte length of data */
	u32 full_hash;    /* the full 32 bit hash of the key */
	u32 magic;        /* try to catch errors */
	/* the following union is implied:
		union {
			char record[rec_len];
			struct {
				char key[key_len];
				char data[data_len];
			}
		}
		u32 totalsize; (tailer)
	*/
};

/* all contexts, to ensure no double-opens (fcntl locks don't nest!) */
static TDB_CONTEXT *tdbs = NULL;

/************************************************
	forward declarations
*/
static tdb_off tdb_find_lock_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash,
	int locktype, struct list_struct *rec );

static tdb_off tdb_find ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash,
		struct list_struct *r );

static int tdb_exists_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash );

/************************************************
	endianess
*/

/* Endian conversion: we only ever deal with 4 byte quantities */
static void *convert ( void *buf, u32 size )
{
	u32 i, *p = buf;
	for (i = 0; i < size / 4; i++)
		p[i] = TDB_BYTEREV(p[i]);
	return buf;
}
#define DOCONV() (tdb->flags & TDB_CONVERT)
#define CONVERT(x) (DOCONV() ? convert(&x, sizeof(x)) : &x)

/************************************************
	hash function
*/

/*
	This is based on the hash algorithm from gdbm
*/
static u32 default_tdb_hash ( TDB_DATA *key )
{
	u32 value;  /* Used to compute the hash value.  */
	u32   i; /* Used to cycle through random values. */
	/* Set the initial value from the key size. */
	for (value = 0x238F13AF * key->dsize, i=0; i < key->dsize; i++)
		value = (value + (key->dptr[i] << (i*5 % 24)));
	return (1103515243 * value + 12345);
}

/************************************************
	mapping
*/

static int tdb_mmap ( TDB_CONTEXT *tdb )
{
	if ( MAP_FAILED == ( tdb->map_ptr = mmap( 0, tdb->map_size,
			PROT_READ | ( tdb->read_only ? 0 : PROT_WRITE ),
			MAP_SHARED | MAP_FILE, tdb->fd, 0 ) )
	)
		return -1;
	tdb->header = (struct tdb_header *) tdb->map_ptr;
	return 0;
}

static int tdb_munmap ( TDB_CONTEXT *tdb )
{
   if ( MAP_FAILED != tdb->map_ptr ) {
		int ret = munmap( tdb->map_ptr, tdb->map_size );
		tdb->map_ptr = MAP_FAILED;
		tdb->header = 0;
		return ret;
	}
	return 0;
}

#ifdef HAVE_MREMAP
static int tdb_mremap ( TDB_CONTEXT *tdb, tdb_len old_size )
{
	if ( MAP_FAILED == tdb->map_ptr )
		return 0;
	if ( MAP_FAILED == ( tdb->map_ptr =
			mremap( tdb->map_ptr, old_size, tdb->map_size, MREMAP_MAYMOVE ) )
	) {
		TDB_DBG( "tdb_mremap failed for size %d (%s)\n",
				tdb->map_size, strerror(errno));
		return -1;
	}
	tdb->header = (struct tdb_header *) tdb->map_ptr;
	return 0;
}
#endif

/************************************************
	locking
*/
static int *alarmed;

/*
	a byte range locking function - return 0 on success
	this functions locks/unlocks 1 byte at the specified offset.
	On error, errno is also set so that errors are passed back properly
	through tdb_open().
*/
static int tdb_brlock ( TDB_CONTEXT *tdb, tdb_off offset,
		int rw_type, int lck_type, int range )
{
	struct flock fl;
	int ret;
	if ( ( tdb->flags & TDB_NOLOCK ) 
			|| ( ( tdb->flags & TDB_LOCKED )
					&& ( range || offset || F_UNLCK != rw_type ) )
	)
		return 0;
	if ( ( rw_type == F_WRLCK) && tdb->read_only ) {
		errno = EACCES;
		return -1;
	}
	if ( alarmed && *alarmed )
		return TDB_ERRCODE( TDB_ERR_LOCK_TIMEOUT, -1 );
	fl.l_type = rw_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = offset;
	fl.l_len = range;
	fl.l_pid = 0;
	do {
		ret = fcntl( tdb->fd, lck_type, &fl );
	} while ( ret && EINTR == errno && !alarmed && !*alarmed );

	if ( ret ) {
		TDB_DBG("tdb_brlock failed (fd=%d) at offset %d rw_type=%d lck_type=%d: %s\n", tdb->fd, offset, rw_type, lck_type, strerror(errno) );
		return TDB_ERRCODE(
				alarmed && *alarmed ? TDB_ERR_LOCK_TIMEOUT : TDB_ERR_LOCK, -1
		);
	}
	if ( !offset && !range ) {
		if ( F_UNLCK == rw_type ) tdb->flags &= ~TDB_LOCKED;
		else tdb->flags |= TDB_LOCKED;
	}
	return 0;
}

/*
	lock a list in the database. list -1 is the alloc list
*/
static int tdb_lock ( TDB_CONTEXT *tdb, int list, int ltype )
{
	if ( tdb->flags & TDB_NOLOCK )
		return 0;

	if ( list < -1 || list >= (int) tdb->header->hash_size ) {
		TDB_DBG( "tdb_lock: invalid list %d for ltype=%d\n", list, ltype );
		return -1;
	}

	/* Since fcntl locks don't nest, we do a lock for the first one,
		and simply bump the count for future ones */
	if ( !tdb->locked[list+1].count ) {
		if ( tdb_brlock( tdb, FREELIST_TOP + sizeof( tdb_off ) * list,
				ltype, F_SETLKW, 1 )
		) {
			TDB_DBG( "tdb_lock failed on list %d ltype=%d (%s)\n",
					list, ltype, strerror(errno) );
			return -1;
		}
		tdb->locked[list+1].ltype = ltype;
	}
	tdb->locked[list+1].count++;
	return 0;
}

/*
	unlock the database: returns void because it's too late for errors.
	changed to return int it may be interesting to know there
	has been an error  --simo
*/
static int tdb_unlock ( TDB_CONTEXT *tdb, int list )
{

	if ( tdb->flags & TDB_NOLOCK )
		return 0;

	/* Sanity checks */
	if ( list < -1 || list >= (int) tdb->header->hash_size ) {
		TDB_DBG( "tdb_unlock: list %d invalid (%d)\n",
				list, tdb->header->hash_size );
		return -1;
	}

	if ( !tdb->locked[list+1].count ) {
		TDB_DBG( "tdb_unlock: count is 0\n" );
		return -1;
	}

	if ( tdb->locked[list+1].count == 1 ) {
		/* Down to last nested lock: unlock underneath */
		if ( tdb_brlock( tdb, FREELIST_TOP + sizeof( tdb_off ) * list,
				F_UNLCK, F_SETLKW, 1 )
		)
			return -1;
	}
	tdb->locked[list+1].count--;
	return 0;
}

/*
	check if the hash is locked
*/
static int tdb_hashlocked ( TDB_CONTEXT *tdb, u32 hash )
{
	u32 i;
	if ( !tdb->lockedhash[0] )
		return 1;
	for ( i = 1; i <= tdb->lockedhash[0]; i++ )
		if ( tdb->lockedhash[i] == hash )
			return 1;
	return TDB_ERRCODE( TDB_ERR_NOLOCK, 0 );
}

/*
	record lock stops delete underneath
*/
static int lock_record ( TDB_CONTEXT *tdb, tdb_off off )
{
	return off ? tdb_brlock( tdb, off, F_RDLCK, F_SETLKW, 1 ) : 0;
}

/*
	fcntl locks don't stack: avoid unlocking someone else's
*/
static int unlock_record ( TDB_CONTEXT *tdb, tdb_off off )
{
	struct tdb_traverse_lock *i;
	u32 count = 0;

	if ( !off ) return 0;
	for ( i = &tdb->travlocks; i; i = i->next )
		if ( i->off == off )
			count++;
	return count == 1 ? tdb_brlock( tdb, off, F_UNLCK, F_SETLKW, 1 ) : 0;
}

/*
	Write locks override our own fcntl readlocks, so check it here.
	Note this is meant to be F_SETLK, *not* F_SETLKW, as it's not
	an error to fail to get the lock here.
*/
static int write_lock_record ( TDB_CONTEXT *tdb, tdb_off off )
{
	struct tdb_traverse_lock *i;
	for ( i = &tdb->travlocks; i; i = i->next )
		if ( i->off == off )
			return -1;
	return tdb_brlock( tdb, off, F_WRLCK, F_SETLK, 1 );
}

/*
	Note this is meant to be F_SETLK, *not* F_SETLKW, as it's not
	an error to fail to get the lock here.
*/
static int write_unlock_record ( TDB_CONTEXT *tdb, tdb_off off )
{
	return tdb_brlock( tdb, off, F_UNLCK, F_SETLK, 1 );
}

static int do_chainlock ( TDB_CONTEXT *tdb, TDB_DATA *key, int ltype )
{
	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
	return ltype
			? tdb_lock( tdb, BUCKET( tdb->hash_fn( key ) ), ltype )
			: tdb_unlock( tdb, BUCKET( tdb->hash_fn( key ) ) );
}


/************************************************
	i/o
*/

/*
	check for an out of bounds access - if it is out of bounds then see if the
	database has been expanded by someone else and expand if necessary
	note that "len" is the minimum length needed for the db
*/
static int tdb_oob ( TDB_CONTEXT *tdb, tdb_off len )
{
	struct stat st;
	if ( len <= tdb->map_size )
		return 0;

	if ( fstat( tdb->fd, &st ) )
		return TDB_ERRCODE( TDB_ERR_IO, -1 );
#ifdef __dietlibc__
# define ST_CAST
#else
# define ST_CAST (off_t)
#endif
	if ( st.st_size < ST_CAST len ) {
		TDB_DBG( "tdb_oob len %d beyond eof at %d\n",
				(int) len, (int) st.st_size );
		return TDB_ERRCODE( TDB_ERR_IO, -1 );
	}

	/* Unmap, update size, remap */
#ifdef HAVE_MREMAP
	{
		tdb_len old_size = tdb->map_size;
		tdb->map_size = st.st_size;
		return tdb_mremap( tdb, old_size ) ? TDB_ERRCODE( TDB_ERR_IO, -1 ) : 0;
	}
#else
	if ( tdb_munmap( tdb ) )
		return TDB_ERRCODE( TDB_ERR_IO, -1 );
	tdb->map_size = st.st_size;
	return tdb_mmap( tdb ) ? TDB_ERRCODE( TDB_ERR_IO, -1 ) : 0;
#endif
}


/*
	read a lump of data at a specified offset, maybe convert
*/
static int tdb_read ( TDB_CONTEXT *tdb, tdb_off off,
	void *buf, tdb_len len, int cv )
{
	if ( MAP_FAILED == tdb->map_ptr || tdb_oob( tdb, off + len ) ) 
		return TDB_ERRCODE( TDB_ERR_IO, -1 );
	memcpy( buf, (char *)tdb->map_ptr + off, len );
	if ( cv )
		convert( buf, len );
	return 0;
}

/*
	write a lump of data at a specified offset
*/
static int tdb_write ( TDB_CONTEXT *tdb, tdb_off off, void *buf, tdb_len len )
{
	if ( MAP_FAILED == tdb->map_ptr || tdb_oob( tdb, off + len ) ) 
		return TDB_ERRCODE( TDB_ERR_IO, -1 );
	memcpy( (char *)tdb->map_ptr + off, buf, len );
	return 0;
}

/*
	get a pointer to data at offset
	replaces tdb_alloc_read
*/
static char *tdb_pointer ( TDB_CONTEXT *tdb, tdb_off off, tdb_len len )
{
	if ( MAP_FAILED == tdb->map_ptr  || tdb_oob( tdb, off + len ) ) 
		return TDB_ERRCODE( TDB_ERR_IO, (char *)0 );
	return tdb->map_ptr + off;
}

/*
	read/write a tdb_off
*/
static int ofs_read ( TDB_CONTEXT *tdb, tdb_off offset, tdb_off *d )
{
	return tdb_read( tdb, offset, (char*)d, sizeof(*d), DOCONV() );
}
static int ofs_write ( TDB_CONTEXT *tdb, tdb_off offset, tdb_off *d )
{
	tdb_off off = *d;
	return tdb_write( tdb, offset, CONVERT(off), sizeof(*d) );
}

/*
	read/write a record
*/
static int rec_read ( TDB_CONTEXT *tdb, tdb_off offset,
	struct list_struct *rec )
{
	if ( tdb_read( tdb, offset, rec, sizeof(*rec), DOCONV() ) )
		return -1;
	if ( TDB_BAD_MAGIC( rec ) ) {
		return TDB_ERRCODE( TDB_ERR_CORRUPT, -1 );
	}
	return tdb_oob( tdb, rec->next + sizeof(*rec) );
}
static int rec_write ( TDB_CONTEXT *tdb, tdb_off offset,
	struct list_struct *rec )
{
	struct list_struct r = *rec;
	return tdb_write( tdb, offset, CONVERT(r), sizeof(r) );
}

/*
	read a freelist record and check for simple errors
*/
static int rec_free_read ( TDB_CONTEXT *tdb, tdb_off off,
	struct list_struct *rec )
{
	if ( tdb_read( tdb, off, rec, sizeof(*rec), DOCONV() ) )
		return -1;

	if ( rec->magic == TDB_MAGIC ) {
		/* this happens when a app is showdown while deleting a record - we
			should not completely fail when this happens */
		TDB_DBG( "rec_free_read non-free magic 0x%x at offset=%d - fixing\n",
				rec->magic, off);
		rec->magic = TDB_FREE_MAGIC;
		if ( tdb_write( tdb, off, rec, sizeof(*rec) ) )
			return -1;
	}

	if ( rec->magic != TDB_FREE_MAGIC ) {
		TDB_DBG( "rec_free_read bad magic 0x%x at offset=%d\n",
				rec->magic, off );
		return TDB_ERRCODE(TDB_ERR_CORRUPT, -1);
	}
	return tdb_oob( tdb, rec->next+sizeof(*rec) );
}

/*
	update a record tailer (must hold allocation lock)
*/
static int update_tailer ( TDB_CONTEXT *tdb, tdb_off offset,
	const struct list_struct *rec )
{
	tdb_off totalsize;

	/* Offset of tailer from record header */
	totalsize = sizeof(*rec) + rec->rec_len;
	return ofs_write( tdb, offset + totalsize - sizeof(tdb_off),
		&totalsize );
}

/*
	Remove an element from the freelist. Must have alloc lock.
*/
static int remove_from_freelist ( TDB_CONTEXT *tdb, tdb_off off, tdb_off next )
{
	tdb_off last_ptr, i;

	/* read in the freelist top */
	last_ptr = FREELIST_TOP;
	while ( !ofs_read( tdb, last_ptr, &i ) && i != 0) {
		if ( i == off ) {
			/* We've found it! */
			return ofs_write( tdb, last_ptr, &next );
		}
		/* Follow chain (next offset is at start of record) */
		last_ptr = i;
	}
	TDB_DBG( "remove_from_freelist: not on list at off=%d\n", off );
	return TDB_ERRCODE( TDB_ERR_CORRUPT, -1 );
}

/*
	Add an element into the freelist. Merge adjacent records if
	neccessary.
*/
static int tdb_free ( TDB_CONTEXT *tdb, tdb_off offset,
	struct list_struct *rec )
{
	tdb_off right, left;

	/* Allocation and tailer lock */
	if ( tdb_lock(tdb, -1, F_WRLCK ) )
		return -1;

	/* set an initial tailer, so if we fail we don't leave a bogus record */
	if ( update_tailer( tdb, offset, rec ) ) {
		TDB_DBG( "tdb_free: update_tailer failed!\n");
		goto fail;
	}

	/* Look right first (I'm an Australian, dammit) */
	right = offset + sizeof(*rec) + rec->rec_len;
	if ( right + sizeof(*rec) <= tdb->map_size ) {
		struct list_struct r;

		if ( tdb_read( tdb, right, &r, sizeof(r), DOCONV() ) ) {
			TDB_DBG( "tdb_free: right read failed at %u\n", right);
			goto left;
		}

		/* If it's free, expand to include it. */
		if ( r.magic == TDB_FREE_MAGIC ) {
			if ( remove_from_freelist(tdb, right, r.next ) ) {
				TDB_DBG( "tdb_free: right free failed at %u\n", right );
				goto left;
			}
			rec->rec_len += sizeof(r) + r.rec_len;
		}
	}

left:
	/* Look left */
	left = offset - sizeof(tdb_off);
	if ( left > TDB_DATA_START( tdb->header->hash_size ) ) {
		struct list_struct l;
		tdb_off leftsize;

		/* Read in tailer and jump back to header */
		if ( ofs_read(tdb, left, &leftsize ) ) {
			TDB_DBG( "tdb_free: left offset read failed at %u\n", left);
			goto update;
		}
		left = offset - leftsize;

		/* Now read in record */
		if ( tdb_read( tdb, left, &l, sizeof(l), DOCONV() ) ) {
			TDB_DBG( "tdb_free: left read failed at %u (%u)\n", left, leftsize);
			goto update;
		}

		/* If it's free, expand to include it. */
		if ( l.magic == TDB_FREE_MAGIC ) {
			if ( remove_from_freelist( tdb, left, l.next ) ) {
				TDB_DBG( "tdb_free: left free failed at %u\n", left );
				goto update;
			} else {
				offset = left;
				rec->rec_len += leftsize;
			}
		}
	}

update:
	if ( update_tailer( tdb, offset, rec ) ) {
		TDB_DBG( "tdb_free: update_tailer failed at %u\n", offset);
		goto fail;
	}

	/* Now, prepend to free list */
	rec->magic = TDB_FREE_MAGIC;

	if ( ofs_read( tdb, FREELIST_TOP, &rec->next )
		|| rec_write( tdb, offset, rec )
		|| ofs_write( tdb, FREELIST_TOP, &offset )
	) {
		TDB_DBG( "tdb_free record write failed at offset=%d\n", offset);
		goto fail;
	}

	/* And we're done. */
	tdb_unlock( tdb, -1 );
	return 0;

fail:
	tdb_unlock( tdb, -1 );
	return -1;
}

/*
	expand the database at least size bytes by expanding the underlying
	file and doing the mmap again if necessary
*/
static int tdb_expand ( TDB_CONTEXT *tdb, tdb_off size )
{
	struct list_struct rec;
	tdb_off offset;
	tdb_len old_size  = tdb->map_size;
#ifdef _SC_PAGE_SIZE
#	define SYSC_PAGESIZE _SC_PAGE_SIZE
#else
#	define SYSC_PAGESIZE _SC_PAGESIZE
#endif
	size_t poff = tdb->map_size & ~((size_t) sysconf( SYSC_PAGESIZE ) - 1);

	if ( tdb_lock( tdb, -1, F_WRLCK ) ) {
		TDB_DBG( "lock failed in tdb_expand\n" );
		return -1;
	}

	/* must know about any previous expansions by another process */
	tdb_oob( tdb, tdb->map_size + 1 );

#define EXP_REC 512
	/* always make room for at least EXP_REC more records, and round
		the database up to a multiple of TDB_PAGE_SIZE */
	size = TDB_ALIGN ( tdb->map_size + size * EXP_REC, TDB_PAGE_SIZE )
			- tdb->map_size;

#ifndef HAVE_MREMAP
	tdb_munmap(tdb);
#endif

	/*
	* We must ensure the file is unmapped before doing this
	* to ensure consistency with systems like OpenBSD where
	* writes and mmaps are not consistent.
	*/

	/* expand the file itself */
	if ( ftruncate(tdb->fd, tdb->map_size + size ) ) {
		TDB_DBG( "ftruncate to %d failed (%s)\n",
			tdb->map_size + size, strerror(errno) );
		goto fail;
	}

	tdb->map_size += size;

	/*
	* We must ensure the file is remapped before adding the space
	* to ensure consistency with systems like OpenBSD where
	* writes and mmaps are not consistent.
	*/

	/* We're ok if the mmap fails as we'll fallback to read/write */
#ifdef HAVE_MREMAP
	tdb_mremap(tdb, old_size);
#else
	tdb_mmap(tdb);
#endif
	/* avoid sparse files */
	memset( tdb->map_ptr + old_size, 0x42, size );
	if ( msync( tdb->map_ptr + poff, tdb->map_size - poff,
			MS_SYNC | MS_INVALIDATE )
	)
		return TDB_ERRCODE( TDB_ERR_IO, -1 );

	/* form a new freelist record */
	memset(&rec,'\0',sizeof(rec));
	rec.rec_len = size - sizeof(rec);

	/* link it into the free list */
	offset = old_size;
	if ( tdb_free(tdb, offset, &rec ) )
		goto fail;

	tdb_unlock( tdb, -1 );
	return 0;
fail:
	tdb_unlock( tdb, -1 );
	return -1;
}

/*
	 allocate some space from the free list. The offset returned points
	to a unconnected list_struct within the database with room for at
	least length bytes of total data

	0 is returned if the space could not be allocated
*/
static tdb_off tdb_allocate ( TDB_CONTEXT *tdb, tdb_len length,
	struct list_struct *rec )
{
	tdb_off rec_ptr, last_ptr, newrec_ptr;
	struct list_struct newrec;

	memset( &newrec, '\0', sizeof(newrec) );

	if ( tdb_lock(tdb, -1, F_WRLCK ) )
		return 0;

	/* Extra bytes required for tailer */
	length += sizeof(tdb_off);

again:
	last_ptr = FREELIST_TOP;

	/* read in the freelist top */
	if ( ofs_read( tdb, FREELIST_TOP, &rec_ptr ) )
		goto fail;

	/* keep looking until we find a freelist record big enough */
	while (rec_ptr) {
		if ( rec_free_read(tdb, rec_ptr, rec ) )
			goto fail;
		if ( rec->rec_len >= length ) {
			/* found it - now possibly split it up  */
			if ( rec->rec_len > length + MIN_REC_SIZE ) {
				/* Length of left piece */
				length = TDB_ALIGN( length, TDB_ALIGNMENT );

				/* Right piece to go on free list */
				newrec.rec_len = rec->rec_len - ( sizeof(*rec) + length );
				newrec_ptr = rec_ptr + sizeof(*rec) + length;

				/* And left record is shortened */
				rec->rec_len = length;
			} else
				newrec_ptr = 0;

			/* Remove allocated record from the free list */
			if ( ofs_write( tdb, last_ptr, &rec->next ) )
				goto fail;

			/* Update header: do this before we drop alloc lock, otherwise tdb_free()
				might try to merge with us, thinking we're free. 
				(Thanks Jeremy Allison). */
			rec->magic = TDB_MAGIC;
			if ( rec_write( tdb, rec_ptr, rec ) )
				goto fail;

			/* Did we create new block? */
			if ( newrec_ptr ) {
				/* Update allocated record tailer (we shortened it). */
				if ( update_tailer( tdb, rec_ptr, rec ) )
					goto fail;

				/* Free new record */
				if ( tdb_free( tdb, newrec_ptr, &newrec ) )
					goto fail;
			}

			/* all done - return the new record offset */
			tdb_unlock( tdb, -1 );
			return rec_ptr;
		}
		/* move to the next record */
		last_ptr = rec_ptr;
		rec_ptr = rec->next;
	}
	/* we didn't find enough space. See if we can expand the
	database and if we can then try again */
	if ( !tdb_expand( tdb, length + sizeof(*rec) ) )
		goto again;
fail:
	tdb_unlock( tdb, -1 );
	return 0;
}

/*
	actually delete an entry in the database given the offset
*/
static int do_delete ( TDB_CONTEXT *tdb, tdb_off rec_ptr,
	struct list_struct*rec )
{
	tdb_off last_ptr, i;
	struct list_struct lastrec;

	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );

	if ( write_lock_record( tdb, rec_ptr ) ) {
		/* Someone traversing here: mark it as dead */
		rec->magic = TDB_DEAD_MAGIC;
		return rec_write( tdb, rec_ptr, rec );
	}
	if ( write_unlock_record( tdb, rec_ptr ) )
		return -1;

	/* find previous record in hash chain */
	if ( ofs_read( tdb, TDB_HASH_TOP( rec->full_hash ), &i) )
		return -1;
	for ( last_ptr = 0; i != rec_ptr; last_ptr = i, i = lastrec.next )
		if ( rec_read( tdb, i, &lastrec) )
			return -1;

	/* unlink it: next ptr is at start of record. */
	if ( !last_ptr )
		last_ptr = TDB_HASH_TOP( rec->full_hash );
	if ( ofs_write( tdb, last_ptr, &rec->next ) )
		return -1;

	/* recover the space */
	return tdb_free( tdb, rec_ptr, rec );
}

/*
	update an entry in place - this only works if the new data size
	is <= the old data size and the key exists.
	on failure return -1.
*/
static int tdb_update_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash,
	TDB_DATA *dbuf )
{
	struct list_struct rec;
	tdb_off rec_ptr;

	/* find entry */
	if ( ! ( rec_ptr = tdb_find( tdb, key, hash, &rec ) ) )
		return -1;

	/* must be long enough key, data and tailer */
	if ( rec.rec_len < key->dsize + dbuf->dsize + sizeof( tdb_off ) ) {
		tdb->ecode = TDB_SUCCESS; /* Not really an error */
		return -1;
	}

	if ( tdb_write( tdb, rec_ptr + sizeof(rec) + rec.key_len,
			dbuf->dptr, dbuf->dsize) )
		return -1;

	if ( dbuf->dsize != rec.data_len) {
		/* update size */
		rec.data_len = dbuf->dsize;
		return rec_write(tdb, rec_ptr, &rec);
	}
	return 0;
}

/*
	delete an entry in the database given a key
*/
static int tdb_delete_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash )
{
	tdb_off rec_ptr;
	struct list_struct rec;
	int ret;

	if ( !( rec_ptr = tdb_find_lock_hash( tdb, key, hash, F_WRLCK, &rec ) ) )
		return -1;
	ret = do_delete( tdb, rec_ptr, &rec );
	tdb_unlock( tdb, BUCKET(rec.full_hash) );
	return ret;
}

/*
	store an element in the database.
	depending on flag any existing element with the same key will be replaced.
	if space > 0 and TDB_INSERT == flag  additional space will be allocated for
	the record to allow in-place replacement
	return 0 on success, -1 on failure
*/
static int do_store ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dbuf,
	int flag, u32 space )
{
	struct list_struct rec;
	u32 hash;
	tdb_off rec_ptr;
	int ret = 0;
	size_t rlen;

	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
	
	/* find which hash bucket it is in */
	hash = tdb->hash_fn( key );
	if ( !tdb_hashlocked( tdb, hash ) || tdb_lock( tdb, BUCKET(hash), F_WRLCK ) )
		return -1;

	/* check for it existing, on insert. */
	if ( flag == TDB_INSERT ) {
		if ( tdb_exists_hash( tdb, key, hash ) ) {
			tdb->ecode = TDB_ERR_EXISTS;
			goto fail;
		}
	} else {
		/* first try in-place update, on modify or replace. */
		if ( !tdb_update_hash( tdb, key, hash, dbuf ) )
			goto out;
		if ( tdb->ecode == TDB_ERR_NOEXIST && flag == TDB_MODIFY ) {
			/* if the record doesn't exist and we are in TDB_MODIFY mode then
				we should fail the store */
			goto fail;
		}
	}
	/* reset the error code potentially set by the tdb_update() */
	tdb->ecode = TDB_SUCCESS;

	/* delete any existing record - if it doesn't exist we don't
		care. Doing this first reduces fragmentation, and avoids
		coalescing with `allocated' block before it's updated. */
	rlen = key->dsize + dbuf->dsize;
	if ( flag != TDB_INSERT ) {
		tdb_delete_hash( tdb, key, hash );
	} else
		rlen += space;
		
	/* we have to allocate some space */
	if ( !( rec_ptr = tdb_allocate( tdb, rlen, &rec ) ) )
		goto fail;
	/* Read hash top into next ptr */
	if ( ofs_read( tdb, TDB_HASH_TOP(hash), &rec.next ) )
		goto fail;

	rec.key_len = key->dsize;
	rec.data_len = dbuf->dsize;
	rec.full_hash = hash;
	rec.magic = TDB_MAGIC;
	/* write out and point the top of the hash chain at it */
	if ( rec_write( tdb, rec_ptr, &rec ) 
			|| tdb_write( tdb, rec_ptr + sizeof( rec ), key->dptr, key->dsize )
			|| tdb_write( tdb, rec_ptr + sizeof( rec ) + key->dsize,
					dbuf->dptr, dbuf->dsize ) 
			|| ofs_write( tdb, TDB_HASH_TOP( hash ), &rec_ptr )
	) {
		/* Need to tdb_unallocate() here */
		goto fail;
	}
out:
	tdb_unlock( tdb, BUCKET(hash) );
	return ret;
fail:
	ret = -1;
	goto out;
}

/*
	initialise a new database with a specified hash size
*/
static int tdb_new_database ( TDB_CONTEXT *tdb, int hash_size )
{
	/* We make it up in memory, then write it out if not internal */
	tdb->map_size = sizeof( struct tdb_header )
			+ ( hash_size + 1 ) * sizeof( tdb_off );
	write( tdb->fd, TDB_MAGIC_FOOD, sizeof( TDB_MAGIC_FOOD ) );
	if ( ftruncate( tdb->fd, tdb->map_size ) || tdb_mmap( tdb ) )
		return -1;
	tdb->header->version = TDB_VERSION;
	tdb->header->hash_size = hash_size;
	/* no spinlock support. tdb_create_rwlocks(tdb->fd, hash_size); */
	return msync( tdb->map_ptr, tdb->map_size, MS_SYNC | MS_INVALIDATE );
}

/************************************************
	traversal
*/

/*
	Uses traverse lock: 0 = finish, -1 = error, other = record offset

	This function is changed to keep a read lock on the hash chain the current
	key is in.
*/
static int tdb_next_lock ( TDB_CONTEXT *tdb, struct tdb_traverse_lock *tlock,
	struct list_struct *rec )
{
	int want_next = ( tlock->off != 0 );

	/* No traversal allowed if you've called tdb_lockkeys() */
	if ( tdb->lockedhash[0] )
		return TDB_ERRCODE( TDB_ERR_NOLOCK, -1 );

	/* Lock each chain from the start one. */
	for (; tlock->hash < tdb->header->hash_size; tlock->hash++ ) {
		if ( tdb_lock( tdb, tlock->hash, F_WRLCK ) )
			return TDB_ERRCODE( TDB_ERR_LOCK, -1 );

		/* No previous record?  Start at top of chain. */
		if ( !tlock->off ) {
			if ( ofs_read( tdb, TDB_HASH_TOP( tlock->hash ), &tlock->off ) )
				goto fail;
			
		} else {
			/* Otherwise unlock the previous record. */
			if ( unlock_record( tdb, tlock->off ) )
				goto fail;
		}
		if ( want_next ) {
			/* We have offset of old record: grab next */
			if ( rec_read( tdb, tlock->off, rec ) )
				goto fail;
			tlock->off = rec->next;
		}

		/* Iterate through chain */
		while( tlock->off ) {
			tdb_off current;
			if ( rec_read( tdb, tlock->off, rec ) )
				goto fail;
			if ( !TDB_DEAD(rec) ) {
				/* Woohoo: we found one! */
				if ( lock_record( tdb, tlock->off ) )
					goto fail;
				return tlock->off;
			}

			/* Detect infinite loops.
				From "Shlomi Yaakobovich" <Shlomi@exanet.com>. */
			if ( tlock->off == rec->next ) {
				TDB_DBG( "tdb_next_lock: loop detected.\n" );
				goto fail;
			}

			/* Try to clean dead ones from old traverses */
			current = tlock->off;
			tlock->off = rec->next;
			if ( !tdb->read_only && do_delete( tdb, current, rec ) )
				goto fail;
		}
		tdb_unlock( tdb, tlock->hash );
		want_next = 0;
	}
	/* We finished iteration without finding anything */
	return TDB_ERRCODE( TDB_ERR_NOEXIST, 0 );

fail:
	tlock->off = 0;
	tdb_unlock( tdb, tlock->hash );
	return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
}

/************************************************
	retrieval
*/

/*
	Returns 0 on fail.  On success, return offset of record, and fills
	in rec
*/
static tdb_off tdb_find ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash,
		struct list_struct *r )
{
	tdb_off rec_ptr;

	/* read in the hash top */
	if ( ofs_read( tdb, TDB_HASH_TOP(hash), &rec_ptr ) )
		return 0;

	/* keep looking until we find the right record */
	while ( rec_ptr ) {
		if ( rec_read( tdb, rec_ptr, r ) )
			return 0;
		if ( !TDB_DEAD(r) && hash == r->full_hash && key->dsize == r->key_len )
		{
			/* a very likely hit - read the key */
			char *k = tdb_pointer( tdb, rec_ptr + sizeof(*r), r->key_len );
			if ( !k )
				return 0;
			if ( !memcmp( key->dptr, k, key->dsize) ) {
				return rec_ptr;
			}
		}
		rec_ptr = r->next;
	}
	return TDB_ERRCODE( TDB_ERR_NOEXIST, 0 );
}

/* As tdb_find, but if you succeed, keep the lock */
static tdb_off tdb_find_lock_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash,
	int locktype, struct list_struct *rec )
{
	tdb_off rec_ptr;
	if ( !tdb_hashlocked( tdb, hash ) )
		return 0;
	if ( tdb_lock( tdb, BUCKET(hash), locktype ) )
		return 0;
	if ( !( rec_ptr = tdb_find( tdb, key, hash, rec ) ) )
		tdb_unlock( tdb, BUCKET(hash) );
	return rec_ptr;
}

/*
	check if an entry in the database exists 
	note that 1 is returned if the key is found and 0 is returned if not found
	this doesn't match the conventions in the rest of this module, but is
	compatible with gdbm
*/
static int tdb_exists_hash ( TDB_CONTEXT *tdb, TDB_DATA *key, u32 hash )
{
	struct list_struct rec;
	if ( !tdb_find_lock_hash(tdb, key, hash, F_RDLCK, &rec ) )
		return 0;
	tdb_unlock( tdb, BUCKET( rec.full_hash ) );
	return 1;
}

/************************************************
	api
*/

/*
	lock the hashes of keys
*/
int tdb_lockhash ( TDB_CONTEXT *tdb, u32 number, TDB_DATA *keys )
{
	u32 i, j, hash;
	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );

	/* Can't lock more keys if already locked */
	if ( tdb->lockedhash[0] )
		return TDB_ERRCODE( TDB_ERR_NOLOCK, -1 );
	if ( sizeof( tdb->lockedhash) / sizeof(tdb->lockedhash[0]) <= number )
		return TDB_ERRCODE( TDB_ERR_OOM, -1 );
	/* First number in array is # keys */
	tdb->lockedhash[0] = number;

	/* Insertion sort by bucket */
	for ( i = 0; i < number; i++ ) {
		hash = tdb->hash_fn( keys + i );
		for ( j = 0; j < i && BUCKET(tdb->lockedhash[j+1]) < BUCKET(hash); j++);
		if ( i - j )
			memmove( tdb->lockedhash + j + 2, tdb->lockedhash + j + 1,
					sizeof(u32) * ( i - j ) );
		tdb->lockedhash[j+1] = hash;
	}
	/* Finally, lock in order */
	for ( i = 1; number >= i; i++ )
		if ( tdb_lock( tdb, BUCKET( tdb->lockedhash[i] ), F_WRLCK ) )
			break;

	/* If error, release locks we have... */
	if (i <= number) {
		for ( j = 0; j < i; j++ )
			tdb_unlock( tdb, BUCKET(tdb->lockedhash[j+1]) );
		CLR_LOCKED( tdb->lockedhash );
		return TDB_ERRCODE( TDB_ERR_NOLOCK, -1 );
	}
	return 0;
}

/*
	Unlock the hashes of the keys previously locked by tdb_lockhash()
*/
void tdb_unlockhash ( TDB_CONTEXT *tdb )
{
	if ( tdb->lockedhash[0] ) {
		u32 i;
		for ( i = 1; i <= tdb->lockedhash[0]; i++ )
			tdb_unlock( tdb, BUCKET( tdb->lockedhash[i] ) );
		CLR_LOCKED( tdb->lockedhash );
	}
}

/*
	lock/unlock entire database
*/
int tdb_lockall ( TDB_CONTEXT *tdb )
{
	/* There are no locks on read-only dbs */
	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
	if ( tdb_brlock(tdb, 0, F_WRLCK, F_SETLKW, 0 ) ) {
		TDB_DBG( "tdb_lockall: failed to lock the database on %s\n",
			strerror( errno ) );
		return -1;  /* errno set by tdb_brlock */
	}
	return 0;
}

void tdb_unlockall ( TDB_CONTEXT *tdb )
{
	if ( !tdb->read_only && tdb_brlock(tdb, 0, F_UNLCK, F_SETLK, 0 ) ) {
		TDB_DBG( "tdb_unlockall: failed to unlock the database on %s\n",
			strerror( errno ) );
	}
}

/*
	Append to an entry. Create if not exist.
*/
int tdb_append ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *new_dbuf )
{
	struct list_struct rec, new_rec;
	u32 hash;
	tdb_off rec_ptr, new_rec_ptr;
	int ret = 0;
	char *tmp = 0;
	int tmp_len;

	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
	/* find which hash bucket it is in */
	hash = tdb->hash_fn( key );
	if ( tdb_lock( tdb, BUCKET(hash), F_WRLCK ) )
		return -1;

	if ( !( rec_ptr = tdb_find( tdb, key, hash, &rec ) ) ) {
		if ( tdb->ecode != TDB_ERR_NOEXIST )
			goto fail;
		/* Not found - create. */
		ret = tdb_store( tdb, key, new_dbuf, TDB_INSERT );
			goto out;
	} 

	/* try in-place first */
	if ( !new_dbuf->dsize )
		goto out;

	if ( rec.rec_len >= key->dsize + rec.data_len + new_dbuf->dsize
				+ sizeof( tdb_off )
	) {
		if ( !tdb_write( tdb, rec_ptr + sizeof(rec) + rec.key_len
				+ rec.data_len, new_dbuf->dptr, new_dbuf->dsize )
		) {
			/* update size */
			rec.data_len += new_dbuf->dsize;
			if ( rec_write( tdb, rec_ptr, &rec ) )
				goto fail;
			goto out;
		}
	}

	/*
		copy old record, since tdb_delete_hash may override it
	*/
	if ( ! ( tmp = (char *) malloc( tmp_len = rec.key_len + rec.data_len ) ) ) {
		tdb->ecode = TDB_ERR_OOM;
		goto fail;
	}
	memcpy( tmp, tdb->map_ptr + rec_ptr + sizeof( rec ), tmp_len );
	
	/* delete any existing record - if it doesn't exist we don't
		care.  Doing this first reduces fragmentation, and avoids
		coalescing with `allocated' block before it's updated. */
	tdb_delete_hash( tdb, key, hash );
	
	if ( !( new_rec_ptr = tdb_allocate( tdb, key->dsize + rec.data_len
				+ new_dbuf->dsize, &new_rec ) )
			|| ofs_read( tdb, TDB_HASH_TOP(hash), &new_rec.next )
	)
		goto fail;

	new_rec.key_len = key->dsize;
	new_rec.data_len = rec.data_len + new_dbuf->dsize;
	new_rec.full_hash = hash;
	new_rec.magic = TDB_MAGIC;

	/* write out and point the top of the hash chain at it */
	if ( rec_write( tdb, new_rec_ptr, &new_rec )
			|| tdb_write( tdb, new_rec_ptr + sizeof( rec ), tmp, tmp_len )
			|| tdb_write( tdb, new_rec_ptr + sizeof(rec) + tmp_len,
					new_dbuf->dptr, new_dbuf->dsize )
			|| ofs_write( tdb, TDB_HASH_TOP(hash), &new_rec_ptr )
	)
		goto fail;

out:
	SAFE_FREE( tmp );
	tdb_unlock( tdb, BUCKET(hash) );
	return ret;

fail:
	ret = -1;
	goto out;
}

/*
	store an element in the database.
	depending on flag any existing element with the same key will be replaced.
*/
int tdb_store ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dbuf, int flag )
{
	return do_store( tdb, key, dbuf, flag, 0 );
}

/*
	insert a new element
	allocate `space´ additional bytes
*/
int tdb_insert ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dbuf, u32 space )
{
	return do_store( tdb, key, dbuf, TDB_INSERT, space );
}

int tdb_delete ( TDB_CONTEXT *tdb, TDB_DATA *key )
{
	if ( tdb->read_only )
		return TDB_ERRCODE( TDB_ERR_LOCK, -1 );
	return tdb_delete_hash( tdb, key, tdb->hash_fn( key ) );
}

int tdb_exists ( TDB_CONTEXT *tdb, TDB_DATA *key )
{
	return tdb_exists_hash(tdb, key, tdb->hash_fn( key ) );
}

#ifdef LUA_BINDING
/*
	find an entry in the database given a key 
	If an entry doesn't exist ecode will be set to TDB_ERR_NOEXIST. The data
	will be placed idirectly on the lua stack
	return 1 on success 0 else
*/
int tdb_fetch ( TDB_CONTEXT *tdb, TDB_DATA *key, lua_State *L )
{
	tdb_off rec_ptr;
	struct list_struct rec;

	tdb->ecode = TDB_SUCCESS;
	/* find which hash bucket it is in */
	if ( !( rec_ptr = tdb_find_lock_hash( tdb, key, tdb->hash_fn( key ),
			F_RDLCK, &rec ) ) )
		return 0;
	lua_pushlstring( L, tdb->map_ptr + rec_ptr + sizeof(rec) + rec.key_len,
			rec.data_len );
	tdb_unlock( tdb, BUCKET(rec.full_hash) );
	return 1;
}

/*
	find the first entry in the database and push its key on the lua stack
	if dst->dsize < key->dsize ecode will be set to TDB_ERR_OOM.
	return 1 on success 0 else
	the read lock on the key found is kept
*/
int tdb_firstkey ( TDB_CONTEXT *tdb, lua_State *L )
{
	struct list_struct rec;
	tdb->ecode = TDB_SUCCESS;

	/* release any old lock */
	if ( unlock_record( tdb, tdb->travlocks.off ) )
		return 0;
	tdb->travlocks.off = tdb->travlocks.hash = 0;
	if ( 0 >= tdb_next_lock( tdb, &tdb->travlocks, &rec ) )
		return 0;
	/* now push the key on the stack */
	lua_pushlstring( L, tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
			rec.key_len );
	tdb_unlock( tdb, BUCKET( tdb->travlocks.hash ) );
	return 1;
}

/*
	find the next entry in the database after key,
	pushing the key right on the lua stack
*/
int tdb_nextkey ( TDB_CONTEXT *tdb, TDB_DATA *key, lua_State *L )
{
	u32 oldhash;
	struct list_struct rec;
	int ret;
	tdb->ecode = TDB_SUCCESS;

	/* Is locked key the old key?  If so, traverse will be reliable. */
	if ( tdb->travlocks.off ) {
		if ( tdb_lock( tdb, tdb->travlocks.hash, F_WRLCK ) )
			return 0;
		if ( rec_read( tdb, tdb->travlocks.off, &rec )
				|| rec.key_len != key->dsize
				|| memcmp( tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
						key->dptr, rec.key_len )
		) {
			/* No, it wasn't: unlock it and start from scratch */
			if ( unlock_record( tdb, tdb->travlocks.off )
					|| tdb_unlock( tdb, tdb->travlocks.hash )
			)
				return 0;
			tdb->travlocks.off = 0;
		}
	}

	if ( !tdb->travlocks.off ) {
		/* No previous element: do normal find, and lock record */
		if ( ! ( tdb->travlocks.off = tdb_find_lock_hash( tdb, key,
				tdb->hash_fn( key ), F_WRLCK, &rec ) )
		)
			return 0;
		tdb->travlocks.hash = BUCKET( rec.full_hash );
		if ( lock_record( tdb, tdb->travlocks.off ) ) {
			tdb_unlock( tdb, tdb->travlocks.hash );
			TDB_DBG( "tdb_nextkey: lock_record failed (%s)!\n", strerror(errno) );
			return 0;
		}
	}
	oldhash = tdb->travlocks.hash;

	/* Grab next record: locks chain and returned record,
		unlocks old record */
	switch ( ( ret = tdb_next_lock( tdb, &tdb->travlocks, &rec ) ) ) {
	case 0:
		lua_pushnil( L );
		ret = 1;
	case -1:
		break;
	default:
		lua_pushlstring( L, tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
			rec.key_len );
		ret = 1;
		/* Unlock the chain of this new record */
		tdb_unlock( tdb, tdb->travlocks.hash );
	}
	/* Unlock the chain of old record */
	tdb_unlock( tdb, BUCKET( oldhash ) );
	if ( 0 >= ret && tdb->travlocks.off ) 
		unlock_record( tdb, tdb->travlocks.off );
	return 1 == ret;
}

#else
/*
	find an entry in the database given a key 
	If an entry doesn't exist ecode will be set to TDB_ERR_NOEXIST. The data
	will be placed in dst, if dst->dsize < data->dsize ecode will be set to
	TDB_ERR_OOM.
	return 0 on success -1 else
*/
int tdb_fetch ( TDB_CONTEXT *tdb, TDB_DATA *key, TDB_DATA *dst )
{
	tdb_off rec_ptr;
	struct list_struct rec;
	int ret = 0;

	tdb->ecode = TDB_SUCCESS;
	/* find which hash bucket it is in */
	if ( !( rec_ptr = tdb_find_lock_hash( tdb, key, tdb->hash_fn( key ),
			F_RDLCK, &rec ) ) )
		return -1;
	if (  rec.data_len <= dst->dsize ) {
		if ( ( dst->dsize = rec.data_len ) ) {
			memcpy( dst->dptr,
					tdb->map_ptr + rec_ptr + sizeof(rec) + rec.key_len,
					rec.data_len );
		}
	} else {
		tdb->ecode = TDB_ERR_OOM;
		ret = -1;
	}
	tdb_unlock( tdb, BUCKET(rec.full_hash) );
	return ret;
}

/*
	find the first entry in the database and return its key in dst
	if dst->dsize < key->dsize ecode will be set to TDB_ERR_OOM.
	return 0 on success -1 else
	the read lock on the key found is kept
*/
int tdb_firstkey ( TDB_CONTEXT *tdb, TDB_DATA *dst )
{
	struct list_struct rec;
	tdb->ecode = TDB_SUCCESS;

	/* release any old lock */
	if ( unlock_record( tdb, tdb->travlocks.off ) )
		return -1;
	tdb->travlocks.off = tdb->travlocks.hash = 0;
	if ( 0 >= tdb_next_lock( tdb, &tdb->travlocks, &rec ) )
		return -1;
	if ( rec.key_len > dst->dsize) {
		tdb->ecode = TDB_ERR_OOM;
		return -1;
	}
	/* now read the key */
	memcpy( dst->dptr, tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
			( dst->dsize = rec.key_len ) );
	tdb_unlock( tdb, BUCKET( tdb->travlocks.hash ) );
	return 0;
}

/*
	find the next entry in the database after key,
	storing its key in key
	if dsize < rec.key_len ecode will be set to TDB_ERR_OOM.
	return 1 on success, 0 on finish, -1 on error
	the read lock on the key found is kept
*/
int tdb_nextkey ( TDB_CONTEXT *tdb, TDB_DATA *key, size_t dsize )
{
	u32 oldhash;
	struct list_struct rec;
	int ret;
	tdb->ecode = TDB_SUCCESS;

	/* Is locked key the old key?  If so, traverse will be reliable. */
	if ( tdb->travlocks.off ) {
		if ( tdb_lock( tdb, tdb->travlocks.hash, F_WRLCK ) )
			return -1;
		if ( rec_read( tdb, tdb->travlocks.off, &rec )
				|| rec.key_len != key->dsize
				|| memcmp( tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
						key->dptr, rec.key_len )
		) {
			/* No, it wasn't: unlock it and start from scratch */
			if ( unlock_record( tdb, tdb->travlocks.off )
					|| tdb_unlock( tdb, tdb->travlocks.hash )
			)
				return -1;
			tdb->travlocks.off = 0;
		}
	}

	if ( !tdb->travlocks.off ) {
		/* No previous element: do normal find, and lock record */
		if ( ! ( tdb->travlocks.off = tdb_find_lock_hash( tdb, key,
				tdb->hash_fn( key ), F_WRLCK, &rec ) )
		)
			return -1;
		tdb->travlocks.hash = BUCKET( rec.full_hash );
		if ( lock_record( tdb, tdb->travlocks.off ) ) {
			tdb_unlock( tdb, tdb->travlocks.hash );
			TDB_DBG( "tdb_nextkey: lock_record failed (%s)!\n", strerror(errno) );
			return -1;
		}
	}
	oldhash = tdb->travlocks.hash;

	/* Grab next record: locks chain and returned record,
		unlocks old record */
	switch ( ( ret = tdb_next_lock( tdb, &tdb->travlocks, &rec ) ) ) {
	case 0:
		key->dsize = 0;
	case -1:
		break;
	default:
		if ( rec.key_len > dsize ) {
			tdb->ecode = TDB_ERR_OOM;
			ret = -1;
		} else {
			memcpy( key->dptr, tdb->map_ptr + tdb->travlocks.off + sizeof(rec),
					( key->dsize = rec.key_len ) );
			ret = 1;
		}
		/* Unlock the chain of this new record */
		tdb_unlock( tdb, tdb->travlocks.hash );
	}
	/* Unlock the chain of old record */
	tdb_unlock( tdb, BUCKET( oldhash ) );
	if ( 0 >= ret && tdb->travlocks.off ) 
		unlock_record( tdb, tdb->travlocks.off );
	return ret;
}
#endif /* LUA_BINDING */

/*
	traverse the entire database using traverse locks - calling fn(tdb, key,
	data, cdata) on each element.
	return -1 on error or the record count traversed
	a non-zero return value from fn() indicates that the traversal should stop
*/
int tdb_traverse ( TDB_CONTEXT *tdb, tdb_traverse_func fn, void *cdata )
{
	struct list_struct rec;
	struct tdb_traverse_lock tl = { NULL, 0, 0 };
	int ret = 0, count = 0;
	TDB_DATA k, v;
	tl.next = tdb->travlocks.next;

	/* fcntl locks don't stack: beware traverse inside traverse */
	tdb->travlocks.next = &tl;

	/* tdb_next_lock places locks on the record returned, and its chain */
	while ( 0 < ( ret = tdb_next_lock( tdb, &tl, &rec ) ) ) {
		count++;
		if ( fn ) {
			k.dptr = tdb->map_ptr + tl.off + sizeof(rec);
			k.dsize = rec.key_len;
			v.dptr = k.dptr + rec.key_len;
			v.dsize = rec.data_len;
			if ( fn( tdb, &k, &v, cdata ) ) {
				/* They want us to terminate traversal */
				if ( unlock_record( tdb, tl.off ) ) {
					TDB_DBG( "tdb_traverse: unlock_record failed!\n" );
					ret = -1;
				}
			}
		}
		if ( tdb_unlock( tdb, tl.hash ) ) {
			TDB_DBG( "tdb_traverse: tdb_unlock of hash chain failed\n" );
			ret = -1;
		}
		if ( -1 == ret )
			break;
	}
	tdb->travlocks.next = tl.next;
	return 0 > ret ? -1 : count;
}

/*
	iterate over all records locking the entire database once - calling fn(tdb,
	key, data, cdata) on each element.
	return -1 on error or the record count traversed
	a non-zero return value from fn() indicates that the iteration should stop
*/
int tdb_iterate ( TDB_CONTEXT *tdb, tdb_traverse_func fn, void *cdata )
{
	struct list_struct rec;
	int ret = 0, cnt = 0;
	TDB_DATA k, v;
	tdb_off off = TDB_DATA_START( tdb->header->hash_size ) + sizeof( tdb_off );
	/* ensure there is no process writing during traversal */
	if ( tdb_brlock(tdb, 0, F_RDLCK, F_SETLKW, 0 ) ) {
		TDB_DBG( "tdb_iterate: failed to lock the database on %s\n",
			strerror( errno ) );
		return -1;  /* errno set by tdb_brlock */
	}
	for ( ;; ) {
		if ( tdb_read( tdb, off, &rec, sizeof(rec), DOCONV() ) )
			break;
		if ( TDB_MAGIC == rec.magic ) {
			cnt++;
			if ( fn ) {
				k.dptr = tdb->map_ptr + off + sizeof(rec);
				k.dsize = rec.key_len;
				v.dptr = k.dptr + rec.key_len;
				v.dsize = rec.data_len;
				if ( fn( tdb, &k, &v, cdata ) )
					break;
			}
		}
		off += rec.rec_len + sizeof( rec );
	}
	if ( tdb_brlock(tdb, 0, F_UNLCK, F_SETLK, 0 ) ) {
		TDB_DBG( "tdb_iterate: failed to unlock the database on %s\n",
			strerror( errno ) );
		ret = -1;
	}
	return 0 > ret ? -1 : cnt;
}

/*
	clears the read lock held during traversal with tdb_firstkey / tdb_nextkey
*/
void tdb_clearkeylock ( TDB_CONTEXT *tdb )
{
	if ( tdb->travlocks.off ) {
		unlock_record( tdb, tdb->travlocks.off );
		tdb->travlocks.hash = tdb->travlocks.off = 0;
	}
}

void tdb_set_lock_alarm ( int *palarm )
{
	alarmed = palarm;
}

/*
	open the database, creating it if necessary
	the TDB_CONTEXT structure and the chain lock structure are allocated here,
	since the hash_size of the tdb might not be known
*/
TDB_CONTEXT * tdb_open ( const char *name,
		int hash_size,
		int tdb_flags,
		int open_flags,
		mode_t mode,
		tdb_hash_func hash_fn )
{
	struct stat st;
	TDB_CONTEXT *t, *tdb = 0;
	int rev = 0;
	
	if ( O_WRONLY == ( open_flags & O_ACCMODE ) ) {
		TDB_DBG( "tdb_open: can't open tdb %s write-only\n",
			name );
		errno = EINVAL;
		goto fail;
	}
	
	if ( !( tdb = calloc( 1, sizeof *tdb ) ) ) {
		/* Can't log this */
		errno = ENOMEM;
		goto fail;
	}
	tdb->fd = -1;
	tdb->map_ptr = MAP_FAILED;
	tdb->flags = tdb_flags;
	tdb->open_flags = open_flags;
	tdb->hash_fn = hash_fn ? hash_fn : default_tdb_hash;
	
	if ( 0 >= hash_size ) hash_size = DEFAULT_HASH_SIZE;
	CLR_LOCKED( tdb->lockedhash );
	
	if ( O_RDONLY == ( tdb->open_flags & O_ACCMODE ) ) {
		tdb->read_only = 1;
		/* read only databases don't do locking or clear if first */
		tdb->flags |= TDB_NOLOCK;
		tdb->flags &= ~TDB_CLEAR_IF_FIRST;
	}

	if ( 0 > ( tdb->fd = open( name, tdb->open_flags, mode ) ) ) {
		TDB_DBG( "tdb_open: could not open file %s: %s\n",
				name, strerror( errno ) );
		goto fail;  /* errno set by open(2) */
   }
	if ( fstat( tdb->fd, &st ) )
		goto fail;
	/* Is it already in the open list?  If so, fail. */	
	for ( t = tdbs; t; t = t->next )
		if ( t->device == st.st_dev && t->inode == st.st_ino )
			goto fail;

	tdb->device = st.st_dev;
	tdb->inode = st.st_ino;
 
	/* ensure there is only one process initialising at once */
	if ( tdb_brlock(tdb, GLOBAL_LOCK, F_WRLCK, F_SETLKW, 1 ) ) {
		TDB_DBG( "tdb_open: failed to get global lock on %s: %s\n",
			name, strerror( errno ) );
		goto fail;  /* errno set by tdb_brlock */
	}

	/* we need to zero database if we are the only one with it open */
	if ( ( tdb_flags & TDB_CLEAR_IF_FIRST ) &&
			!( tdb_brlock( tdb, ACTIVE_LOCK, F_WRLCK, F_SETLK, 1 ) )
	) {
		tdb->open_flags |= O_CREAT;
		if ( -1 == ftruncate( tdb->fd, 0 ) ) {
			TDB_DBG( "tdb_open: failed to truncate %s: %s\n",
					name, strerror( errno ) );
			goto fail; /* errno set by ftruncate */
		}
		st.st_size = 0;
	}

	if ( !st.st_size && ( O_CREAT & tdb->open_flags ) ) {
		if ( tdb_new_database( tdb, hash_size ) ) {
			errno = EIO; /* ie bad format or something */
			goto fail;
		}
		rev = ( tdb->header->version == TDB_BYTEREV( TDB_VERSION ) );
	} else {
		tdb->map_size = st.st_size;
		if ( tdb_mmap( tdb ) 
			|| strncmp( tdb->header->magic_food, TDB_MAGIC_FOOD,
					sizeof( TDB_MAGIC_FOOD ) - 1  )
			|| ( tdb->header->version != TDB_VERSION
					&& ! ( rev = 
						( tdb->header->version == TDB_BYTEREV( TDB_VERSION ) ) ) )
		)
			goto fail;
	}
	if ( rev )
		tdb->flags |= TDB_CONVERT;

	if ( !( tdb->locked = 
			calloc( tdb->header->hash_size + 1, sizeof( tdb->locked[0] ) ) )
	) {
		errno = ENOMEM;
		goto fail;
	}

	/* leave this lock in place to indicate it's in use */
	if ( ( TDB_CLEAR_IF_FIRST & tdb->flags ) 
			&& tdb_brlock( tdb, ACTIVE_LOCK, F_RDLCK, F_SETLKW, 1 ) )
			goto fail;

   if ( tdb_brlock( tdb, GLOBAL_LOCK, F_UNLCK, F_SETLKW, 1 ) )
		goto fail;

	tdb->next = tdbs;
	tdbs = tdb;
	return tdb;

fail:
	if ( tdb ) {
		int e = errno;
		if ( 0 <= tdb->fd )
			close( tdb->fd );
		if ( MAP_FAILED != tdb->map_ptr )
			tdb_munmap( tdb );
		SAFE_FREE( tdb->locked );
		SAFE_FREE( tdb );
		errno = e;
	}
	return 0;
}

/*
	Close a database.
*/
void tdb_close ( TDB_CONTEXT *tdb )
{
	TDB_CONTEXT **t;
	if ( MAP_FAILED != tdb->map_ptr ) {
		tdb_munmap( tdb );
	}
	if ( tdb->fd != -1 )
		close(tdb->fd);
	SAFE_FREE( tdb->locked );

	/* Remove from contexts list */
	for ( t = &tdbs; *t; *t = (*t)->next) {
		if ( *t == tdb ) {
			*t = tdb->next;
			break;
		}
	}
	SAFE_FREE( tdb );
}

/*
	lock/unlock one hash chain. This is meant to be used to reduce
	contention - it cannot guarantee how many records will be locked
*/
int tdb_chainlock ( TDB_CONTEXT *tdb, TDB_DATA *key )
{
	return do_chainlock( tdb, key, F_WRLCK );
}
int tdb_chainunlock ( TDB_CONTEXT *tdb, TDB_DATA *key )
{
	return do_chainlock( tdb, key, 0 );
}
int tdb_chainlock_read ( TDB_CONTEXT *tdb, TDB_DATA *key )
{
	return do_chainlock( tdb, key, F_RDLCK );
}

