#ifndef TUX3_H
#define TUX3_H
#include <inttypes.h>
#include "trace.h"

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t le_u16;
typedef uint32_t le_u32;
typedef uint64_t le_u64;

#define fieldtype(structure, field) typeof(((struct structure *)NULL)->field)
#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

typedef uint64_t inum_t;
typedef u64 block_t;

struct bleaf
{
	le_u16 magic, version;
	le_u32 count;
	le_u64 using_mask;
	struct etree_map { le_u32 offset; le_u32 block; } map[];
};

#define SB_MAGIC { 't', 'e', 's', 't', 0xdd, 0x08, 0x08, 0x06 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 */


struct disksuper
{
	typeof((char[])SB_MAGIC) magic;
	u64 create_time;
	block_t root;
	u64 flags;
	u32 levels;
	u32 sequence; /* commit block sequence number */
	block_t bitmap_base;
	block_t blocks; /* if zero then snapdata is combined in metadata space */
	block_t freeblocks;
	block_t last_alloc;
	u64 bitmap_blocks;
	u32 blocksize_bits;
};

struct sb
{
	struct disksuper image;
	char bogopad[4096 - sizeof(struct disksuper)];
	struct dev *dev;
	u32 alloc_per_node;
};
#endif