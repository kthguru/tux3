#ifndef TUX3_DLEAF2_H
#define TUX3_DLEAF2_H

#define SEG_HOLE	(1 << 0)
#define SEG_NEW		(1 << 1)

struct seg {
	block_t block;
	unsigned count;
	unsigned state;
};

struct dleaf_req {
	struct btree_key_range key;	/* index and count */

	int nr_segs;			/* Number of segs used */
	int max_segs;			/* Maximum segs */
	struct seg *seg;
};

#endif /* !TUX3_DLEAF2_H */
