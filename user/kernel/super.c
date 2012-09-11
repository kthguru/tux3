/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include "tux3.h"
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

/* This will go to include/linux/magic.h */
#ifndef TUX3_SUPER_MAGIC
#define TUX3_SUPER_MAGIC	0x74757833
#endif

#define trace trace_on

/* FIXME: this should be mount option? */
int tux3_trace;
module_param(tux3_trace, int, 0644);
#endif

#ifdef ATOMIC
#ifdef __KERNEL__
#define BUFFER_LINK	b_assoc_buffers
#else
#define BUFFER_LINK	link
#endif
static void cleanup_dirty_buffers(struct list_head *head)
{
	struct buffer_head *buffer, *n;

	list_for_each_entry_safe(buffer, n, head, BUFFER_LINK) {
		trace(">>> clean inum %Lx, buffer %Lx, count %d",
		      tux_inode(buffer_inode(buffer))->inum,
		      bufindex(buffer), bufcount(buffer));
		assert(buffer_dirty(buffer));
		tux3_clear_buffer_dirty(buffer);
	}
}

static void cleanup_dirty_inode(struct inode *inode)
{
	if (!list_empty(&tux_inode(inode)->dirty_list)) {
		trace(">>> clean inum %Lx, i_count %d, i_state %lx",
		      tux_inode(inode)->inum, atomic_read(&inode->i_count),
		      inode->i_state);
		del_defer_alloc_inum(inode);
		tux3_clear_dirty_inode(inode);
	}
}

/*
 * Some inode/buffers are always (re-)dirtied, so we have to cleanup
 * those for umount.
 */
static void cleanup_dirty_for_umount(struct sb *sb)
{
	unsigned rollup = sb->rollup;

	/*
	 * Pinned buffer and bitmap are not flushing always, it is
	 * normal. So, this clean those for unmount.
	 */
	if (sb->bitmap) {
		struct dirty_buffers *dirty = inode_dirty_heads(sb->bitmap);
		cleanup_dirty_buffers(dirty_head_when(dirty, rollup));
		cleanup_dirty_inode(sb->bitmap);
	}
	cleanup_dirty_buffers(dirty_head_when(&sb->pinned, rollup));

	/* orphan_add should be empty */
	assert(list_empty(&sb->orphan_add));
	/* Deferred orphan deletion request is not flushed for each delta  */
	clean_orphan_list(&sb->orphan_del);

	/* defree must be flushed for each delta */
	assert(flink_empty(&sb->defree.head)||flink_is_last(&sb->defree.head));
}
#else /* !ATOMIC */
static inline void cleanup_dirty_for_umount(struct sb *sb)
{
}
#endif /* !ATOMIC */

static void __tux3_put_super(struct sb *sbi)
{
	/* All forked buffers should be freed here */
	free_forked_buffers(sbi, 1);

	destroy_defer_bfree(&sbi->derollup);
	destroy_defer_bfree(&sbi->defree);

	iput(sbi->rootdir);
	sbi->rootdir = NULL;
	iput(sbi->atable);
	sbi->atable = NULL;
	iput(sbi->vtable);
	sbi->vtable = NULL;
	iput(sbi->bitmap);
	sbi->bitmap = NULL;
	iput(sbi->logmap);
	sbi->logmap = NULL;
	iput(sbi->volmap);
	sbi->volmap = NULL;

	/* FIXME: add more sanity check */
	assert(list_empty(&sbi->alloc_inodes));
	assert(link_empty(&sbi->forked_buffers));
}

static struct inode *create_internal_inode(struct sb *sbi, inum_t inum,
					   struct tux_iattr *iattr)
{
	static struct tux_iattr null_iattr;
	struct inode *dir = &(struct inode){
		.i_sb = vfs_sb(sbi),
		.i_mode = S_IFDIR | 0755,
	};
	struct inode *inode;

	if (iattr == NULL)
		iattr = &null_iattr;

	inode = __tux_create_inode(dir, inum, iattr, 0);
	assert(IS_ERR(inode) || tux_inode(inode)->inum == inum);
	return inode;
}

/*
 * Internal inode (e.g. bitmap inode) yet may not be written. So, if
 * there is no inode, create inode instead.
 */
static struct inode *iget_or_create_inode(struct sb *sbi, inum_t inum)
{
	struct inode *inode;

	inode = tux3_iget(sbi, inum);
	if (IS_ERR(inode) && PTR_ERR(inode) == -ENOENT)
		inode = create_internal_inode(sbi, inum, NULL);
	return inode;
}

struct replay *tux3_init_fs(struct sb *sbi)
{
	struct replay *rp = NULL;
	struct inode *inode;
	int err;

	err = -ENOMEM;

	/* Prepare non on-disk inodes */
	sbi->volmap = tux_new_volmap(sbi);
	if (!sbi->volmap)
		goto error;

	sbi->logmap = tux_new_logmap(sbi);
	if (!sbi->logmap)
		goto error;

	/* Replay physical structures */
	rp = replay_stage1(sbi);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}

	/* Load internal inodes */
	inode = iget_or_create_inode(sbi, TUX_BITMAP_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->bitmap = inode;
#if 0
	inode = tux3_iget(sbi, TUX_VTABLE_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->vtable = inode;
#endif
	inode = tux3_iget(sbi, TUX_ATABLE_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->atable = inode;

	inode = tux3_iget(sbi, TUX_ROOTDIR_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->rootdir = inode;

	err = replay_stage2(rp);
	if (err) {
		rp = NULL;
		goto error;
	}

	return rp;

error_inode:
	err = PTR_ERR(inode);
error:
	if (!IS_ERR_OR_NULL(rp))
		replay_stage3(rp, 0);
	__tux3_put_super(sbi);

	return ERR_PTR(err);
}

#ifdef __KERNEL__
static struct kmem_cache *tux_inode_cachep;

static void tux3_inode_init_once(void *mem)
{
	tuxnode_t *tuxi = mem;

	INIT_LIST_HEAD(&tuxi->dirty_list);
	INIT_LIST_HEAD(&tuxi->alloc_list);
	INIT_LIST_HEAD(&tuxi->orphan_list);
	init_dirty_buffers(inode_dirty_heads(&tuxi->vfs_inode));
	inode_init_once(&tuxi->vfs_inode);
}

static int __init tux3_init_inodecache(void)
{
	tux_inode_cachep = kmem_cache_create("tux3_inode_cache",
		sizeof(tuxnode_t), 0, (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
		tux3_inode_init_once);
	if (tux_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void __exit tux3_destroy_inodecache(void)
{
	kmem_cache_destroy(tux_inode_cachep);
}

static struct inode *tux3_alloc_inode(struct super_block *sb)
{
	static struct timespec epoch;
	tuxnode_t *tuxi = kmem_cache_alloc(tux_inode_cachep, GFP_KERNEL);

	if (!tuxi)
		return NULL;
	tuxi->btree = (struct btree){ };
	tuxi->present = 0;
	tuxi->xcache = NULL;
	tuxi->io = NULL;

	/* uninitialized stuff by alloc_inode() */
	tuxi->vfs_inode.i_version = 1;
	tuxi->vfs_inode.i_atime = epoch;
	tuxi->vfs_inode.i_mtime = epoch;
	tuxi->vfs_inode.i_ctime = epoch;
	tuxi->vfs_inode.i_mode = 0;
	return &tuxi->vfs_inode;
}

static void tux3_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(tux_inode_cachep, tux_inode(inode));
}

static void tux3_destroy_inode(struct inode *inode)
{
	BUG_ON(!list_empty(&tux_inode(inode)->dirty_list));
	BUG_ON(!list_empty(&tux_inode(inode)->alloc_list));
	BUG_ON(!list_empty(&tux_inode(inode)->orphan_list));
	BUG_ON(!dirty_buffers_is_empty(inode_dirty_heads(inode)));
	call_rcu(&inode->i_rcu, tux3_i_callback);
}

#ifndef ATOMIC
static void tux3_write_super(struct super_block *sb)
{
	lock_super(sb);
	if (save_sb(tux_sb(sb))) {
		printk(KERN_ERR "TUX3: unable to write superblock\n");
		return;
	}
	sb->s_dirt = 0;
	unlock_super(sb);
}

/* Just a glue to be called to write sb for non-atomic mode ->sync_fs(). */
int force_delta(struct sb *sb)
{
	tux3_write_super(vfs_sb(sb)); /* FIXME: error handling */
	return 0;
}
#endif

static int tux3_sync_fs(struct super_block *sb, int wait)
{
	/* FIXME: We should support "wait" parameter. */
	trace_on("wait (%u) parameter is unsupported for now", wait);
	return force_delta(tux_sb(sb));
}

struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	unsigned long *older_than_this;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	enum wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

static struct wb_writeback_work *
get_next_work_item(struct backing_dev_info *bdi)
{
	struct wb_writeback_work *work = NULL;

	spin_lock_bh(&bdi->wb_lock);
	if (!list_empty(&bdi->work_list)) {
		work = list_entry(bdi->work_list.next,
				  struct wb_writeback_work, list);
		list_del_init(&work->list);
	}
	spin_unlock_bh(&bdi->wb_lock);
	return work;
}

static long tux3_do_writeback(struct bdi_writeback *wb, int force_wait)
{
	struct backing_dev_info *bdi = wb->bdi;
	struct wb_writeback_work *work = NULL;
	long wrote = 0;

	set_bit(BDI_writeback_running, &wb->bdi->state);
	while ((work = get_next_work_item(bdi)) != NULL) {
		/*
		 * Override sync mode, in case we must wait for completion
		 * because this thread is exiting now.
		 */
		if (force_wait)
			work->sync_mode = WB_SYNC_ALL;
#if 0
		wrote += wb_writeback(wb, work);
#endif
		/*
		 * Notify the caller of completion if this is a synchronous
		 * work item, otherwise just free it.
		 */
		if (work->done)
			complete(work->done);
		else
			kfree(work);
	}
#if 0
	/*
	 * Check for periodic writeback, kupdated() style
	 */
	wrote += wb_check_old_data_flush(wb);
	wrote += wb_check_background_flush(wb);
#endif
	clear_bit(BDI_writeback_running, &wb->bdi->state);

	return wrote;
}

/*
 * Handle writeback of dirty data for the device backed by this bdi. Also
 * wakes up periodically and does kupdated style flushing.
 */
int tux3_writeback_thread(void *data)
{
	struct bdi_writeback *wb = data;
	struct backing_dev_info *bdi = wb->bdi;
	long pages_written;

	current->flags |= PF_SWAPWRITE;
	set_freezable();
	wb->last_active = jiffies;

	/*
	 * Our parent may run at a different priority, just set us to normal
	 */
	set_user_nice(current, 0);

	while (!kthread_freezable_should_stop(NULL)) {
		/*
		 * Remove own delayed wake-up timer, since we are already awake
		 * and we'll take care of the preriodic write-back.
		 */
		del_timer(&wb->wakeup_timer);

		pages_written = tux3_do_writeback(wb, 0);

		if (pages_written)
			wb->last_active = jiffies;

		set_current_state(TASK_INTERRUPTIBLE);
		if (!list_empty(&bdi->work_list) || kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			continue;
		}

		if (wb_has_dirty_io(wb) && dirty_writeback_interval)
			schedule_timeout(msecs_to_jiffies(dirty_writeback_interval * 10));
		else {
			/*
			 * We have nothing to do, so can go sleep without any
			 * timeout and save power. When a work is queued or
			 * something is made dirty - we will be woken up.
			 */
			schedule();
		}
	}

	/* Flush any work that raced with us exiting */
	if (!list_empty(&bdi->work_list))
		tux3_do_writeback(wb, 1);

	return 0;
}

#ifndef BDI_SET_TO_MAPPING
static int passthrough_congested_fn(void *data, int bits)
{
	struct sb *sbi = data;
	return bdi_congested(sbi->orig_bdi, bits);
}
#else
static int bug_congested_fn(void *data, int bits)
{
	BUG();
	return 0;
}
#endif

/*
 * We need to disable writeback to control dirty flags of inode.
 * Otherwise, writeback will clear dirty, and inode can be reclaimed
 * without our control.
 */
static int setup_bdi(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);
	struct backing_dev_info *bdi = &sbi->bdi;
	struct backing_dev_info *orig_bdi = sb->s_bdi;
	dev_t dev = sb->s_bdev->bd_dev;
	struct task_struct *task;
	int err;

	bdi->name		= "tux3";
#ifndef BDI_SET_TO_MAPPING
	bdi->capabilities	= orig_bdi->capabilities | BDI_CAP_NO_WRITEBACK;
	bdi->ra_pages		= orig_bdi->ra_pages;
	bdi->congested_fn	= passthrough_congested_fn;
	bdi->congested_data	= sbi;
#else
	bdi->capabilities	= BDI_CAP_NO_WRITEBACK;
	bdi->congested_fn	= bug_congested_fn;
#endif

	err = bdi_init(bdi);
	if (err)
		return err;

	err = bdi_register(bdi, NULL, "%s-%u:%u", bdi->name,
			   MAJOR(dev), MINOR(dev));
	if (err) {
		bdi_destroy(bdi);
		return err;
	}

	sbi->orig_bdi = orig_bdi;
	sb->s_bdi = bdi;

	task = kthread_create(tux3_writeback_thread, &bdi->wb,
			      "flush-%s", dev_name(bdi->dev));
	if (IS_ERR(task)) {
		bdi_destroy(bdi);
		return PTR_ERR(task);
	}

	/*
	 * The spinlock makes sure we do not lose wake-ups when racing
	 * with 'bdi_queue_work()'.  And as soon as the bdi thread is
	 * visible, we can start it.
	 */
	spin_lock_bh(&bdi->wb_lock);
	bdi->wb.task = task;
	spin_unlock_bh(&bdi->wb_lock);

	return 0;
}

static void cleanup_bdi(struct super_block *sb)
{
	struct backing_dev_info *bdi = sb->s_bdi;
	struct task_struct *task;

	sb->s_bdi = tux_sb(sb)->orig_bdi;

	/*
	 * Finally, kill the kernel thread. We don't need to be RCU
	 * safe anymore, since the bdi is gone from visibility.
	 */
	spin_lock_bh(&bdi->wb_lock);
	task = bdi->wb.task;
	bdi->wb.task = NULL;
	spin_unlock_bh(&bdi->wb_lock);

	if (task)
		kthread_stop(task);

	bdi_destroy(bdi);
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

	cleanup_dirty_for_umount(sbi);

	__tux3_put_super(sbi);
	cleanup_bdi(sb);

	sb->s_fs_info = NULL;
	kfree(sbi);
}

static int tux3_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct sb *sbi = tux_sb(sb);

	buf->f_type = sb->s_magic;
	buf->f_bsize = sbi->blocksize;
	buf->f_blocks = sbi->volblocks;
	buf->f_bfree = sbi->freeblocks;
	buf->f_bavail = sbi->freeblocks;
#if 0
	buf->f_files = buf->f_blocks << (sbi->clus_bits - EXFAT_CHUNK_BITS) / 3;
	buf->f_ffree = buf->f_blocks << (sbi->clus_bits - EXFAT_CHUNK_BITS) / 3;
	buf->f_fsid.val[0] = sbi->serial_number;
	/*buf->f_fsid.val[1];*/
#endif
	buf->f_namelen = TUX_NAME_LEN;
//	buf->f_frsize = sbi->blocksize;

	return 0;
}

static const struct super_operations tux3_super_ops = {
	.alloc_inode	= tux3_alloc_inode,
	.destroy_inode	= tux3_destroy_inode,
	.dirty_inode	= tux3_dirty_inode,
	.evict_inode	= tux3_evict_inode,
	/* FIXME: we have to handle write_inode of sync (e.g. cache pressure) */
//	.write_inode	= tux3_write_inode,
#ifndef ATOMIC
	.write_super	= tux3_write_super,
#endif
	.sync_fs	= tux3_sync_fs,
	.put_super	= tux3_put_super,
	.statfs		= tux3_statfs,
};

static int tux3_fill_super(struct super_block *sb, void *data, int silent)
{
	struct sb *sbi;
	struct replay *rp = NULL;
	int err, blocksize;

	sbi = kzalloc(sizeof(struct sb), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sbi->vfs_sb = sb;
	sb->s_fs_info = sbi;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = TUX3_SUPER_MAGIC;
	sb->s_op = &tux3_super_ops;
	sb->s_time_gran = 1;

	err = setup_bdi(sb);
	if (err) {
		printk(KERN_ERR "TUX3: unable to setup bdi\n");
		goto error_free;
	}

	err = -EIO;
	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to set blocksize\n");
		goto error_bdi;
	}

	/* Initialize and load sbi */
	if ((err = load_sb(sbi))) {
		if (!silent) {
			if (err == -EINVAL)
				warn("invalid superblock [%Lx]",
				     be64_to_cpup((__be64 *)sbi->super.magic));
			else
				warn("Unable to read superblock");
		}
		goto error;
	}

	if (sbi->blocksize != blocksize) {
		if (!sb_set_blocksize(sb, sbi->blocksize)) {
			printk(KERN_ERR "TUX3: blocksize too small for device.\n");
			goto error;
		}
	}
	warn("s_blocksize %lu", sb->s_blocksize);

	rp = tux3_init_fs(sbi);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}

	err = replay_stage3(rp, 1);
	if (err) {
		rp = NULL;
		goto error;
	}

	sb->s_root = d_make_root(sbi->rootdir);
	sbi->rootdir = NULL;	/* vfs takes care rootdir inode */
	if (!sb->s_root) {
		err = -ENOMEM;
		goto error;
	}

	return 0;

error:
	if (!IS_ERR_OR_NULL(rp))
		replay_stage3(rp, 0);
	__tux3_put_super(sbi);
error_bdi:
	cleanup_bdi(sb);
error_free:
	kfree(sbi);

	return err;
}

static struct dentry *tux3_mount(struct file_system_type *fs_type, int flags,
	const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, tux3_fill_super);
}

static struct file_system_type tux3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tux3",
	.fs_flags	= FS_REQUIRES_DEV,
	.mount		= tux3_mount,
	.kill_sb	= kill_block_super,
};

static int __init init_tux3(void)
{
	int err = tux3_init_inodecache();
	if (err)
		return err;
	return register_filesystem(&tux3_fs_type);
}

static void __exit exit_tux3(void)
{
	unregister_filesystem(&tux3_fs_type);
	tux3_destroy_inodecache();
}

module_init(init_tux3);
module_exit(exit_tux3);
MODULE_LICENSE("GPL");
#endif /* !__KERNEL__ */
