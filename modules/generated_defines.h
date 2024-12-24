
	static inline int cas_add_disk(struct gendisk *gd)
	{
		add_disk(gd);
		return 0;
	}

    static inline bool cas_bdev_exist(const char *path)
    {
        struct block_device *bdev;

        bdev = lookup_bdev(path);
        if (IS_ERR(bdev))
            return false;
        bdput(bdev);
        return true;
    }

    static inline bool cas_bdev_match(const char *path, struct block_device *bd)
    {
        struct block_device *bdev;
        bool match = false;

        bdev = lookup_bdev(path);
        if (IS_ERR(bdev))
            return false;
        match = (bdev == bd);
        bdput(bdev);
        return match;
    }
#define cas_bdev_nr_sectors(bd) \
            (bd->bd_part->nr_sects)
typedef struct block_device *cas_bdev_handle_t;
#define cas_bdev_open_by_path(path, mode, holder) \
			blkdev_get_by_path(path, mode, holder)
#define cas_bdev_get_from_handle(handle) \
			((struct block_device *)handle)
#define cas_bdev_release(handle, mode, holder) \
			blkdev_put((struct block_device *)handle, mode)
#define cas_bdev_whole(bd) \
            (bd->bd_contains)

	static inline int cas_bd_get_next_part(struct block_device *bd)
	{
		int part_no = 0;
		struct gendisk *disk = bd->bd_disk;
		struct disk_part_iter piter;
		struct hd_struct *part;

		mutex_lock(&bd->bd_mutex);

		disk_part_iter_init(&piter, disk, DISK_PITER_INCL_EMPTY);
		while ((part = disk_part_iter_next(&piter))) {
			part_no = part->partno;
			break;
		}
		disk_part_iter_exit(&piter);

		mutex_unlock(&bd->bd_mutex);

		return part_no;
	}

	static inline int cas_blk_get_part_count(struct block_device *bdev)
	{
		struct disk_part_tbl *ptbl;
		int i, count = 0;

		rcu_read_lock();
		ptbl = rcu_dereference(bdev->bd_disk->part_tbl);
		for (i = 0; i < ptbl->len; ++i) {
			if (rcu_access_pointer(ptbl->part[i]))
				count++;
		}
		rcu_read_unlock();

		return count;
	}
static inline struct bio *cas_bio_alloc(struct block_device *bdev, gfp_t gfp_mask, unsigned short num_vecs)
		{
			(void)bdev;
			return bio_alloc(gfp_mask, num_vecs);
		}
#define CAS_BIO_SET_DEV(bio, bdev) \
            bio->bi_bdev = bdev
#define CAS_BIO_GET_DEV(bio) \
            bio->bi_bdev->bd_disk
#define CAS_IS_DISCARD(bio) \
			((CAS_BIO_OP_FLAGS(bio)) & REQ_OP_DISCARD)
#define CAS_BIO_DISCARD \
			((REQ_OP_WRITE | REQ_OP_DISCARD))
#define CAS_BIO_OP_FLAGS_FORMAT "0x%016lX"
#define CAS_BIO_OP_FLAGS(bio) \
			(bio)->bi_rw
#define CAS_BIO_GET_GENDISK(bio) (bio->bi_bdev->bd_disk)
#define CAS_BIO_BISIZE(bio) \
			bio->bi_size
#define CAS_BIO_BISECTOR(bio) \
			bio->bi_sector
#define CAS_BIO_MAX_VECS ((uint32_t)BIO_MAX_PAGES)

    static inline struct bio *cas_bio_split(struct bio *bio, int sectors)
    {
        struct bio *split, copy;
        int bytes = sectors << 9;
        uint32_t idx, vecs = 0;
        int ret;

        copy = *bio;
        copy.bi_io_vec = &copy.bi_io_vec[copy.bi_idx];
        copy.bi_vcnt -= copy.bi_idx;
        copy.bi_idx = 0;

        BUG_ON(bytes >= bio->bi_size);

        // For simplicity we assume that split is alligned.
        // Otherwise bvec modification would be required.
        while (bytes) {
            if (bytes >= bio_iovec_idx(&copy, vecs)->bv_len) {
                bytes -= bio_iovec_idx(&copy, vecs)->bv_len;
                vecs++;
            } else {
                vecs++;
                break;
            }
        }

        split = bio_alloc_bioset(GFP_NOIO, vecs, NULL);
        if (!split)
            return NULL;

        copy.bi_max_vecs = vecs;
        __bio_clone(split, &copy);
        split->bi_size = sectors << 9;
        split->bi_vcnt = vecs;

        if (bio_integrity((&copy))) {
            ret = bio_integrity_clone(split, bio, GFP_NOIO);
            if (ret < 0) {
                bio_put(split);
                return NULL;
            }
            for (idx = 0, bytes = 0; idx < bio->bi_idx; idx++)
                bytes += bio_iovec_idx(bio, idx)->bv_len;
            bio_integrity_trim(split, bytes >> 9, sectors);
        }

        bio_advance(bio, split->bi_size);

        return split;
    }
#define CAS_SEGMENT_BVEC(vec) \
			(vec)
#define cas_blk_queue_exit(q) 
#define CAS_BLK_STATUS_T int
#define CAS_BLK_STS_NOTSUPP -ENOTSUPP
#define CAS_BLKDEV_DEFAULT_RQ (BLKDEV_MAX_RQ)
#define CAS_BLK_MODE fmode_t
#define CAS_BLK_MODE_READ FMODE_READ
#define CAS_BLK_MODE_WRITE FMODE_WRITE
#define CAS_BLK_MODE_EXCL FMODE_EXCL
#define _CAS_GENHD_FLAGS (GENHD_FL_NO_PART_SCAN | GENHD_FL_EXT_DEVT)
#define cas_class_create(owner, name) \
			class_create(owner, name)

	static inline void cas_cleanup_disk(struct gendisk *gd)
	{
		put_disk(gd);
	}

        static inline void cas_cleanup_queue(struct request_queue *q)
        {
		blk_cleanup_queue(q);
	}
#define CAS_COMPLETE_AND_EXIT(compl, code) complete_and_exit(compl, code)
#define CAS_DAEMONIZE(name, arg...) \
			do { } while (0)
#define CAS_ALIAS_NODE_TO_DENTRY(alias) \
			container_of(alias, struct dentry, d_alias)
#define CAS_SET_DISCARD_ZEROES_DATA(queue_limits, val) \
			queue_limits.discard_zeroes_data = val
#define CAS_ERRNO_TO_BLK_STS(status) status
#define CAS_IS_SET_FLUSH(flags) \
            ((flags) & REQ_FLUSH)
#define CAS_SET_FLUSH(flags) \
            ((flags) | REQ_FLUSH)
#define CAS_CLEAR_FLUSH(flags) \
            ((flags) & ~REQ_FLUSH)
#define GET_DISK_MAX_PARTS(x) disk_max_parts(x)

        static inline unsigned long cas_get_free_memory(void)
        {
            return si_mem_available() << PAGE_SHIFT;
        }

        static inline int cas_has_discard_support(struct block_device *bd)
        {
		struct request_queue *q = bdev_get_queue(bd);
		return (int)blk_queue_discard(q);
	}
#define CAS_ALIAS_NODE_TYPE \
			struct hlist_node
#define CAS_DENTRY_LIST_EMPTY(head) \
			hlist_empty(head)
#define CAS_INODE_FOR_EACH_DENTRY(pos, head) \
			hlist_for_each(pos, head)
#define CAS_FILE_INODE(file) \
			file->f_inode
#define CAS_KRETURN(_x) return 
#define CAS_MAKE_REQ_RET_TYPE void 

        static inline void cas_blk_queue_make_request(struct request_queue *q,
                make_request_fn *mfn)
        {
            blk_queue_make_request(q, mfn);
        }
#define MODULE_MUTEX_SUPPORTED 1
#define CAS_MODULE_PUT_AND_EXIT(code) module_put_and_exit(code)
#define CAS_BLK_MQ_F_STACKING 0
#define CAS_BLK_MQ_F_BLOCKING \
            BLK_MQ_F_BLOCKING

#include <uapi/asm-generic/mman-common.h>
#include <uapi/linux/mman.h>
	static inline unsigned long cas_vm_mmap(struct file *file,
			unsigned long addr, unsigned long len)
	{
		return vm_mmap(file, addr, len, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, 0);
	}

	static inline int cas_vm_munmap(unsigned long start, size_t len)
	{
		return vm_munmap(start, len);
	}
#define CAS_SET_QUEUE_CHUNK_SECTORS(queue, chunk_size) \
			queue->limits.chunk_sectors = chunk_size
#define CAS_QUEUE_FLAG_SET(flag, request_queue) \
			queue_flag_set(flag, request_queue)

	static inline void cas_copy_queue_limits(struct request_queue *exp_q,
			struct queue_limits *cache_q_limits, struct request_queue *core_q)
	{
		struct queue_limits_aux *l_aux = exp_q->limits.limits_aux;
		exp_q->limits = *cache_q_limits;
		exp_q->limits.limits_aux = l_aux;
		if (exp_q->limits.limits_aux && cache_q_limits->limits_aux)
			*exp_q->limits.limits_aux = *cache_q_limits->limits_aux;
		exp_q->limits.max_sectors = core_q->limits.max_sectors;
		exp_q->limits.max_hw_sectors = core_q->limits.max_hw_sectors;
		exp_q->limits.max_segments = core_q->limits.max_segments;
		exp_q->limits.max_write_same_sectors = 0;
	}

	static inline void cas_cache_set_no_merges_flag(struct request_queue *cache_q)
	{
		if (queue_virt_boundary(cache_q))
			queue_flag_set(QUEUE_FLAG_NOMERGES, cache_q);
	}

        static inline void cas_reread_partitions(struct block_device *bdev)
        {
            ioctl_by_bdev(bdev, BLKRRPART, (unsigned long)NULL);
        }
#define CAS_SET_SUBMIT_BIO(_fn)

	static inline void cas_submit_bio(int rw, struct bio *bio)
	{
			submit_bio(rw, bio);
	}
#define CAS_GET_CURRENT_TIME(timespec) ktime_get_real_ts64(timespec)

        static inline int cas_vfs_ioctl(struct file *file, unsigned int cmd,
                unsigned long arg)
        {
            int error = -ENOTTY;

            if (!file->f_op->unlocked_ioctl)
                goto out;

            error = file->f_op->unlocked_ioctl(file, cmd, arg);
            if (error == -ENOIOCTLCMD)
                error = -ENOTTY;
        out:
            return error;
        }

        static inline void *cas_vmalloc(unsigned long size, gfp_t gfp_mask)
        {
            return __vmalloc(size, gfp_mask, PAGE_KERNEL);
        }

        static inline int cas_alloc_mq_disk(struct gendisk **gd, struct request_queue **queue,
					    struct blk_mq_tag_set *tag_set)
        {
		*gd = alloc_disk(1);
		if (!(*gd))
			return -ENOMEM;

		*queue = blk_mq_init_queue(tag_set);
		if (IS_ERR_OR_NULL(*queue)) {
			put_disk(*gd);
			return -ENOMEM;
		}
		(*gd)->queue = *queue;

		return 0;
        }

	static inline void cas_cleanup_mq_disk(struct gendisk *gd)
	{
		blk_cleanup_queue(gd->queue);
		gd->queue = NULL;
		put_disk(gd);
	}
#define CAS_REFER_BDEV_CLOSE_CALLBACK(name) \
			name##_callback_wrapper
#define CAS_BDEV_CLOSE(name, DISK) \
			static void name##_callback(DISK); \
			static void name##_callback_wrapper(struct gendisk *gd, \
					CAS_BLK_MODE _mode) \
			{ \
				name##_callback(gd); \
			} \
			static void name##_callback(DISK)
#define CAS_REFER_BDEV_OPEN_CALLBACK(name) \
			name##_callback_wrapper
#define CAS_BDEV_OPEN(name, DISK) \
			static int name##_callback(DISK); \
			static int name##_callback_wrapper(struct block_device *bdev, \
					CAS_BLK_MODE _mode) \
			{ \
				return name##_callback(bdev->bd_disk); \
			} \
			static int name##_callback(DISK)
#define CAS_REFER_BLOCK_CALLBACK(name) \
				   name##_callback
#define CAS_BLOCK_CALLBACK_INIT(BIO) \
			{; }
#define CAS_BLOCK_CALLBACK_RETURN(BIO) \
			{ return; }
#define CAS_BIO_ENDIO(BIO, BYTES_DONE, ERROR) \
			bio_endio(BIO, ERROR)
#define CAS_DECLARE_BLOCK_CALLBACK(name, BIO, BYTES_DONE, ERROR) \
			static void name##_callback(BIO, ERROR)
#define CAS_BLOCK_CALLBACK_ERROR(BIO, ERROR) \
			ERROR

        static inline unsigned long long cas_generic_start_io_acct(
                struct bio *bio)
        {
            struct gendisk *gd = CAS_BIO_GET_DEV(bio);

            generic_start_io_acct(gd->queue, bio_data_dir(bio),
                    bio_sectors(bio), &gd->part0);
            return jiffies;
        }

        static inline void cas_generic_end_io_acct(
                struct bio *bio, unsigned long start_time)
        {
            struct gendisk *gd = CAS_BIO_GET_DEV(bio);

            generic_end_io_acct(gd->queue, bio_data_dir(bio),
                    &gd->part0, start_time);
        }
#define CAS_CHECK_QUEUE_FLUSH(q) \
			CAS_IS_SET_FLUSH((q)->flush_flags)
#define CAS_CHECK_QUEUE_FUA(q) \
			((q)->flush_flags & REQ_FUA)
static inline void cas_set_queue_flush_fua(struct request_queue *q,
				bool flush, bool fua)
	{
		unsigned int flags = 0;
		if (flush)
			flags = CAS_SET_FLUSH(flags);
		if (fua)
			flags |= REQ_FUA;
		if (flags)
			blk_queue_flush(q, flags);
	}

        static inline void cas_set_discard_flag(struct request_queue *q)
        {
		CAS_QUEUE_FLAG_SET(QUEUE_FLAG_DISCARD, q);
	}
