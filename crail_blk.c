/*
 * Crail Kernel Client
 *
 * Author: Jonas Pfefferle <jpf@zurich.ibm.com>
 *
 * Copyright (C) 2015, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include "crail_client.h"
#include "crail_debug.h"

#include "crail_blk.h"

#define CRAILBLK_NAME "crail_disk"

#define CRAILBLK_BLOCK_SIZE 512

struct crail_blk {
	struct crail_file *file;

	struct request_queue *queue;

	struct gendisk *gd;
};


static int crail_blk_open(struct block_device *bdev, fmode_t mode)
{
	dprint(DBG_BLK, "\n");

	/* TODO: do we want to get the file here? anything else to do? */

	return 0;
}

static void crail_blk_release(struct gendisk *disk, fmode_t mode)
{
	dprint(DBG_BLK, "\n");
}

static const struct block_device_operations crail_blk_ops = {
	.owner = THIS_MODULE,
	.open = crail_blk_open,
	.release = crail_blk_release,
};

static void complete_mq_req(void *data, int status)
{
	struct request *req = data;
	if (req) {
		blk_mq_end_io(req, status);
	} else {
		dprint(DBG_ON, "io_cb NULL!?\n");
	}
}

/* we get max of 32K (8*PAGE_SIZE) contiguous buffers */
#define CRAIL_BLK_SEG_MAX 32

static int crail_blk_queue_rq(struct blk_mq_hw_ctx *hctx,
		struct request *req)
{
	struct bio_vec *bv;
	struct req_iterator req_iter;
	struct crail_io_callback *io_cb = req->special;
	struct crail_blk *crail_blk = hctx->queue->queuedata;
	void *base;
	unsigned long size;
	unsigned long offset;
	u32 i;
	int ret;

	dprint(DBG_BLK, "\n");

	base = bio_data(req->bio);
	size = 0;
	offset = blk_rq_pos(req) << 9;
	i = 0;

	BUG_ON(req->nr_phys_segments > CRAIL_BLK_SEG_MAX);

	if (unlikely(req->cmd_type != REQ_TYPE_FS || !base)) {
		dprint(DBG_ON, "no fs type request or null base\n");
		blk_mq_end_io(req, -EIO);
	} else {
        crail_begin_transaction(crail_blk->file, io_cb);
		rq_for_each_segment(bv, req, req_iter) {
			void *new_base;
			new_base = page_address(bv->bv_page) + bv->bv_offset;
			if (new_base != base + size) {
				dprint(DBG_BLK, "end of contiguous request\n");

				if (rq_data_dir(req) == READ) {
					ret = crail_file_read_async(crail_blk->file, offset, base,
							size, io_cb);
				} else {
					ret = crail_file_write_async(crail_blk->file, offset, base,
							size, io_cb);
				}

				if (ret < 0) {
					dprint(DBG_ON, "error on read/write\n");
					return BLK_MQ_RQ_QUEUE_ERROR;
				}

				offset += size;
				base = new_base;
				size = 0;
				i++;
			}

			size += bv->bv_len;
		}

		/* handle the last segment */
		io_cb->func = complete_mq_req;
		io_cb->data = req;
		if (rq_data_dir(req) == READ) {
			ret = crail_file_read_async(crail_blk->file, offset, base,
					size, io_cb);
		} else {
			ret = crail_file_write_async(crail_blk->file, offset, base,
					size, io_cb);
		}
        crail_end_transaction(io_cb);

		if (ret < 0) {
			dprint(DBG_ON, "error on read/write\n");
			return BLK_MQ_RQ_QUEUE_ERROR;
		}
	}

	return BLK_MQ_RQ_QUEUE_OK;
}

static int major = 0;


static struct blk_mq_ops crail_blk_mq_ops = {
		.queue_rq       = crail_blk_queue_rq,
		.map_queue      = blk_mq_map_queue,
		.alloc_hctx     = blk_mq_alloc_single_hw_queue,
		.free_hctx      = blk_mq_free_single_hw_queue,
};

static struct blk_mq_reg crail_blk_mq_reg = {
		.ops            = &crail_blk_mq_ops,
		.nr_hw_queues   = 1,
		.queue_depth    = 128, /* this should be more than sufficient */
		.numa_node      = NUMA_NO_NODE,
		.flags          = BLK_MQ_F_SHOULD_MERGE,
		.cmd_size		= sizeof(struct crail_io_callback),
};

struct crail_blk *crail_blk_disk_create(struct crail_file *file)
{
	int ret;
	struct crail_blk *crail_blk;
	struct gendisk *disk;

	dprint(DBG_BLK, "\n");

	BUG_ON(major <= 0);

	crail_blk = kzalloc(sizeof(*crail_blk), GFP_KERNEL);
	if (!crail_blk) {
		dprint(DBG_ON, "could not allocate rb\n");
		ret = -ENOMEM;
		goto fail;
	}
	crail_blk->file = file;

	crail_blk->queue = blk_mq_init_queue(&crail_blk_mq_reg, crail_blk);
	if (!crail_blk->queue) {
		dprint(DBG_ON, "coult not init queue\n");
		ret = -EFAULT;
		goto fail_rb;
	}

	crail_blk->queue->queuedata = crail_blk;
    queue_flag_set_unlocked(QUEUE_FLAG_NONROT, crail_blk->queue);
	blk_queue_logical_block_size(crail_blk->queue, CRAILBLK_BLOCK_SIZE);
	blk_queue_max_segments(crail_blk->queue, CRAIL_BLK_SEG_MAX);
	blk_queue_max_hw_sectors(crail_blk->queue, ~0U);
	blk_queue_max_segment_size(crail_blk->queue, ~0U);

	disk = alloc_disk(10);
	if (!disk) {
		dprint(DBG_ON, "alloc disk failed!\n");
		ret = -EFAULT;
		goto fail_queue;
	}
	disk->major = major;
	disk->first_minor = 1;
	disk->fops = &crail_blk_ops;
	disk->private_data = crail_blk;
	disk->queue = crail_blk->queue;
	snprintf(disk->disk_name, sizeof(disk->disk_name), "crail_blk%d", 0);
	/* capacity is in number of sectors! (FIXME: round up!) */
	set_capacity(disk, crail_file_size(file)/CRAILBLK_BLOCK_SIZE);
	add_disk(disk);


	crail_blk->gd = disk;

	return crail_blk;
fail_queue:
	blk_cleanup_queue(crail_blk->queue);
fail_rb:
	kfree(crail_blk);
fail:
	return ERR_PTR(ret);
}

void crail_blk_disk_destroy(struct crail_blk *crail_blk)
{

	dprint(DBG_BLK, "\n");

	del_gendisk(crail_blk->gd);
	blk_cleanup_queue(crail_blk->queue);
	put_disk(crail_blk->gd);

	kfree(crail_blk);
}

int crail_blk_init(void)
{

	dprint(DBG_BLK, "\n");

	major = register_blkdev(0, CRAILBLK_NAME);
	if (major <= 0) {
		dprint(DBG_ON, "could not register block device!\n");
		return -EBUSY;
	}

	return 0;
}

void crail_blk_exit(void)
{

	dprint(DBG_BLK, "\n");

	if (major > 0) {
		unregister_blkdev(major, CRAILBLK_NAME);
	}
}
