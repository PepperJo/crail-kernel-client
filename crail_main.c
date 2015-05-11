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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/atomic.h>

#include <rdma/rdma_cm.h>

#include "darpc.h"
#include "crail_client.h"
#include "crail_debug.h"
#include "crail_blk.h"

static struct crail_file *file = NULL;
static struct crail_client *crail = NULL;
static struct crail_blk *blk = NULL;

//struct {
//	volatile unsigned long counter;
//	char *buf;
//	int stop;
//} bench;
//
//void callback(void *data);
//
//struct crail_io_callback cb = {
//		.function = callback,
//};
//
//void callback(void *data)
//{
//	ssize_t read;
//	if (!bench.stop) {
//		read = crail_file_read_async(file, 0, bench.buf, 512, &cb);
//		if (read < 0) {
//			dprint(DBG_ON, "read file failed!\n");
//		}
//		bench.counter++;
//	}
//}

static int start(void)
{
	struct sockaddr_in addr;
	char ip[4] = { 10, 3, 15, 17 };
	char *buf;
	unsigned long offset;
	u32 i;
//	struct timespec start, end;
//	unsigned long cc;
	int ret;

	dprint(DBG_ON, "\n");

	/* 128MB block size */
	crail = crail_client_create(27, 40);
	if (IS_ERR(crail)) {
		dprint(DBG_ON, "could not create client!\n");
		ret = PTR_ERR(crail);
		goto fail;
	}

	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr.s_addr, ip, sizeof(ip));
	addr.sin_port = cpu_to_be16(9000);

	ret = crail_client_connect(crail, &addr);
	if (ret) {
		dprint(DBG_ON, "could not connect\n");
		goto fail_crail;
	}

    file = crail_file_open(crail, "test1", CRAIL_FILE_RW);
    if (IS_ERR(file)) {
        file = crail_file_create(crail, "test1");
        if (IS_ERR(file)) {
            dprint(DBG_ON, "could not create file\n");
            ret = PTR_ERR(file);
            goto fail_crail;
        }

#define BUF_SHIFT 10
#define BUF_SIZE ((1<<BUF_SHIFT) * PAGE_SIZE) /* 128MB */
        buf = (void *)__get_free_pages(GFP_DMA, BUF_SHIFT);
        if (!buf) {
            dprint(DBG_ON, "could not allocate buf\n");
            ret = -ENOMEM;
            goto fail_file;
        }

#define DISK_CAP (60ULL * 1000 * 1000 * 1000) /* 5GB */
        for (i = 0, offset = 0; i < DISK_CAP/BUF_SIZE + 1; i++) {
            ssize_t written;
            written = crail_file_write(file, offset, buf, BUF_SIZE);
            if (written < 0) {
                dprint(DBG_ON, "write file failed!\n");
                goto fail_file;
            }
            offset += BUF_SIZE;
        }
        free_pages((unsigned long)buf, BUF_SHIFT);
    }

	blk = crail_blk_disk_create(file);
	if (IS_ERR(blk)) {
		dprint(DBG_ON, "blk error!\n");
		ret = PTR_ERR(blk);
		goto fail_file;
	}

	return 0;
fail_file:
	crail_file_close(file);
	file = NULL;
fail_crail:
	crail_client_destroy(crail);
	crail = NULL;
fail:
	return ret;
}

static void end(void)
{
	dprint(DBG_ON, "\n");


	if (blk) {
		crail_blk_disk_destroy(blk);
	}

	if (file) {
		crail_file_close(file);
	}

	if (crail) {
		crail_client_destroy(crail);
	}
}

static int __init init(void)
{
	dprint(DBG_ON, "\n");
	crail_client_init();
	crail_blk_init();
	return start();
}

static void __exit fini(void)
{
	dprint(DBG_ON, "\n");
	end();
	crail_blk_exit();
	crail_client_exit();
}
module_init(init);
module_exit(fini);

MODULE_DESCRIPTION("crail_client");
MODULE_LICENSE("GPL");
