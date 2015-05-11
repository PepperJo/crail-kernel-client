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

#ifndef CRAIL_CLIENT_H_
#define CRAIL_CLIENT_H_

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dma-direction.h>
#include <linux/atomic.h>

struct sockaddr_in;

enum crail_file_mode {
	CRAIL_FILE_READ = 1,
	CRAIL_FILE_WRITE = 2,
	CRAIL_FILE_RW = CRAIL_FILE_READ | CRAIL_FILE_WRITE
};

struct crail_client;

#define CRAIL_MAX_PATH 256

struct crail_io_callback;

typedef void (*crail_callback_t)(void *, int);

struct crail_io_callback {
    unsigned long n_blk_ops;

    crail_callback_t func;
    void *data;

    struct crail_file *file;
    int status;

    u64 new_file_size;

    char __padding[16];
    atomic_long_t n_blk_ops_finished;
};

/* metadata ops */
struct crail_file *crail_file_create(struct crail_client *crail,
		const char *path);
struct crail_file *crail_file_open(struct crail_client *crail,
		const char *path, enum crail_file_mode mode);
int crail_file_close(struct crail_file *file);

unsigned long crail_file_size(struct crail_file *file);

ssize_t crail_file_read(struct crail_file *file, u64 offset, char *buf,
		unsigned long size);
ssize_t crail_file_write(struct crail_file *file, u64 offset,
		const char *buf, unsigned long size);

void crail_begin_transaction(struct crail_file *file,
        struct crail_io_callback *io_cb);

void crail_end_transaction(struct crail_io_callback *io_cb);

ssize_t crail_file_read_async(struct crail_file *file, u64 offset, char *buf,
		unsigned long size, struct crail_io_callback *callback);

ssize_t crail_file_write_async(struct crail_file *file, u64 offset,
		const char *buf, unsigned long size, struct crail_io_callback *callback);

/* client ops */
int crail_client_connect(struct crail_client *crail,
		struct sockaddr_in *addr);
struct crail_client *crail_client_create(u32 block_size, u32 queue_depth);
void crail_client_destroy(struct crail_client *crail);

int crail_client_init(void);
void crail_client_exit(void);

#endif /* CRAIL_CLIENT_H_ */
