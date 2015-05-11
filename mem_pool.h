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

#ifndef MEM_POOL_H_
#define MEM_POOL_H_

#include <linux/slab.h>
#include <linux/kernel.h>

#include "ida_fixed.h"

/* Note there are a few reasons why we do not use kmem_cache:
 * 	1. we do know the number of max allocations at all time
 * 	2. we need access to the memory which holds the data to dma map it */

struct mem_pool {
	struct ida_fixed ida;
	void *data;
	unsigned long obj_size;
	unsigned long count;
};

static inline int mem_pool_init(struct mem_pool *mem_pool,
		unsigned long obj_size, unsigned long count, unsigned long align)
{
	int ret;

	ret = ida_fixed_init(&mem_pool->ida, count);
	if (ret) {
		return ret;
	}

	mem_pool->obj_size = ALIGN(obj_size, align);
	mem_pool->data = kmalloc(mem_pool->obj_size * count, GFP_KERNEL);
	if (!mem_pool->data) {
		ida_fixed_destroy(&mem_pool->ida);
		return -ENOMEM;
	}

	return 0;
}

static inline void mem_pool_destroy(struct mem_pool *mem_pool)
{
	kfree(mem_pool->data);
}

static void *mem_pool_alloc(struct mem_pool *mem_pool, unsigned long *idx)
{
	*idx = ida_fixed_alloc(&mem_pool->ida);
	if (!ida_fixed_valid(&mem_pool->ida, *idx)) {
		return NULL;
	}

	return mem_pool->data + mem_pool->obj_size * *idx;
}

static void mem_pool_free(struct mem_pool *mem_pool, void *data)
{
	unsigned long idx;

	if (data < mem_pool->data ||
			(data - mem_pool->data) % mem_pool->obj_size) {
		return;
	}

	idx = (data - mem_pool->data) / mem_pool->obj_size;

	if (ida_fixed_valid(&mem_pool->ida, idx)) {
		ida_fixed_free(&mem_pool->ida, idx);
	}
}

#endif /* MEM_POOL_H_ */
