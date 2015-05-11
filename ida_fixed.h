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

#ifndef IDA_FIXED_H_
#define IDA_FIXED_H_

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/slab.h>

struct ida_fixed {
	unsigned long last_alloc;
	unsigned long *data;
	unsigned long bits;
};

static inline int ida_fixed_init(struct ida_fixed *ida,
		unsigned long size)
{
	ida->data = kzalloc(BITS_TO_LONGS(size) * sizeof(unsigned long),
			GFP_KERNEL);
	if (!ida->data) {
		return -ENOMEM;
	}
	ida->last_alloc = 0;
	ida->bits = size;
	return 0;
}

static inline void ida_fixed_destroy(struct ida_fixed *ida)
{
	kfree(ida->data);
}

static inline unsigned long ida_fixed_alloc(struct ida_fixed *ida)
{
	unsigned long idx;

	/* this implements find next */
	do {
		unsigned long last_alloc = ida->last_alloc;
		if ((idx = find_next_zero_bit(ida->data, ida->bits, last_alloc)) ==
				ida->bits) {
			/* we did not find anything -> start at beginning */
			idx = find_first_zero_bit(ida->data, last_alloc);
			if (idx == last_alloc) {
				return ida->bits;
			}
		}

		/* this is only a hint so we don't care that it is not atomic */
		ida->last_alloc = idx;
	} while (test_and_set_bit(idx, ida->data));

	return idx;
}

static inline bool ida_fixed_valid(struct ida_fixed *ida,
		unsigned long idx)
{
	return idx < ida->bits;
}

static inline void ida_fixed_free(struct ida_fixed *ida,
		unsigned long idx)
{
	clear_bit(idx, ida->data);
}

#endif /* IDA_FIXED_H_ */
