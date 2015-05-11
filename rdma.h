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

#ifndef RDMA_H_
#define RDMA_H_

#include <linux/types.h>
#include <linux/dma-direction.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

struct rdma_client;

typedef void (*rdma_client_comp_handler)(struct rdma_client *c,
		struct ib_wc *, unsigned int entries);

struct rdma_client {
	struct rdma_cm_id *cm_id;
	struct ib_qp_cap qp_cap;
	struct completion cm_done;
	enum rdma_cm_event_type cm_state;

	struct ib_cq *cq;
	u32 cq_depth;
	rdma_client_comp_handler comp_handler;
	struct ib_pd *pd;
	struct ib_mr *dma_mr;
    struct ib_wc *wc;

	struct task_struct *poll_thread;
	volatile bool cq_polling;

	void *private_data;
};

int rdma_client_begin_polling(struct rdma_client *c);
void rdma_client_end_polling(struct rdma_client *c);

int rdma_client_connect(struct rdma_client *c,
		struct sockaddr_in *addr, u32 connection_timeout);
int rdma_client_disconnect(struct rdma_client *c);

struct rdma_client *rdma_client_create(
		rdma_client_comp_handler client_comp_handler, struct ib_qp_cap qp_cap,
		u32 cq_depth);
void rdma_client_destroy(struct rdma_client *c);

static inline int rdma_dma_map(struct rdma_client *c, dma_addr_t *dma_addr,
        void *data, unsigned long size, enum dma_data_direction dir)
{
	if (unlikely(c->cm_state != RDMA_CM_EVENT_ESTABLISHED)) {
		return -ENOTCONN;
	}
	*dma_addr = ib_dma_map_single(c->cm_id->device, data, size, dir);
	if (ib_dma_mapping_error(c->cm_id->device, *dma_addr)) {
		return -EFAULT;
	}
	return 0;
}

static inline void rdma_dma_unmap(struct rdma_client *c, dma_addr_t dma_addr,
		unsigned long size, enum dma_data_direction dir)
{
	ib_dma_unmap_single(c->cm_id->device, dma_addr, size, dir);
}

static inline int rdma_client_post_send(struct rdma_client *c,
        struct ib_send_wr *wr, struct ib_send_wr **bad_wr)
{
	if (unlikely(c->cm_state != RDMA_CM_EVENT_ESTABLISHED)) {
		return -ENOTCONN;
	}
	return ib_post_send(c->cm_id->qp, wr, bad_wr);
}

static inline int rdma_client_post_recv(struct rdma_client *c,
        struct ib_recv_wr *wr, struct ib_recv_wr **bad_wr)
{
	if (unlikely(c->cm_state != RDMA_CM_EVENT_ESTABLISHED)) {
		return -ENOTCONN;
	}
	return ib_post_recv(c->cm_id->qp, wr, bad_wr);
}

static inline u32 rdma_client_lkey(struct rdma_client *c)
{
    /* return c->cm_id->device->local_dma_lkey; */
	return c->dma_mr->lkey;
}

#endif /* RDMA_H_ */
