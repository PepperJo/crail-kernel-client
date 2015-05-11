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
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/spinlock.h>

#include "rdma.h"
#include "ida_fixed.h"

#include "darpc_debug.h"

#include "darpc.h"

static void darpc_comp_handler(struct rdma_client *rdma, struct ib_wc *wc,
		unsigned int entries)
{
	struct darpc_client *darpc = rdma->private_data;
	unsigned int i;

	dprint(DBG_CQ, "\n");

	for (i = 0; i < entries; i++) {
		switch(wc[i].opcode) {
		case IB_WC_SEND:
		{
			struct darpc_rpc *rpc = (struct darpc_rpc *)wc[i].wr_id;

			dprint(DBG_CQ, "send\n");

			if (unlikely(wc[i].status)) {
				dprint(DBG_ON, "send failed with: %d\n", wc[i].status);
				rpc->status = -EIO;
				complete(&rpc->completion);
			}
			break;
		}
		case IB_WC_RECV:
		{
			struct darpc_response *response =
					(struct darpc_response *)wc[i].wr_id;
			struct darpc_rpc *rpc;

			dprint(DBG_CQ, "recv\n");

			if (unlikely(wc[i].status)) {
				/* we need a timeout on the completion because we don't
				 * know to which rpc this failed response belongs to */
				dprint(DBG_ON, "recv failed with: %d\n", wc[i].status);
				darpc->response_error(response, darpc->data);
			} else {
				u32 ticket = be32_to_cpu(response->ticket);

				if (!ida_fixed_valid(&darpc->ida, ticket)) {
					dprint(DBG_ON, "invalid ticket!\n");
					darpc->response_error(response, darpc->data);
					break;
				}

				rpc = darpc->rpc + ticket;
				rpc->response = response;
				rpc->status = 0;
				complete(&rpc->completion);
			}
			break;
		}
		default:
			dprint(DBG_ON, "error!\n");
		}
	}
}

struct darpc_client *darpc_client_create(u32 queue_depth,
		darpc_response_error_cb response_error, void *data)
{
	struct darpc_client *darpc;
	struct ib_qp_cap cap;
	int ret;

	dprint(DBG_CLIENT, "\n");

	darpc = kmalloc(sizeof(*darpc), GFP_KERNEL);
	if (!darpc) {
		dprint(DBG_ON, "could not allocate darpc\n");
		ret = -ENOMEM;
		goto fail;
	}
	darpc->response_error = response_error;
	darpc->data = data;

	darpc->rpc = kmalloc(sizeof(*darpc->rpc) * queue_depth, GFP_KERNEL);
	if (!darpc->rpc) {
		dprint(DBG_ON, "could not allocate rpc buffer\n");
		ret = -ENOMEM;
		goto fail_darpcc;
	}

	ret = ida_fixed_init(&darpc->ida, queue_depth);
	if (ret) {
		dprint(DBG_ON, "could not alloc ida\n");
		goto fail_rpc;
	}

	cap.max_recv_sge = 1;
	cap.max_send_sge = 1;
	cap.max_inline_data = 0;
	cap.max_recv_wr = queue_depth;
	cap.max_send_wr = queue_depth;

	darpc->rdma = rdma_client_create(darpc_comp_handler, cap, queue_depth*2);
	if (IS_ERR(darpc->rdma)) {
		dprint(DBG_ON, "coult not create rdma client\n");
		ret = PTR_ERR(darpc->rdma);
		goto fail_ida;
	}
	darpc->rdma->private_data = darpc;

	return darpc;
fail_ida:
	ida_fixed_destroy(&darpc->ida);
fail_rpc:
	kfree(darpc->rpc);
fail_darpcc:
	kfree(darpc);
fail:
	return ERR_PTR(ret);
}

void darpc_client_destroy(struct darpc_client *darpc)
{

	dprint(DBG_CLIENT, "\n");

	rdma_client_destroy(darpc->rdma);
	ida_fixed_destroy(&darpc->ida);
	kfree(darpc->rpc);
	kfree(darpc);
}

int darpc_client_connect(struct darpc_client *darpcc,
		struct sockaddr_in *addr)
{
	struct rdma_client *rdma = darpcc->rdma;
	int ret;

	dprint(DBG_CLIENT, "\n");

	ret = rdma_client_connect(rdma, addr, 2000);

    /* rdma_client_begin_polling(rdma); */

	return ret;
}

/* response requires DMA from device */
int darpc_client_post_response(struct darpc_client *darpc,
		struct darpc_response *response, dma_addr_t dma_addr,
		unsigned long data_size)
{
	struct rdma_client *rdma = darpc->rdma;
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge sge;

	dprint(DBG_RPC, "\n");

	sge.addr = dma_addr;
	sge.length = sizeof(*response) + data_size;
	sge.lkey = rdma_client_lkey(rdma);

	wr.next = NULL;
	wr.wr_id = (unsigned long)response;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	return rdma_client_post_recv(rdma, &wr, &bad_wr);
}

/* caller must ensure that there are enough pre-posted responses
 * request requires DMA to device */
struct darpc_rpc *darpc_client_perform_rpc(struct darpc_client *darpc,
		struct darpc_request *request, dma_addr_t dma_addr,
		unsigned long data_size)
{
	struct rdma_client *rdma = darpc->rdma;
	unsigned long size;
	struct ib_send_wr wr, *bad_wr;
	struct ib_sge sge;
	u64 addr;
	struct darpc_rpc *rpc;
	unsigned long idx;
	int ret;

	dprint(DBG_RPC, "\n");

	idx = ida_fixed_alloc(&darpc->ida);
	if (!ida_fixed_valid(&darpc->ida, idx)) {
		dprint(DBG_ON, "could not allocate rpc!\n");
		ret = -ENOMEM;
		goto fail;
	}

	rpc = darpc->rpc + idx;
	init_completion(&rpc->completion);
	request->ticket = cpu_to_be32(idx);

	size =  sizeof(*request) + data_size;

	/* in theory we could send these unsignaled however
	 * unsignaled sends are outstanding until a signal send is
	 * performed... */
	if (size > rdma->qp_cap.max_inline_data) {
		dprint(DBG_RPC, "RPC does not fit in inline data (%lu > %u)", size,
				rdma->qp_cap.max_inline_data);
		addr = dma_addr;
		wr.send_flags = IB_SEND_SIGNALED;
	} else {
		addr = (u64)request;
		wr.send_flags = IB_SEND_INLINE | IB_SEND_SIGNALED;
	}

	sge.addr = addr;
	sge.length = size;
	sge.lkey = rdma_client_lkey(rdma);

	wr.wr_id = (u64)rpc;
	wr.next = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	ret = rdma_client_post_send(rdma, &wr, &bad_wr);
	if (ret) {
		goto fail_alloc;
	}
	return rpc;
fail_alloc:
	ida_fixed_free(&darpc->ida, idx);
fail:
	return ERR_PTR(ret);
}

void darpc_client_rpc_done(struct darpc_client *darpc,
		struct darpc_rpc *rpc)
{
	unsigned long idx;

	idx = rpc - darpc->rpc;
	if (ida_fixed_valid(&darpc->ida, idx)) {
		ida_fixed_free(&darpc->ida, idx);
	} else {
		dprint(DBG_ON, "invalid index!\n");
	}
}
