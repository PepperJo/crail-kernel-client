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

#ifndef DARPC_H_
#define DARPC_H_

#include <linux/completion.h>
#include "ida_fixed.h"

struct sockaddr_in;

struct darpc_request {
	__be32 ticket;
	void *data[0];
} __attribute__((packed));

struct darpc_response {
	__be32 ticket;
	void *data[0];
} __attribute__((packed));

struct darpc_rpc {
	struct completion completion;
	int status;
	struct darpc_response *response;
};

typedef void (*darpc_response_error_cb)(struct darpc_response *response,
		void *data);

struct darpc_client {
	struct rdma_client *rdma;

	struct darpc_rpc *rpc;

	struct ida_fixed ida;

	darpc_response_error_cb response_error;
	void *data;
};

struct darpc_client *darpc_client_create(u32 queue_depth,
		darpc_response_error_cb response_error, void *data);
void darpc_client_destroy(struct darpc_client *darpcc);

int darpc_client_connect(struct darpc_client *darpcc,
		struct sockaddr_in *addr);

int darpc_client_post_response(struct darpc_client *darpc,
		struct darpc_response *response, dma_addr_t dma_addr,
		unsigned long data_size);
struct darpc_rpc *darpc_client_perform_rpc(struct darpc_client *darpc,
		struct darpc_request *request, dma_addr_t dma_addr,
		unsigned long data_size);
void darpc_client_rpc_done(struct darpc_client *darpc,
		struct darpc_rpc *rpc);

#endif /* DARPC_H_ */
