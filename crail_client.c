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

#include <linux/slab.h>
#include <linux/cache.h>
#include <linux/in.h>

#include "crail_debug.h"
#include "mem_pool.h"
#include "darpc.h"
#include "crail_rpc.h"
#include "rdma.h"

#include "crail_client.h"

static struct kmem_cache *block_cache;
static struct kmem_cache *block_wc_cache;

struct crail_client {
	struct darpc_client *darpc;
	struct kref ref_cnt;

	/* rpc store */
	dma_addr_t req_addr;
	struct mem_pool request_pool;
	dma_addr_t resp_addr;
	struct mem_pool response_pool;

	u32 block_shift;

	spinlock_t lock;
	struct list_head datanode;
};


struct crail_block_wc {
    struct crail_io_callback *io_cb;

    dma_addr_t addr;
    u32 size;
};

#define CRAIL_MAX_BLOCKS_PER_FILE 512

struct crail_file {
	struct crail_client *crail;
	struct crail_block **block_cache;

	struct crail_file *parent;
	u64 fd;
	u64 token;
	u64 size;
	u64 modification_time;
	bool dir;
	u64 dir_offset;

	void *private_data;
};

struct crail_block {
	struct crail_datanode_client *crail_data;
	u64 remote_addr;
	u32 rkey;
};

struct crail_datanode_client {
	struct rdma_client *rdma;
	struct sockaddr_in addr;

	struct list_head list;
};

static dma_addr_t crail_request_dma_addr(struct crail_client *crail,
		unsigned long idx)
{
	return crail->req_addr + crail->request_pool.obj_size * idx;
}

static dma_addr_t crail_response_dma_addr(struct crail_client *crail,
		unsigned long idx)
{
	return crail->resp_addr + crail->response_pool.obj_size * idx;
}

static int crail_post_response(struct crail_client *crail)
{
	struct darpc_response *dresp;
	unsigned long idx;

	int ret;
	dresp = mem_pool_alloc(&crail->response_pool, &idx);
	if (!dresp) {
		dprint(DBG_ON, "could not alloc response\n");
		return -ENOMEM;
	}

	ret = darpc_client_post_response(crail->darpc, dresp,
			crail_response_dma_addr(crail, idx), CRAIL_MAX_RESPONSE_SIZE);
	if (ret) {
		dprint(DBG_ON, "could not post response!\n");
		mem_pool_free(&crail->response_pool, dresp);
		return ret;
	}

	return 0;
}

static void datanode_destroy(struct crail_datanode_client *crail_data)
{
	dprint(DBG_DATA, "\n");

	rdma_client_destroy(crail_data->rdma);
	kfree(crail_data);
}

static void client_destroy(struct kref *ref_cnt)
{
	struct crail_client *crail = container_of(ref_cnt, struct crail_client,
			ref_cnt);
	struct crail_datanode_client *crail_data, *tmp;

	dprint(DBG_CLIENT, "\n");

	spin_lock(&crail->lock);
	list_for_each_entry_safe(crail_data, tmp, &crail->datanode, list) {
		datanode_destroy(crail_data);
	}
	spin_unlock(&crail->lock);

    if (crail->req_addr) {
        rdma_dma_unmap(crail->darpc->rdma, crail->req_addr,
                crail->request_pool.obj_size * crail->request_pool.count,
                DMA_TO_DEVICE);
    }

    if (crail->resp_addr) {
        rdma_dma_unmap(crail->darpc->rdma, crail->resp_addr,
                crail->response_pool.obj_size * crail->response_pool.count,
                DMA_FROM_DEVICE);
    }

	darpc_client_destroy(crail->darpc);

	mem_pool_destroy(&crail->request_pool);
	mem_pool_destroy(&crail->response_pool);
	kfree(crail);
}

/* ------------ Metadata operations ----------------- */
/* 		(for now these operations are all sync) 	  */

static struct crail_file *file_from_file_info(struct crail_client *crail,
		const struct crail_rpc_file_info *file_info)
{
	int ret;
	struct crail_file *file;

	file = kmalloc(sizeof(*file), GFP_KERNEL);
	if (!file) {
		dprint(DBG_ON, "could not allocate file!\n");
		ret = -ENOMEM;
		goto fail;
	}
	kref_get(&crail->ref_cnt);
	file->crail = crail;
	file->block_cache = kzalloc(
			sizeof(*file->block_cache) * CRAIL_MAX_BLOCKS_PER_FILE, GFP_KERNEL);
	if (!file->block_cache) {
		dprint(DBG_ON, "could not allocate block cache\n");
		ret = -ENOMEM;
		goto fail_file;
	}

	file->fd = be64_to_cpu(file_info->fd);
	file->size = be64_to_cpu(file_info->capacity);
	file->dir = be32_to_cpu(file_info->dir);
	file->dir_offset = be64_to_cpu(file_info->dir_offset);
	file->modification_time = be64_to_cpu(file_info->modification_time);
	file->token = be64_to_cpu(file_info->token);

	file->private_data = NULL;
	file->parent = NULL;

	dprint(DBG_META, "file_info: fd = %llu, size = %llu\n", file->fd,
			file->size);

	return file;
fail_file:
	kfree(file);
fail:
	return ERR_PTR(ret);
}

static struct crail_file *file_alloc(struct crail_client *crail,
		struct crail_rpc_response_file *resp)
{
	struct crail_file *file;
	int ret;

	if (be16_to_cpu(resp->hdr.error) != CRAIL_ERR_OK) {
		dprint(DBG_ON, "file error!\n");
		ret = -EFAULT;
		goto fail;
	}

	file = file_from_file_info(crail, &resp->file_info);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto fail;
	}

	file->parent = file_from_file_info(crail, &resp->parent_info);
	if (IS_ERR(file->parent)) {
		ret = PTR_ERR(file);
		goto fail_file;
	}

	return file;
fail_file:
	kfree(file);
fail:
	return ERR_PTR(ret);
}

static void file_free(struct crail_file *file)
{
	kref_put(&file->crail->ref_cnt, &client_destroy);
	if (file->parent) {
		file_free(file->parent);
	}
	kfree(file);
}

static void path_to_file_name(struct crail_rpc_file_name *name,
		const char *path)
{
	name->length = cpu_to_be32(2);
	memset(name->components, 0, sizeof(name->components));
    /* name->components[0] is root */
	name->components[1] =
			cpu_to_be32(full_name_hash(path, strnlen(path, CRAIL_MAX_PATH)));
}

struct crail_file *crail_file_create(struct crail_client *crail,
		const char *path)
{
	struct darpc_request *dreq;
	struct darpc_rpc *rpc;
	struct crail_rpc_request_create_file *req;
	struct crail_rpc_response_file *resp;
	struct crail_file *file;
	unsigned long idx;
	int ret;

	dprint(DBG_META, "\n");

	ret = crail_post_response(crail);
	if (ret) {
		dprint(DBG_ON, "post response failed!\n");
		goto fail;
	}

	dreq = mem_pool_alloc(&crail->request_pool, &idx);
	if (!dreq) {
		dprint(DBG_ON, "could not alloc request\n");
		ret = -ENOMEM;
		goto fail;
	}

	req = (struct crail_rpc_request_create_file *)&dreq->data;
	req->hdr.cmd = cpu_to_be16(CRAIL_RPC_CREATE_FILE);
	req->hdr.type = cpu_to_be16(CRAIL_RPC_CREATE_FILE);
	req->name.length = cpu_to_be32(1);
	path_to_file_name(&req->name, path);
	req->dir = cpu_to_be32(0);
	req->overwriteable = cpu_to_be32(1);
	req->writeable = cpu_to_be32(1);

	rpc = darpc_client_perform_rpc(crail->darpc, dreq,
			crail_request_dma_addr(crail, idx), sizeof(*req));
	if (IS_ERR(rpc)) {
		dprint(DBG_ON, "request failed!\n");
		ret = PTR_ERR(rpc);
		goto fail_req;
	}

	ret = wait_for_completion_interruptible(&rpc->completion);
	if (ret) {
		dprint(DBG_ON, "interrupted\n");
		/* FIXME: free RPC!!!! */
		goto fail;
	}

	mem_pool_free(&crail->request_pool, dreq);

	resp = (struct crail_rpc_response_file *)&rpc->response->data;
	file = file_alloc(crail, resp);
	mem_pool_free(&crail->response_pool, rpc->response);
	darpc_client_rpc_done(crail->darpc, rpc);
	if (IS_ERR(file)) {
		dprint(DBG_ON, "create file failed!\n");
		ret = PTR_ERR(file);
		goto fail;
	}

	return file;
fail_req:
	mem_pool_free(&crail->request_pool, dreq);
fail:
	return ERR_PTR(ret);
}

struct crail_file *crail_file_open(struct crail_client *crail,
		const char *path, enum crail_file_mode mode)
{
	struct darpc_request *dreq;
	struct darpc_rpc *rpc;
	struct crail_rpc_request_get_file *req;
	struct crail_rpc_response_file *resp;
	unsigned long idx;
	struct crail_file *file;
	int ret;

	dprint(DBG_META, "\n");

	ret = crail_post_response(crail);
	if (ret) {
		dprint(DBG_ON, "post response failed!\n");
		goto fail;
	}

	dreq = mem_pool_alloc(&crail->request_pool, &idx);
	if (!dreq) {
		dprint(DBG_ON, "could not alloc request\n");
		ret = -ENOMEM;
		goto fail;
	}

	req = (struct crail_rpc_request_get_file *)&dreq->data;
	req->hdr.cmd = cpu_to_be16(CRAIL_RPC_GET_FILE);
	req->hdr.type = cpu_to_be16(CRAIL_RPC_GET_FILE);
	path_to_file_name(&req->name, path);
	req->writeable = cpu_to_be32(mode & CRAIL_FILE_WRITE ? 1 : 0);

	rpc = darpc_client_perform_rpc(crail->darpc, dreq,
			crail_request_dma_addr(crail, idx), sizeof(*req));
	if (IS_ERR(rpc)) {
		dprint(DBG_ON, "request failed!\n");
		ret = PTR_ERR(rpc);
		goto fail_req;
	}

	ret = wait_for_completion_interruptible(&rpc->completion);
	if (ret) {
		dprint(DBG_ON, "interrupted\n");
		/* FIXME: free RPC!!!! */
		goto fail;
	}

	mem_pool_free(&crail->request_pool, dreq);

	resp = (struct crail_rpc_response_file *)&rpc->response->data;
	file = file_alloc(crail, resp);
	mem_pool_free(&crail->response_pool, rpc->response);
	darpc_client_rpc_done(crail->darpc, rpc);
	if (IS_ERR(file)) {
		dprint(DBG_ON, "create file failed!\n");
		ret = PTR_ERR(file);
		goto fail;
	}

	return file;
fail_req:
	mem_pool_free(&crail->request_pool, dreq);
fail:
	return ERR_PTR(ret);
}

static int set_file(struct crail_file *file, bool close)
{
	struct crail_client *crail = file->crail;
	struct darpc_rpc *rpc;
	struct darpc_request *dreq;
	struct crail_rpc_request_set_file *req;
	struct crail_rpc_response_set_file *resp;
	unsigned long idx;
	int ret = 0;

	dprint(DBG_META, "\n");

	ret = crail_post_response(crail);
	if (ret) {
		dprint(DBG_ON, "post response failed!\n");
		goto fail;
	}

	dreq = mem_pool_alloc(&crail->request_pool, &idx);
	if (!dreq) {
		dprint(DBG_ON, "could not alloc request\n");
		ret = -ENOMEM;
		goto fail;
	}

	req = (struct crail_rpc_request_set_file *)&dreq->data;
	req->hdr.cmd = cpu_to_be16(CRAIL_RPC_SET_FILE);
	req->hdr.type = cpu_to_be16(CRAIL_RPC_SET_FILE);
	req->file_info.fd = cpu_to_be64(file->fd);
	req->file_info.token = cpu_to_be64(file->token);
	req->file_info.capacity = cpu_to_be64(file->size);
	req->file_info.dir = cpu_to_be32(file->dir ? 1 : 0);
	req->file_info.dir_offset = cpu_to_be64(file->dir_offset);
	req->close = cpu_to_be32(close ? 1 : 0);

	rpc = darpc_client_perform_rpc(crail->darpc, dreq,
				crail_request_dma_addr(crail, idx), sizeof(*req));
	if (IS_ERR(rpc)) {
		dprint(DBG_ON, "request failed!\n");
		ret = PTR_ERR(rpc);
		goto fail_req;
	}

	ret = wait_for_completion_interruptible(&rpc->completion);
	if (ret) {
		dprint(DBG_ON, "interrupted\n");
		/* FIXME: free RPC!!!! */
		goto fail;
	}

	resp = (struct crail_rpc_response_set_file *)&rpc->response->data;
	if (be32_to_cpu(resp->hdr.error)) {
		dprint(DBG_ON, "response error\n");
	}

	mem_pool_free(&crail->response_pool, rpc->response);
	darpc_client_rpc_done(crail->darpc, rpc);
fail_req:
	mem_pool_free(&crail->request_pool, dreq);
fail:
	return ret;
}

int crail_file_close(struct crail_file *file)
{
	u32 i;
	int ret;

	ret = set_file(file, true);
	if (ret) {
		dprint(DBG_ON, "set file failed\n");
	}

	for (i = 0; i < CRAIL_MAX_BLOCKS_PER_FILE; i++) {
		if (file->block_cache[i]) {
			kmem_cache_free(block_cache, file->block_cache[i]);
		}
	}
	file_free(file);
	return ret;
}

unsigned long crail_file_size(struct crail_file *file)
{
	return file->size;
}

/* ------------ datanode ----------------- */

enum file_op {
   CRAIL_READ,
   CRAIL_WRITE
};

static int perform_block_op(struct crail_block *block, unsigned long offset,
        void *data, u32 size, struct crail_io_callback *io_cb, enum file_op op)

{
	struct rdma_client *rdma = block->crail_data->rdma;
	dma_addr_t dma_addr;
	struct ib_sge sge;
    struct crail_block_wc *block_wc;
    enum dma_data_direction dma_dir =
        op == CRAIL_READ ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	struct ib_send_wr wr, *bad_wr;
    int ret;

	dprint(DBG_DATA, "\n");

	dma_addr = ib_dma_map_single(rdma->cm_id->device, data, size, dma_dir);
	if (ib_dma_mapping_error(rdma->cm_id->device, dma_addr)) {
		dprint(DBG_ON, "mapping error\n");
		ret = -EFAULT;
        goto fail;
	}

	sge.addr = dma_addr;
	sge.length = size;
	sge.lkey = rdma_client_lkey(rdma);

    block_wc = kmem_cache_alloc(block_wc_cache, GFP_KERNEL);
    if (!block_wc) {
        dprint(DBG_ON, "could not alloc block wc\n");
        ret = -ENOMEM;
        goto fail_dma_map;
    }

    block_wc->io_cb = io_cb;
    block_wc->addr = dma_addr;
    block_wc->size = size;

	wr.next = NULL;
	wr.wr_id = (u64)block_wc;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = block->remote_addr + offset;
	wr.wr.rdma.rkey = block->rkey;
	wr.send_flags = IB_SEND_SIGNALED;
    if (op == CRAIL_WRITE) {
    	wr.opcode = IB_WR_RDMA_WRITE;
    } else {
	    wr.opcode = IB_WR_RDMA_READ;
    }

	ret = rdma_client_post_send(rdma, &wr, &bad_wr);
    if (ret) {
        dprint(DBG_ON, "post send failed\n");
        goto fail_block_wc;
    }

    return 0;
fail_block_wc:
    kmem_cache_free(block_wc_cache, block_wc);
fail_dma_map:
    ib_dma_unmap_single(rdma->cm_id->device, dma_addr, size, dma_dir);
fail:
    return ret;
}

static inline void block_op_finish(struct crail_io_callback *io_cb,
        int status)
{
    long n_blk_ops_finished;

    if (status) {
        io_cb->status = status;
    }

    n_blk_ops_finished = atomic_long_inc_return(&io_cb->n_blk_ops_finished);

    if (n_blk_ops_finished == io_cb->n_blk_ops) {
        int ret;

        if (!io_cb->status && io_cb->new_file_size) {
            io_cb->file->size = io_cb->new_file_size;
        }
        if (io_cb->status || io_cb->new_file_size) {
            /* we only update the file on error or if we have
             * a new file size -> */
            ret = set_file(io_cb->file, false);
            if (ret) {
                io_cb->status = ret;
            }
        }
        io_cb->func(io_cb->data, io_cb->status);
    }
}

static void datanode_comp_handler(struct rdma_client *rdma,
		struct ib_wc *wc, unsigned int entries)
{
	unsigned int i;

    dprint(DBG_DATA, "\n");

	for(i = 0; i < entries; i++) {
		switch(wc[i].opcode) {
			case IB_WC_RDMA_WRITE:
			case IB_WC_RDMA_READ:
			{
				enum dma_data_direction dir = wc[i].opcode == IB_WC_RDMA_WRITE ?
						DMA_TO_DEVICE : DMA_FROM_DEVICE;
                struct crail_block_wc *block_wc;
                struct crail_io_callback *io_cb;

                block_wc = (struct crail_block_wc *)wc[i].wr_id;
                io_cb = block_wc->io_cb;

                block_op_finish(io_cb, wc[i].status);

                ib_dma_unmap_single(rdma->cm_id->device, block_wc->addr,
                        block_wc->size, dir);

                kmem_cache_free(block_wc_cache, block_wc);
				break;
			}
			default:
				dprint(DBG_ON, "neither read or write!\n");
                break;
		}
	}
}

static struct crail_datanode_client *datanode_connect(struct crail_client *crail,
		struct sockaddr_in *addr)
{
	struct crail_datanode_client *crail_data;
	struct rdma_client *rdma;
	struct ib_qp_cap qp_cap;
	int ret;

	dprint(DBG_DATA, "%pI4:%hu\n", &addr->sin_addr.s_addr,
				be16_to_cpu(addr->sin_port));

	spin_lock(&crail->lock);
	list_for_each_entry(crail_data, &crail->datanode, list) {
		if (crail_data->addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
				crail_data->addr.sin_port == addr->sin_port) {
			spin_unlock(&crail->lock);
			dprint(DBG_DATA, "cached!\n");
			return crail_data;
		}
	}
	spin_unlock(&crail->lock);


	crail_data = kmalloc(sizeof(*crail_data), GFP_KERNEL);
	if (!crail_data) {
		dprint(DBG_ON, "could not allocate datanode\n");
		ret = -ENOMEM;
		goto fail;
	}
	memcpy(&crail_data->addr, addr, sizeof(*addr));

	qp_cap.max_inline_data = 0;
	qp_cap.max_recv_sge = 1;
	qp_cap.max_send_sge = 1;
	qp_cap.max_recv_wr = 0;
	qp_cap.max_send_wr = 1 << 12 /* 4096 */;
	rdma = rdma_client_create(datanode_comp_handler, qp_cap, qp_cap.max_send_wr);
	if (IS_ERR(rdma)) {
		dprint(DBG_ON, "could not create rdma client\n");
		ret = PTR_ERR(rdma);
		goto fail_data;
	}
	rdma->private_data = crail_data;

	ret = rdma_client_connect(rdma, addr, 2000);
	if (ret) {
		dprint(DBG_ON, "could not connect to datanode!\n");
		goto fail_client;
	}

	crail_data->rdma = rdma;

	rdma_client_begin_polling(rdma);

    spin_lock(&crail->lock);
	list_add(&crail_data->list, &crail->datanode);
    spin_unlock(&crail->lock);

	return crail_data;
fail_client:
	rdma_client_destroy(rdma);
fail_data:
	kfree(crail_data);
fail:
	return ERR_PTR(ret);
}

/* ------------ File operations ----------------- */

static unsigned long offset_in_block(struct crail_file *file,
		unsigned long offset)
{
	return offset & ((1 << file->crail->block_shift) - 1);
}

static unsigned long file_offset_block_idx(struct crail_file *file,
		unsigned long offset)
{
	return offset >> file->crail->block_shift;
}

struct block_future {
	struct crail_block *block;
	u64 block_idx;
	struct darpc_rpc *rpc;
	struct darpc_request *request;
};

static inline int try_wait_for_get_block(struct crail_file *file,
		struct block_future *bf)
{

	if (!bf->rpc) {
		/* cached blocked */
		dprint(DBG_DATA, "cached\n");
		return 0;
	} else if (try_wait_for_completion(&bf->rpc->completion)) {
		struct crail_client *crail = file->crail;
		struct crail_block *block = bf->block;
		struct crail_block *old_block;
		struct crail_rpc_response_get_block *resp;
		struct crail_datanode_client *datanode;
		struct sockaddr_in addr;
		int ret = 0;

		mem_pool_free(&crail->request_pool, bf->request);

		/* get block rpc is done: get response and check if connection
		 * to datanode already exists */

		resp = (struct crail_rpc_response_get_block *)&bf->rpc->response->data;
		if (be32_to_cpu(resp->hdr.error) != CRAIL_ERR_OK) {
			dprint(DBG_ON, "get block rpc failed\n");
			ret = -EFAULT;
			goto fail;
		}

		addr.sin_addr.s_addr = resp->block_info.ip;
		addr.sin_port = cpu_to_be16(be32_to_cpu(resp->block_info.port));
		addr.sin_family = AF_INET;

		datanode = datanode_connect(crail, &addr);
		if (IS_ERR(datanode)) {
			dprint(DBG_ON, "could not connect to datanode!\n");
			ret = PTR_ERR(datanode);
			goto fail;
		}

		block->crail_data = datanode;
		block->remote_addr = be64_to_cpu(resp->block_info.addr);
		block->rkey = be32_to_cpu(resp->block_info.lkey);

		old_block = xchg(file->block_cache + bf->block_idx, block);
		if (old_block) {
			/* there was a race so we just free the existing entry */
			kmem_cache_free(block_cache, old_block);
		}
fail:
		mem_pool_free(&crail->response_pool, bf->rpc->response);
		darpc_client_rpc_done(crail->darpc, bf->rpc);
		return ret;
	}
	return -EBUSY;
}

static int get_block(struct crail_file *file, u64 block_idx,
		struct block_future *future)
{
	struct darpc_rpc *rpc;
	struct darpc_request *dreq;
	struct crail_rpc_request_get_block *req;
	struct crail_block *block;
	struct crail_client *crail = file->crail;
	unsigned long idx;
	int ret;

	dprint(DBG_DATA, "\n");

	BUG_ON(block_idx > CRAIL_MAX_BLOCKS_PER_FILE);

	block = file->block_cache[block_idx];
	if (block) {
		future->block = block;
		future->rpc = NULL;
		dprint(DBG_DATA, "cached\n");
		return 0;
	}

	/* note that here might be a race where blocks are already added
	 * in this case we add the block again and remove the old one */
	block = kmem_cache_alloc(block_cache, GFP_KERNEL);
	if (!block) {
		dprint(DBG_ON, "could not allocate block!\n");
		ret = -ENOMEM;
		goto fail;
	}

	ret = crail_post_response(crail);
	if (ret) {
		dprint(DBG_ON, "post response failed!\n");
		goto fail_block;
	}

	dreq = mem_pool_alloc(&crail->request_pool, &idx);
	if (!dreq) {
		dprint(DBG_ON, "could not alloc request\n");
		ret = -ENOMEM;
		goto fail;
	}

	req = (struct crail_rpc_request_get_block *)&dreq->data;

	req->hdr.cmd = cpu_to_be16(CRAIL_RPC_GET_BLOCK);
	req->hdr.type = cpu_to_be16(CRAIL_RPC_GET_BLOCK);
	req->fd = cpu_to_be64(file->fd);
	req->token = cpu_to_be64(file->token);
	req->capacity = cpu_to_be64(file->size);
	req->position = cpu_to_be64(block_idx << crail->block_shift);

	rpc = darpc_client_perform_rpc(crail->darpc, dreq,
					crail_request_dma_addr(crail, idx), sizeof(*req));
	if (IS_ERR(rpc)) {
		dprint(DBG_ON, "request failed!\n");
		ret = PTR_ERR(rpc);
		goto fail_req;
	}

	future->block = block;
	future->block_idx = block_idx;
	future->rpc = rpc;
	future->request = dreq;
	return 0;
fail_req:
	mem_pool_free(&crail->request_pool, dreq);
fail_block:
	kmem_cache_free(block_cache, block);
fail:
	return ret;
}

static inline unsigned long size_left_in_block(struct crail_file *file,
        u64 start, u64 end, unsigned long size)
{
    struct crail_client *crail = file->crail;
    return  min_t(u64, (1 << crail->block_shift) - offset_in_block(file, end),
                size - (end - start));
}

static int crail_file_op(struct crail_file *file, u64 offset,
		char *buf, unsigned long size, enum file_op op,
		struct crail_io_callback *callback)
{
	struct block_future bf = { /* gcc thinks var is used uninit */ };
	u64 end = offset;
	int ret = 0;
    unsigned int n_blk_ops = 0;

	dprint(DBG_FILE, "fd: %llu, offset: %llu, size: %lu, op: %d\n",
				file->fd, offset, size, op);

	if (offset > file->size) {
		dprint(DBG_ON, "offset exceeds file size!\n");
		ret = -EINVAL;
		goto fail;
	}

    /* let's find out how many block ops we need */
    while (size > (end - offset)) {
        n_blk_ops++;
        end += size_left_in_block(file, offset, end, size);
    }

    callback->n_blk_ops += n_blk_ops;

    end = offset;
    while (size > (end - offset)) {
        unsigned long size_left;

        size_left = size_left_in_block(file, offset, end, size);
        ret = get_block(file, file_offset_block_idx(file, end), &bf);
        if (ret) {
            dprint(DBG_ON, "get block failed\n");
            break;
        }

        while ((ret = try_wait_for_get_block(file, &bf)) == -EBUSY);

        if (!ret) {
            ret = perform_block_op(bf.block, offset_in_block(file, end),
                    buf + (end - offset), size_left, callback, op);
            if (ret) {
                dprint(DBG_ON, "block op failed (%d)\n", ret);
                break;
            }
        } else {
            dprint(DBG_ON, "failed to wait for get block!\n");
            break;
        }

        n_blk_ops--;
        end += size_left;
    }

    if (end > file->size) {
        callback->new_file_size = end;
    }
    callback->n_blk_ops -= n_blk_ops;
    if (ret) {
        callback->status = ret;
    }
fail:
	return ret;
}

void crail_begin_transaction(struct crail_file *file,
        struct crail_io_callback *io_cb)
{
    io_cb->file = file;
    io_cb->status = 0;

    io_cb->new_file_size = 0;

    io_cb->n_blk_ops = 0;
    atomic_long_set(&io_cb->n_blk_ops_finished, -1);
}

void crail_end_transaction(struct crail_io_callback *io_cb)
{
    block_op_finish(io_cb, 0);
}

static void complete_sync_file_op(void *data, int status)
{
    struct completion *comp = data;
    complete(comp);
}

static ssize_t crail_file_op_sync(struct crail_file *file, u64 offset, char *buf,
        unsigned long size, enum file_op op)
{
	int ret;
	DECLARE_COMPLETION_ONSTACK(completion);
	struct crail_io_callback callback;

	dprint(DBG_FILE, "\n");

	callback.func = complete_sync_file_op;
	callback.data = &completion;

    crail_begin_transaction(file, &callback);
	ret = crail_file_op(file, offset, buf, size, op, &callback);
    crail_end_transaction(&callback);

	if (!ret) {
		ret = wait_for_completion_interruptible(&completion);
	}

    if (callback.status) {
        ret = callback.status;
    }

	return ret ? ret : size;

}

ssize_t crail_file_read(struct crail_file *file, u64 offset,
		char *buf, unsigned long size)
{

    dprint(DBG_FILE, "\n");

	if (offset + size > file->size) {
		dprint(DBG_ON, "read exceeds file size\n");
		return -EINVAL;
	}

	return crail_file_op_sync(file, offset, buf, size, CRAIL_READ);
}

ssize_t crail_file_write(struct crail_file *file, u64 offset,
		const char *buf, unsigned long size)
{

	dprint(DBG_FILE, "\n");

	return crail_file_op_sync(file, offset, (char *)buf, size, CRAIL_WRITE);
}

ssize_t crail_file_read_async(struct crail_file *file, u64 offset,
		char *buf, unsigned long size, struct crail_io_callback *callback)
{
	int ret;

    dprint(DBG_FILE, "\n");

	if (offset + size > file->size) {
		dprint(DBG_ON, "read exceeds file size\n");
		return -EINVAL;
	}

	ret = crail_file_op(file, offset, buf, size, CRAIL_READ, callback);
	return ret ? ret : size;
}

ssize_t crail_file_write_async(struct crail_file *file, u64 offset,
		const char *buf, unsigned long size,
		struct crail_io_callback *callback)
{
	int ret;

	dprint(DBG_FILE, "\n");

	ret = crail_file_op(file, offset, (char *)buf, size, CRAIL_WRITE,
			callback);
	return ret ? ret : size;
}

/* ------------ crail client operations ----------------- */

int crail_client_connect(struct crail_client *crail, struct sockaddr_in *addr)
{
	int ret;

	dprint(DBG_CLIENT, "\n");

	ret = darpc_client_connect(crail->darpc, addr);
	if (ret) {
		dprint(DBG_ON, "could not connect\n");
		return ret;
	}

	/* map all the responses and requests */
	ret = rdma_dma_map(crail->darpc->rdma, &crail->req_addr,
			crail->request_pool.data,
			crail->request_pool.obj_size * crail->request_pool.count,
			DMA_TO_DEVICE);
	if (ret) {
		dprint(DBG_ON, "request dma map failed\n");
        crail->req_addr = 0;
		return ret;
	}

	ret = rdma_dma_map(crail->darpc->rdma, &crail->resp_addr,
			crail->response_pool.data,
			crail->response_pool.obj_size * crail->response_pool.count,
			DMA_FROM_DEVICE);
	if (ret) {
		dprint(DBG_ON, "response dma map failed!\n");
        crail->resp_addr = 0;
		rdma_dma_unmap(crail->darpc->rdma, crail->req_addr,
				crail->request_pool.obj_size * crail->request_pool.count,
				DMA_TO_DEVICE);
		return ret;
	}

	return 0;
}

static void crail_response_error(struct darpc_response *response,
		void *data)
{
	struct crail_client *crail = data;

	dprint(DBG_ON, "\n");

	mem_pool_free(&crail->response_pool, response);
}

struct crail_client *crail_client_create(u32 block_shift, u32 queue_depth)
{
	struct crail_client *crail;
	int ret;

	dprint(DBG_CLIENT, "\n");

	if (block_shift > 32) {
		dprint(DBG_ON, "block size to large!\n");
		ret = -EINVAL;
		goto fail;
	}

	crail = kmalloc(sizeof(*crail), GFP_KERNEL);
	if (!crail) {
		dprint(DBG_ON, "could not allocate crail client\n");
		ret = -ENOMEM;
		goto fail;
	}
    crail->req_addr = 0;
    crail->resp_addr = 0;

	ret = mem_pool_init(&crail->request_pool,
			sizeof(struct darpc_request) + CRAIL_MAX_REQUEST_SIZE, queue_depth,
			L1_CACHE_BYTES);
	if (ret) {
		dprint(DBG_ON, "could not alloc req mem pool\n");
		goto fail_crail;
	}

	ret = mem_pool_init(&crail->response_pool,
			sizeof(struct darpc_response) + CRAIL_MAX_RESPONSE_SIZE,
			queue_depth, L1_CACHE_BYTES);
	if (ret) {
		dprint(DBG_ON, "could not alloc resp mem pool\n");
		goto fail_req;
	}
	/* we dma map request/response after connect because we need the
	 * ib device for that! */

	INIT_LIST_HEAD(&crail->datanode);
	spin_lock_init(&crail->lock);

	crail->darpc = darpc_client_create(queue_depth, &crail_response_error, crail);
	if (IS_ERR(crail->darpc)) {
		dprint(DBG_ON, "could not create darpc client\n");
		ret = PTR_ERR(crail->darpc);
		goto fail_resp;
	}
	crail->block_shift = block_shift;
	kref_init(&crail->ref_cnt);

	return crail;
fail_resp:
	mem_pool_destroy(&crail->response_pool);
fail_req:
	mem_pool_destroy(&crail->request_pool);
fail_crail:
	kfree(crail);
fail:
	return ERR_PTR(ret);
}

void crail_client_destroy(struct crail_client *crail)
{

	dprint(DBG_CLIENT, "\n");

	kref_put(&crail->ref_cnt, client_destroy);
}

int crail_client_init(void)
{
    int ret;

	block_cache = kmem_cache_create("crail-block-cache",
			sizeof(struct crail_block), 0, 0, NULL);
	if (!block_cache) {
		dprint(DBG_ON, "could not allocate block cache\n");
		ret = -ENOMEM;
        goto fail;
	}

	block_wc_cache = kmem_cache_create("crail-block-wc-cache",
			sizeof(struct crail_block_wc), 0, 0, NULL);
	if (!block_wc_cache) {
		dprint(DBG_ON, "could not allocate block wc cache\n");
		ret = -ENOMEM;
        goto fail_block_cache;
	}

	return 0;
fail_block_cache:
    kmem_cache_destroy(block_cache);
fail:
    return ret;
}

void crail_client_exit(void)
{
	kmem_cache_destroy(block_cache);
    kmem_cache_destroy(block_wc_cache);
}
