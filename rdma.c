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

#include <linux/kthread.h>

#include "rdma_debug.h"

#include "rdma.h"

#define NUM_WC_POLL 32

static inline int cq_poll_n(struct rdma_client *c, struct ib_wc *wc,
        unsigned long n)
{
	int ret;

	if ((ret = ib_poll_cq(c->cq, n, wc)) > 0) {
		c->comp_handler(c, wc, ret);
	}

	return ret;
}

static int poll_thread(void *data)
{
	struct rdma_client *c = data;

	dprint(DBG_POLL, "\n");


	while (!kthread_should_stop()) {

		 while(cq_poll_n(c, c->wc, NUM_WC_POLL) > 0);

		 schedule();
	}

	return 0;
}

int rdma_client_begin_polling(struct rdma_client *c)
{
	static unsigned long id = 0;
	int ret = 0;

	dprint(DBG_POLL, "\n");

	if (!c->cm_id) {
		dprint(DBG_ON, "not connected!\n");
		ret = -ENOTCONN;
		goto fail;
	}

	if (!c->poll_thread) {
		struct task_struct *thread;
		thread = kthread_create(poll_thread, c, "rdma-client-cq-poll-%lu",
				id++);
		if (IS_ERR(thread)) {
			dprint(DBG_ON, "could not create thread\n");
			ret = PTR_ERR(thread);
			goto fail;
		}
		c->poll_thread = thread;
	}
	c->cq_polling = true;
	wake_up_process(c->poll_thread);
fail:
	return ret;
}

void rdma_client_end_polling(struct rdma_client *c)
{
    struct ib_wc wc;

	dprint(DBG_POLL, "\n");

	ib_req_notify_cq(c->cq, IB_CQ_NEXT_COMP);
	c->cq_polling = false;
	/* avoid race condition -> retrieve left wc */
	while (cq_poll_n(c, &wc, 1) > 0);
}

int rdma_client_disconnect(struct rdma_client *c)
{
	int ret;

	ret = rdma_disconnect(c->cm_id);
	if (ret) {
		dprint(DBG_ON, "disconnect failed!\n");
		return ret;
	}
//	ret = wait_for_completion_interruptible(&c->cm_done);
//	if (ret || c->cm_state != RDMA_CM_EVENT_DISCONNECTED) {
//		ret = ret ? ret : -EFAULT;
//		dprint(DBG_ON, "could not disconnect successfully\n");
//		return ret;
//	}
	return 0;
}

static void destroy_cm_id(struct rdma_client *c)
{
	if (c->poll_thread) {
		kthread_stop(c->poll_thread);
		c->poll_thread = NULL;
	}

	if (c->cm_id) {
		rdma_client_disconnect(c);
		rdma_destroy_qp(c->cm_id);
		ib_dereg_mr(c->dma_mr);
		ib_dealloc_pd(c->pd);
		ib_destroy_cq(c->cq);
		rdma_destroy_id(c->cm_id);
		c->cm_id = NULL;
	}
}

static int cm_event_handler(struct rdma_cm_id *id,
		struct rdma_cm_event *event)
{
	struct rdma_client *c = id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
	case RDMA_CM_EVENT_ESTABLISHED:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
	case RDMA_CM_EVENT_DISCONNECTED:
		dprint(DBG_CONN, "%d\n", event->event);
		break;
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_MULTICAST_JOIN:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_CONNECT_REQUEST:
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		dprint(DBG_CONN, "disconnect: %d\n", event->event);
		rdma_client_disconnect(c);
		break;
	default:
		BUG();
	}
	c->cm_state = event->event;
	complete(&c->cm_done);
	return 0;
}

static void comp_handler(struct ib_cq *cq, void *cq_context)
{
	struct rdma_client *c = cq_context;

	dprint(DBG_CQ, "\n");

	if (!c->cq_polling) {
		ib_req_notify_cq(c->cq, IB_CQ_NEXT_COMP);
	}
	while (cq_poll_n(c, c->wc, NUM_WC_POLL) > 0);
}

int rdma_client_connect(struct rdma_client *c,
		struct sockaddr_in *addr, u32 connection_timeout)
{
	struct ib_qp_init_attr qp_attr;
	struct rdma_conn_param conn_param;
	struct ib_device_attr dev_attr;
	int ret;

	dprint(DBG_CONN, "\n");

	if (c->cm_id) {
			dprint(DBG_CONN, "already connected!\n");
			return -EBUSY;
	}

	c->cm_id = rdma_create_id(cm_event_handler, c, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(c->cm_id)) {
		ret = PTR_ERR(c->cm_id);
		goto fail;
	}

	ret = rdma_resolve_addr(c->cm_id, NULL, (struct sockaddr *)addr,
			connection_timeout);
	if (ret) {
		dprint(DBG_ON, "could not resolve addr (1)\n");
		goto fail_create_id;
	}

	ret = wait_for_completion_interruptible(&c->cm_done);
	if (ret || c->cm_state != RDMA_CM_EVENT_ADDR_RESOLVED) {
		ret = ret ? ret : -EFAULT;
		dprint(DBG_ON, "could not resolve addr (2)\n");
		goto fail_create_id;
	}

	ret = rdma_resolve_route(c->cm_id, connection_timeout);
	if (ret) {
		dprint(DBG_ON, "could not resolve route (1)\n");
		goto fail_create_id;
	}

	ret = wait_for_completion_interruptible(&c->cm_done);
	if (ret || c->cm_state != RDMA_CM_EVENT_ROUTE_RESOLVED) {
		ret = ret ? ret : -EFAULT;
		dprint(DBG_ON, "could not resolve route (2)\n");
		goto fail_create_id;
	}

	c->cq = ib_create_cq(c->cm_id->device, comp_handler, NULL, c,
			c->cq_depth, 0);
	if (IS_ERR(c->cq)) {
		ret = PTR_ERR(c->cq);
		dprint(DBG_ON, "could not create cq (%d)\n", ret);
		goto fail_create_id;
	}

	ib_req_notify_cq(c->cq, IB_CQ_NEXT_COMP);

	c->pd = ib_alloc_pd(c->cm_id->device);
	if (IS_ERR(c->pd)) {
		dprint(DBG_ON, "could not create pd\n");
		ret = PTR_ERR(c->pd);
		goto fail_create_cq;
	}

	/* Apparently iWarp requires remote write access for rdma reads o_O */
	c->dma_mr = ib_get_dma_mr(c->pd, IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(c->dma_mr)) {
		dprint(DBG_ON, "could not get dma mr\n");
		ret = PTR_ERR(c->dma_mr);
		goto fail_create_pd;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.event_handler = NULL;
	qp_attr.qp_context = c;
	qp_attr.cap = c->qp_cap;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = c->cq;
	qp_attr.recv_cq = c->cq;
	ret = rdma_create_qp(c->cm_id, c->pd, &qp_attr);
	if (ret) {
		dprint(DBG_ON, "could not create qp\n");
		goto fail_dma_mr;
	}
	c->qp_cap = qp_attr.cap;

	ret = ib_query_device(c->cm_id->device, &dev_attr);
	if (ret) {
		dprint(DBG_ON, "could not query device!\n");
		goto fail_create_qp;
	}

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.retry_count = 3;
	conn_param.responder_resources = dev_attr.max_qp_rd_atom;
	conn_param.initiator_depth = dev_attr.max_qp_rd_atom;
	ret = rdma_connect(c->cm_id, &conn_param);
	if (ret) {
		dprint(DBG_ON, "could not connect (1) (%d)\n", ret);
		goto fail_create_qp;
	}

	ret = wait_for_completion_interruptible(&c->cm_done);
	if (ret || c->cm_state != RDMA_CM_EVENT_ESTABLISHED) {
		ret = ret ? ret : -EFAULT;
		dprint(DBG_ON, "could not connect (2)\n");
		goto fail_create_qp;
	}

	dprint(DBG_CONN, "Connected!\n");

	return 0;
fail_create_qp:
	rdma_destroy_qp(c->cm_id);
fail_dma_mr:
	ib_dereg_mr(c->dma_mr);
fail_create_pd:
	ib_dealloc_pd(c->pd);
fail_create_cq:
	ib_destroy_cq(c->cq);
fail_create_id:
	rdma_destroy_id(c->cm_id);
	c->cm_id = NULL;
fail:
	return ret;
}

struct rdma_client *rdma_client_create(
		rdma_client_comp_handler client_comp_handler, struct ib_qp_cap qp_cap,
		u32 cq_depth)
{
	struct rdma_client *c;
    int ret;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		dprint(DBG_ON, "could not allocate client!\n");
		ret = -ENOMEM;
        goto fail;
	}
	init_completion(&c->cm_done);
	c->comp_handler = client_comp_handler;
	c->cq_depth = cq_depth;
	c->qp_cap = qp_cap;

    c->wc = kmalloc(sizeof(*c->wc) * NUM_WC_POLL, GFP_KERNEL);
    if (!c->wc) {
        dprint(DBG_ON, "could not alloc wcs\n");
        ret = -ENOMEM;
        goto fail_rdma;
    }

	return c;
fail_rdma:
    kfree(c);
fail:
    return ERR_PTR(ret);
}

void rdma_client_destroy(struct rdma_client *c)
{
	dprint(DBG_CLIENT, "\n");

	destroy_cm_id(c);
    kfree(c->wc);
	kfree(c);
}
