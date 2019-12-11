/*
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 2.1 along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
 * AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
 * DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
 * OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
 * WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
 * EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
 * THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
 * CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
 * EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
 * OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
 * PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
 * REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
 * UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
 *
 * queue.c
 *
 * libptrace queue management.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <libptrace/error.h>
#include "queue.h"

int pt_queue_init(struct pt_queue *queue, size_t size)
{
	pt_queue_entry_t *data;

	assert(queue != NULL);
	assert(size != 0);

	if (size > SIZE_MAX / sizeof(pt_queue_entry_t)) {
		pt_error_internal_set(PT_ERROR_ARITH_OVERFLOW);
		return -1;
	}

	if ( (data = calloc(size, sizeof(pt_queue_entry_t))) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	queue->flags = PT_QUEUE_FLAG_NONE;
	queue->data  = data;
	queue->size  = size;
	queue->head  = 0;
	queue->tail  = 0;
	pt_mutex_init(&queue->mutex);
	pt_condvar_init(&queue->cond_full);
	pt_condvar_init(&queue->cond_empty);

	return 0;
}

int pt_queue_destroy(struct pt_queue *queue)
{
	assert(queue != NULL);
	assert(queue->data != NULL);

	pt_mutex_destroy(&queue->mutex);
	pt_condvar_destroy(&queue->cond_full);
	pt_condvar_destroy(&queue->cond_empty);
	free(queue->data);

	return 0;
}

static inline int pred_queue_full_(void *arg)
{
	struct pt_queue *queue = (struct pt_queue *)arg;
	return queue->tail == queue->head + queue->size;
}

static int pt_queue_push(struct pt_queue *queue, void *value)
{
	assert(queue != NULL);
	assert(value != NULL);

	pt_mutex_lock(&queue->mutex);

	/* No space left in the queue. */
	if (queue->tail == queue->head + queue->size) {

		/* Non-blocking mode.  Return an error. */
		if (queue->flags & PT_QUEUE_FLAG_SEND_NONBLOCK) {
			pt_mutex_unlock(&queue->mutex);
			pt_error_internal_set(PT_ERROR_WOULD_BLOCK);
			return -1;
		}

		/* Wait until we have space again. */
		pt_condvar_wait(&queue->cond_full, &queue->mutex, pred_queue_full_, queue);
	}

	queue->data[queue->tail++ % queue->size] = value;

	/* If we have consumers waiting on an empty queue, notify
	 * one of them.
	 */
	if ( (queue->flags & PT_QUEUE_FLAG_RECV_NONBLOCK) == 0)
		pt_condvar_notify(&queue->cond_empty);

	pt_mutex_unlock(&queue->mutex);

	return 0;
}

static inline int pred_queue_empty_(void *arg)
{
	struct pt_queue *queue = (struct pt_queue *)arg;
	return queue->head == queue->tail;
}

static void *pt_queue_pop(struct pt_queue *queue)
{
	void *ret = NULL;

	assert(queue != NULL);

	pt_mutex_lock(&queue->mutex);

	/* No elements in the queue. */
	if (queue->head == queue->tail) {
		if (queue->flags & PT_QUEUE_FLAG_RECV_NONBLOCK) {
			pt_mutex_unlock(&queue->mutex);
			pt_error_internal_set(PT_ERROR_WOULD_BLOCK);
			return NULL;
		}

		pt_condvar_wait(&queue->cond_empty, &queue->mutex, pred_queue_empty_, queue);
	}

	ret = queue->data[queue->head++ % queue->size];

	/* If pushes are blocking we notify a single push waiter. */
	if ( (queue->flags & PT_QUEUE_FLAG_SEND_NONBLOCK) == 0)
		pt_condvar_notify(&queue->cond_full);

	pt_mutex_unlock(&queue->mutex);

	return ret;
}

struct pt_message
{
	size_t        msg_len;
	unsigned char msg[0];
};

int pt_queue_send(struct pt_queue *queue, const void *msg, size_t msg_len)
{
	struct pt_message *tx_msg;

	if ( (tx_msg = malloc(sizeof *tx_msg + msg_len)) == NULL) {
		pt_error_errno_set(errno);
		return -1;
	}

	tx_msg->msg_len = msg_len;
	memcpy(tx_msg->msg, msg, msg_len);

	if (pt_queue_push(queue, tx_msg) == -1) {
		free(tx_msg);
		return -1;
	}

	return 0;
}

int pt_queue_recv(struct pt_queue *queue, void *msg, size_t msg_len)
{
	struct pt_message *rx_msg;

	if ( (rx_msg = pt_queue_pop(queue)) == NULL)
		return -1;

	/* XXX: message is lost. */
	if (rx_msg->msg_len > msg_len) {
		free(rx_msg);
		pt_error_internal_set(PT_ERROR_MSGSIZE);
		return -1;
	}

	memcpy(msg, rx_msg->msg, rx_msg->msg_len);
	free(rx_msg);

	return 0;
}
