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
 
#ifndef _DARPC_DEBUG_H
#define _DARPC_DEBUG_H

#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>	/* in_interrupt() */

/*
 * dprint: Selective debug printing
 *
 * Use an OR combination of DBG_* as dbgcat in dprint*(dbgcat,...)
 * to assign debug messages to categories:
 *
 * dbgcat	Debug message belongs to category
 * ----------------------------------------------------------------------------
 * DBG_ON	Always on, for really important events or error conditions
 * DBG_TMP	Temporarily on for fine-grained debugging
 * DBQ_OBJ	Object management (object construction/destruction/refcounting)
 * DBG_MM	Memory management
 * DBG_EH	Event handling (completion events and asynchronous events)
 * DBG_CM	Connection management, QP states
 * DBG_WR	Work requests
 * DBG_TX	iWARP TX path
 * DBG_RX	iWARP RX path
 * DBG_SK	Socket operations
 * DBG_KT	Kernel threads
 * DBG_IRQ	Interrupt context (SoftIRQ or HardIRQ)
 * DBG_DM	Device management
 * DBG_HDR	Packet HDRs
 * DBG_ALL	All categories above
 */
#define DBG_ON			0x00000001
#define DBG_CQ			0x00000002
#define DBG_CLIENT		0x00000004
#define DBG_RPC			0x00000008
#define DBG_ALL		(DBG_ON | DBG_CQ | DBG_CLIENT | DBG_RPC)

/*
 * Set DPRINT_MASK to tailor your debugging needs:
 *
 * DPRINT_MASK value		Enables debug messages for
 * ---------------------------------------------------------------------
 * DBG_ON			Important events / error conditions only
 *				(minimum number of debug messages)
 * OR-ed combination of DBG_*	Selective debugging
 * DBG_KT|DBG_ON		Kernel threads
 * DBG_ALL			All categories
 */
#define DPRINT_MASK 	DBG_ON

#undef DEBUG
#define DEBUG_ORQ
#undef DEBUG_ORQ

#if DPRINT_MASK > 0

/**
 * dprint - Selective debug print for process, SoftIRQ or HardIRQ context
 *
 * Debug print with selectable debug categories,
 * starting with header
 * - "( pid /cpu) __func__" for process context
 * - "( irq /cpu) __func__" for IRQ context
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * @fmt		: printf compliant format string
 * @args	: printf compliant argument list
 */
#define dprint(dbgcat, fmt, args...)					\
	do {								\
		if ((dbgcat) & DPRINT_MASK) {				\
			if (!in_interrupt())				\
				pr_info("(%5d/%1d) %s " fmt,		\
					current->pid,			\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			else						\
				pr_info("( irq /%1d) %s " fmt,		\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
		}							\
	} while (0)

#endif

#endif
