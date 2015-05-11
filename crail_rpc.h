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

#ifndef CRAIL_RPC_H_
#define CRAIL_RPC_H_

enum crail_rpc_type {
	CRAIL_RPC_CREATE_FILE = 1,
	CRAIL_RPC_GET_FILE = 2,
	CRAIL_RPC_SET_FILE = 3,
	CRAIL_RPC_GET_BLOCK = 6,
	CRAIL_RPC_PING = 11,
};

struct crail_rpc_request {
	__be16 cmd;
	__be16 type;
} __attribute__((packed));

struct crail_rpc_response {
	__be16 type;
	__be16 error;
} __attribute__((packed));

struct crail_rpc_file_info {
	__be64 fd;
	__be64 capacity;
	__be32 dir;
	__be64 dir_offset;
	__be64 token;
	__be64 modification_time;
} __attribute__((packed));

#define CRAIL_MAX_FILE_COMPONENTS 16

struct crail_rpc_file_name {
	__be32 length;
	__be32 components[CRAIL_MAX_FILE_COMPONENTS];
} __attribute__((packed));

struct crail_rpc_request_get_file {
	struct crail_rpc_request hdr;
	struct crail_rpc_file_name name;
	__be32 writeable;
};

struct crail_rpc_request_set_file {
	struct crail_rpc_request hdr;
	struct crail_rpc_file_info file_info;
	__be32 close;
} __attribute__((packed));

struct crail_rpc_response_set_file {
	struct crail_rpc_response hdr;
} __attribute__((packed));

struct crail_rpc_request_ping {
	struct crail_rpc_request hdr;
	__be32 op;
} __attribute__((packed));


struct crail_rpc_response_ping {
	struct crail_rpc_response hdr;
	__be32 data;
} __attribute__((packed));

struct crail_rpc_request_create_file {
	struct crail_rpc_request hdr;
	struct crail_rpc_file_name name;
	__be32 dir;
	__be32 overwriteable;
	__be32 writeable;
} __attribute__((packed));

enum crail_rpc_error {
	CRAIL_ERR_OK = 0,
	CRAIL_ERR_UNKNOWN = 1,
	CRAIL_ERR_PROTOCOL_MISMATCH = 2,
	CRAIL_ERR_CREATE_FILE_FAILED = 3,
	CRAIL_ERR_GET_FILE_FAILED = 4,
	CRAIL_ERR_TOKEN_TAKEN = 5,
};

struct crail_rpc_response_file {
	struct crail_rpc_response hdr;
	struct crail_rpc_file_info file_info;
	struct crail_rpc_file_info parent_info;
	__be64 token;
} __attribute__((packed));

struct crail_rpc_request_get_block {
	struct crail_rpc_request hdr;
	__be64 fd;
	__be64 token;
	__be64 position;
	__be64 capacity;
} __attribute__((packed));

struct crail_rpc_block_info {
	__be32 ip;
	__be32 port;
	__be64 addr;
	__be32 length;
	__be32 lkey;
} __attribute__((packed));

struct crail_rpc_response_get_block {
	struct crail_rpc_response hdr;
	struct crail_rpc_block_info block_info;
} __attribute__((packed));


#define maxC(a, b) ((a) > (b) ? (a) : (b))

#define CRAIL_MAX_RESPONSE_SIZE maxC( \
		maxC(	sizeof(struct crail_rpc_response_ping), \
				144U), \
		maxC(	sizeof(struct crail_rpc_response_file), \
				sizeof(struct crail_rpc_response_get_block)))

#define CRAIL_MAX_REQUEST_SIZE maxC( \
		maxC(	sizeof(struct crail_rpc_request_ping), \
				sizeof(struct crail_rpc_request_create_file)), \
		sizeof(struct crail_rpc_request_get_block))

#endif /* CRAIL_RPC_H_ */
