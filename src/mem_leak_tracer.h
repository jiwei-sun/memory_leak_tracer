/* memory leak tracer tool header file 
 *
 * Copyright (C) 2019 Sun Jiwei <jiwei.sun.bj@qq.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#ifndef _MEM_LEAK_TRACER_H
#define _MEM_LEAK_TRACER_H

/* one hour */
#define LOOP_TIME	(60 * 60)
/* log is in /tmp/memory_debug */
#define LOG_PATH "/tmp/memory_debug"
#define MAX_FRAME 64
#define HASHTABLE_SIZE	(1543)
#define CALLOC_STATIC_SIZE	(2048)

struct mem_leak_node_hdr {
	unsigned long flag;
	struct mem_leak_node *node;
};

struct mem_leak_node {
	unsigned char frame_cnt;
	char type;
	char in_used;
	size_t len;
	unsigned long addr;
	unsigned long time_stamp;
	void *frame[MAX_FRAME];
	struct list_head mmap_list;
	struct list_head alloc_list;
	struct list_head free_list;
	struct frame_hash_node *frame_node;
};

struct frame_hash_node {
	struct hlist_node hash_node;
	void *frame[MAX_FRAME];
	unsigned char frame_cnt;
	unsigned long counter;
};

static void* (*real_malloc)(size_t size);
static void* (*real_calloc)(size_t nmemb, size_t size);
static void* (*real_realloc)(void *ptr, size_t size);
static void  (*real_free)(void *ptr);
static void *(*real_mmap)(void *addr, size_t length, int prot, int flags,
		int fd, off_t offset);
static int (*real_munmap)(void *addr, size_t length);

extern void mem_leak_backtrace_symbols_fd(void *const *buffer, int size, int fd);
extern int mem_leak_backtrace(void **buffer, int size);
#endif
