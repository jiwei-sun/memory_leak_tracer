/* memory leak trace tool
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
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "app_arch.h"
#include "list.h"
#include "mmap_header.h"
#include "mem_leak_tracer.h"

//#define EN_DEBUG
#ifdef EN_DEBUG
#define DEBUG_LOG_FILE	LOG_PATH"/mem_leak_tool_debug.log"
static int fd_dbg = 2; /* default is stdout; */
#endif

static unsigned long loop_time = LOOP_TIME;
static struct hlist_head frame_hash_table[HASHTABLE_SIZE];

/* For alloc function, such as malloc, calloc, realloc */
static struct list_head alloc_header;

static struct list_head free_header;

/* For mmap function, such as mmap, and munmap */
static struct list_head mmap_header;

static pthread_mutex_t alloc_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mmap_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t free_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t hash_table_mutex = PTHREAD_MUTEX_INITIALIZER;

/* For reentrant */
static __thread char disable_hook;

static char calloc_static_buf[CALLOC_STATIC_SIZE];
static unsigned long calloc_static_pos = 0;
static int initi = 0;
static pid_t current_pid = 0;

static unsigned int cal_hash(long* backtrace, unsigned char frame_cnt)
{
	unsigned char i;
	unsigned int hash = 0;

	if (!backtrace)
		return 0;

	for (i = 0 ; i < frame_cnt ; i++)
		hash = hash * 33 + (backtrace[i] >> 2);

	return hash;
}

static void record_doubtful_to_file(const char *file_name)
{
	char str[128];
	unsigned long slot;
	int cnt;
	int fd;

	fd = open(file_name, O_WRONLY | O_CREAT, 0777);
	if (fd == -1) {
		cnt = sprintf(str, "open %s failed, errno:%d\n", file_name, errno);
		write(2, str, cnt);
		exit(1);
	}

	for (slot = 0; slot < HASHTABLE_SIZE; slot++) {
		struct hlist_head *head = &frame_hash_table[slot];
		struct frame_hash_node *frame_node;

		hlist_for_each_entry(frame_node, head, hash_node) {
			if (frame_node->counter > 1) {
				cnt = sprintf(str, "\n\nCall Trace counter: %lu\n",
						frame_node->counter);
				write(fd, str, cnt);
				mem_leak_backtrace_symbols_fd(frame_node->frame, frame_node->frame_cnt, fd);
			}
		}
	}

	close(fd);
}

static void report_doubtful(void)
{
	char file_name[128];
	int cnt;

	cnt = sprintf(file_name, "%s/%d.doubtful.%lu.log", LOG_PATH, current_pid, time(NULL));
	if (cnt < 0) {
		exit(1);
	}

	record_doubtful_to_file(file_name);
}

static void record_all_to_file(const char *file_name)
{
	char str[128];
	char str_type[16];
	int cnt;
	int fd;
	struct mem_leak_node *node;

	fd = open(file_name, O_WRONLY | O_CREAT, 0777);
	if (fd == -1) {
		cnt = sprintf(str, "open %s failed, errno:%d\n", file_name, errno);
		write(2, str, cnt);
		exit(1);
	}

	list_for_each_entry(node, &mmap_header, mmap_list) {
		switch (node->type) {
			case 1:
				sprintf(str_type, "%s", "mmap");
				break;
			default:
				sprintf(str_type, "%s", "type error");
				break;
		}
		cnt = sprintf(str, "\n\n %s addr %p, len %u, time_stamp:%lu\n",
				str_type, (void *)node->addr,
				(unsigned int)node->len, node->time_stamp);
		write(fd, str, cnt);
		mem_leak_backtrace_symbols_fd(node->frame, node->frame_cnt, fd);
	}

	list_for_each_entry(node, &alloc_header, alloc_list) {
		switch (node->type) {
			case 2:
				sprintf(str_type, "%s", "malloc");
				break;
			case 3:
				sprintf(str_type, "%s", "calloc");
				break;
			case 4:
				sprintf(str_type, "%s", "realloc");
				break;
			default:
				sprintf(str_type, "%s", "type error");
				break;
		}
		cnt = sprintf(str, "\n\n %s addr %p, len %u, time_stamp:%lu\n",
				str_type, (void *)node->addr,
				(unsigned int)node->len, node->time_stamp);
		write(fd, str, cnt);
		mem_leak_backtrace_symbols_fd(node->frame, node->frame_cnt, fd);
	}
	close(fd);
}

static void report_all(void)
{
	char file_name[128];
	int cnt;

	cnt = sprintf(file_name, "%s/%d.all.%lu.log", LOG_PATH, current_pid, time(NULL));
	if (cnt < 0) {
		exit(1);
	}
	record_all_to_file(file_name);
}

static void *record_thread(void *arg)
{
	//sleep(120);
	report_all();
	report_doubtful();

	while(1) {
#ifdef EN_DEBUG
		char str[128];
		int cnt;
		cnt = sprintf(str, "\nprint list thread running,task:%d\n", getpid());
		write(fd_dbg, str, cnt);
#endif
		sleep(loop_time);
		report_all();
		report_doubtful();
	}

	return NULL;
}

static void check_pid(void)
{
	int ret;
	pthread_t thread;
	pid_t new_pid = getpid();

	if (new_pid == current_pid)
		return;

	current_pid = new_pid;

	ret = pthread_create(&thread, NULL, record_thread, NULL);
	if (ret != 0) {
		char str[64];
		int cnt;
		cnt = sprintf(str, "create thread failed, errno:%d\n", errno);
		write(2, str, cnt);
		exit(1);
	}
}

static void get_loop_time(void)
{
	char *env_loop_time = getenv("MEM_LEAK_LOOP_TIME");
	if (env_loop_time)
		loop_time = atoi(env_loop_time);
}

__attribute__((constructor)) static void init_test(void)
{
	if (initi == 0) {
		int cnt;
		char str[128];

		initi = 1;

		if (access(LOG_PATH, F_OK) !=  0) {
			if (mkdir(LOG_PATH, 0777) == -1) {
				cnt = sprintf(str, "CREATE %s failed, errno:%d\n",
						LOG_PATH, errno);
				write(2, str, cnt);
				exit(1);
			}
		}

		check_pid();
		get_loop_time();

#ifdef EN_DEBUG
		fd_dbg = open(DEBUG_LOG_FILE, O_RDWR | O_APPEND | O_CREAT, 0777);
		if (fd_dbg == -1) {
			cnt = sprintf(str, "open %s failed, errno:%d\n",
					DEBUG_LOG_FILE, errno);
			write(2, str, cnt);
			exit(1);
		}
#endif

		INIT_LIST_HEAD(&alloc_header);
		INIT_LIST_HEAD(&free_header);
		INIT_LIST_HEAD(&mmap_header);

		real_malloc = dlsym(RTLD_NEXT, "malloc");
		real_calloc = dlsym(RTLD_NEXT, "calloc");
		real_realloc = dlsym(RTLD_NEXT, "realloc");
		real_free = dlsym(RTLD_NEXT, "free");
		real_mmap = dlsym(RTLD_NEXT, "mmap");
		real_munmap = dlsym(RTLD_NEXT, "munmap");

		if (!real_malloc || !real_calloc || !real_realloc ||
		    !real_free || !real_mmap || !real_munmap) {
			cnt = sprintf(str, "relocate the function error,task:%d\n", getpid());
			write(2, str, cnt);
			exit(1);
		}
		initi = 0;
	}
}

static struct mem_leak_node * get_free_node(void)
{
	struct mem_leak_node *node = NULL;

	pthread_mutex_lock(&free_list_mutex);
	if (!list_empty(&free_header)) {
		node = list_first_entry(&free_header, struct mem_leak_node, free_list);
		list_del(&node->free_list);
	}
	pthread_mutex_unlock(&free_list_mutex);

	if (!node) {
		node = (struct mem_leak_node *) real_malloc(sizeof(struct mem_leak_node));
		if (!node)
			return NULL;

		INIT_LIST_HEAD(&node->mmap_list);
		INIT_LIST_HEAD(&node->alloc_list);
		INIT_LIST_HEAD(&node->free_list);
	}

	return node;
}

struct frame_hash_node * record_backtrace(void **frame, char frame_cnt)
{
	unsigned char i;
	size_t hash = cal_hash(*frame, frame_cnt);
	size_t slot = hash % HASHTABLE_SIZE;

	struct frame_hash_node *frame_node, *tmp_node;
	struct hlist_head *head = &frame_hash_table[slot];

	pthread_mutex_lock(&hash_table_mutex);

	hlist_for_each_entry(frame_node, head, hash_node) {
		tmp_node = frame_node;
		if (frame_cnt != tmp_node->frame_cnt)
			continue;

		for (i = 0; i < frame_cnt ; i++) {
			if (tmp_node->frame[i] == frame[i])
				continue;
			tmp_node = NULL;
			break;
		}
		if (tmp_node) {
			tmp_node->counter++;
			pthread_mutex_unlock(&hash_table_mutex);
			return tmp_node;
		}
	}

	frame_node = real_malloc(sizeof(struct frame_hash_node));
	frame_node->counter = 1;
	frame_node->frame_cnt = frame_cnt;
	for (i = 0; i < frame_cnt ; i++) {
		frame_node->frame[i] = frame[i];
	}
	INIT_HLIST_NODE(&frame_node->hash_node);

	hlist_add_head(&frame_node->hash_node, head);

	pthread_mutex_unlock(&hash_table_mutex);
	return frame_node;
}

void *mmap(void *addr, size_t length, int prot, int flags,
		int fd, off_t offset)
{
	void *ret_addr;

	check_pid();

	if(real_mmap) {
		struct mem_leak_node *node;

		ret_addr = real_mmap(addr, length, prot, flags, fd, offset);
		if (disable_hook || (ret_addr == (void *)-1))
			return ret_addr;

		//In case of iteration
		disable_hook = 1;

		node = get_free_node();
		if (!node)
			exit(-1);

		node->frame_cnt = mem_leak_backtrace(node->frame, MAX_FRAME);
		node->addr = (unsigned long)ret_addr;
		node->len = length;
		node->in_used = 1;
		node->type = 0x1;
		node->time_stamp = time(NULL);
		node->frame_node = record_backtrace(node->frame, node->frame_cnt);
		pthread_mutex_lock(&mmap_list_mutex);
		INIT_LIST_HEAD(&node->mmap_list);
		list_add_tail(&node->mmap_list, &mmap_header);
		pthread_mutex_unlock(&mmap_list_mutex);

		disable_hook = 0;
	} else {
		ret_addr = (void *)syscall(__NR_mmap2, addr, length, prot, flags, fd, offset);
		if ((void *)-1 == ret_addr) {
			int cnt;
			char str[128];
			cnt = snprintf(str, 128, "Syscall mmap failed, errno:%d\n", errno);
			write(2, str, cnt);
			exit(1);
		}
	}
#ifdef EN_DEBUG
	int cnt;
	char str[128];
	cnt = snprintf(str, 128, "\n==%s %d,task:%d,ret_addr:0x%p, addr:0x%p\n",__func__, __LINE__, getpid(),ret_addr, addr);
	write(fd_dbg, str, cnt);
#endif
	return ret_addr;
}

int munmap(void *addr, size_t length)
{
	check_pid();

	if (real_munmap) {
		struct mem_leak_node *node;

		if (disable_hook) {
			return real_munmap(addr, length);
		}

again:
		list_for_each_entry_reverse(node, &mmap_header, mmap_list) {
			if (node->in_used == 0)
				goto again;

			if (node->addr == (unsigned long)addr) {
				pthread_mutex_lock(&mmap_list_mutex);
				__list_del_entry(&node->mmap_list);
				node->in_used = 0;
				node->addr = 0;
				node->len = 0;
				node->frame_cnt = 0;
				node->type = 0x0;
				node->time_stamp = 0;
				if (node->frame_node && (node->frame_node->counter > 0))
					node->frame_node->counter--;
				node->frame_node = NULL;
				pthread_mutex_unlock(&mmap_list_mutex);

				pthread_mutex_lock(&free_list_mutex);
				list_add_tail(&node->free_list, &free_header);
				pthread_mutex_unlock(&free_list_mutex);

				return real_munmap(addr, length);
			}
		}
		return real_munmap(addr, length);
	} else {
		return syscall(__NR_munmap, addr, length);
	}

	return -1;
}

void *malloc(size_t size)
{
	void * addr = NULL;

	check_pid();

	if(real_malloc) {
		struct mem_leak_node_hdr *hdr = NULL;

		if (disable_hook)
			return real_malloc(size);

		//In case of iteration
		disable_hook = 1;

		addr = real_malloc(size + sizeof(struct mem_leak_node_hdr));
		if (!addr)
			return addr;

		hdr = (struct mem_leak_node_hdr*)addr;
		hdr->flag = 0xa5a5a5a5;
		hdr->node = get_free_node();
		if (!hdr->node)
			exit(1);

		addr = (void *)((struct mem_leak_node_hdr *)addr + 1);

		pthread_mutex_lock(&alloc_list_mutex);
		hdr->node->frame_cnt = mem_leak_backtrace(hdr->node->frame, MAX_FRAME);

		hdr->node->frame_node = record_backtrace(hdr->node->frame, hdr->node->frame_cnt);
		hdr->node->addr = (unsigned long)addr;
		hdr->node->len = size;
		hdr->node->in_used = 1;
		hdr->node->type = 0x2;
		hdr->node->time_stamp = time(NULL);

		INIT_LIST_HEAD(&hdr->node->alloc_list);
		list_add_tail(&hdr->node->alloc_list, &alloc_header);
		pthread_mutex_unlock(&alloc_list_mutex);

		disable_hook = 0;
	}

	return addr;
}

static void* temp_malloc(size_t size)
{
	void *ptr;

	if (calloc_static_pos + size >= sizeof(calloc_static_buf))
		return NULL;

	ptr = calloc_static_buf + calloc_static_pos;
	calloc_static_pos += size;

	return ptr;
}

static void* temp_calloc(size_t nmemb, size_t size)
{
	unsigned int i = 0;
	void *ptr = temp_malloc(nmemb * size);
	if (!ptr)
		return NULL;

	for (; i < nmemb * size; ++i)
		*((char*)(ptr + i)) = '\0';
	return ptr;
}

static int is_calloc_static_area(void *ptr)
{
	if (((unsigned long)ptr >= (unsigned long)calloc_static_buf) &&
	    ((unsigned long)ptr < (unsigned long)(calloc_static_pos + CALLOC_STATIC_SIZE)))
		return 1;

	return 0;
}

void *calloc(size_t nmemb, size_t size)
{
	void * addr = NULL;

	check_pid();

	if(real_calloc) {
		size_t tmp_size;
		struct mem_leak_node_hdr *hdr = NULL;

		if (disable_hook)
			return real_calloc(nmemb, size);

		//In case of iteration
		disable_hook = 1;

		//addr = real_calloc(nmemb, size);
		tmp_size = size * nmemb;
		addr = real_malloc(tmp_size + sizeof(struct mem_leak_node_hdr));
		if (!addr)
			return addr;

		hdr = (struct mem_leak_node_hdr*)addr;
		hdr->flag = 0xa5a5a5a5;
		hdr->node = get_free_node();
		if (!hdr->node)
			exit(1);

		//addr = (void *)((char *)addr + sizeof(struct mem_leak_node_hdr));
		addr = (void *)((struct mem_leak_node_hdr *)addr + 1);

		pthread_mutex_lock(&alloc_list_mutex);
		hdr->node->frame_cnt = mem_leak_backtrace(hdr->node->frame, MAX_FRAME);
		hdr->node->frame_node = record_backtrace(hdr->node->frame, hdr->node->frame_cnt);
		hdr->node->addr = (unsigned long)addr;
		hdr->node->len = tmp_size;
		hdr->node->in_used = 1;
		hdr->node->type = 0x3;
		hdr->node->time_stamp = time(NULL);

		INIT_LIST_HEAD(&hdr->node->alloc_list);
		list_add_tail(&hdr->node->alloc_list, &alloc_header);
		pthread_mutex_unlock(&alloc_list_mutex);

		disable_hook = 0;
	} else {
		addr = temp_calloc(nmemb, size);
	}

	return addr;
}

void* realloc(void *ptr, size_t size)
{
	void * addr = NULL;

	check_pid();

	if(real_realloc) {
		struct mem_leak_node_hdr *hdr = NULL;
		struct mem_leak_node_hdr *old_hdr = NULL;
		unsigned char effective_hdr = 0;
		void * tmp_addr = NULL;

		if (disable_hook)
			return real_realloc(ptr, size);

		//In case of iteration
		disable_hook = 1;

		addr = real_malloc(size + sizeof(struct mem_leak_node_hdr));
		if (!addr)
			return addr;

		hdr = (struct mem_leak_node_hdr*)addr;
		hdr->flag = 0xa5a5a5a5;
		hdr->node = get_free_node();
		if (!hdr->node)
			exit(1);

		//addr = (void *)((char *)addr + sizeof(struct mem_leak_node_hdr));
		addr = (void *)((struct mem_leak_node_hdr *)addr + 1);

		if (ptr) {
			size_t old_size, copy_size;
			old_hdr = (struct mem_leak_node_hdr*)((char *)ptr - sizeof(struct mem_leak_node_hdr));

			if (old_hdr->flag == 0xa5a5a5a5) {
				old_size = old_hdr->node->len;
				copy_size = old_size < size ? old_size : size;
				memcpy(addr, ptr, copy_size);
				effective_hdr = 1;
			} else {
				tmp_addr = real_realloc(ptr, size);
				if (!tmp_addr)
					exit(1);
				memcpy(addr, tmp_addr, size);
				real_free(tmp_addr);
			}
		}

		pthread_mutex_lock(&alloc_list_mutex);
		hdr->node->frame_cnt = mem_leak_backtrace(hdr->node->frame, MAX_FRAME);
		hdr->node->frame_node = record_backtrace(hdr->node->frame, hdr->node->frame_cnt);
		hdr->node->addr = (unsigned long)addr;
		hdr->node->len = size;
		hdr->node->in_used = 1;
		hdr->node->type = 0x4;
		hdr->node->time_stamp = time(NULL);

		INIT_LIST_HEAD(&hdr->node->alloc_list);
		list_add_tail(&hdr->node->alloc_list, &alloc_header);
		pthread_mutex_unlock(&alloc_list_mutex);

		disable_hook = 0;

		if (effective_hdr == 1) {
			free(ptr);
		}
	}

	return addr;
}

void free(void *ptr)
{
	check_pid();

	if (is_calloc_static_area(ptr))
		return;

	if (real_free) {
		struct mem_leak_node_hdr *hdr;

		if (disable_hook || !ptr) {
			real_free(ptr);
			return;
		}

		hdr = (struct mem_leak_node_hdr*)((char *)ptr - sizeof(struct mem_leak_node_hdr));

		if (hdr->flag == 0xa5a5a5a5) {
			pthread_mutex_lock(&alloc_list_mutex);
			__list_del_entry(&hdr->node->alloc_list);
			hdr->node->in_used = 0;
			hdr->node->addr = 0;
			hdr->node->len = 0;
			hdr->node->frame_cnt = 0;
			hdr->node->type = 0x0;
			hdr->node->time_stamp = 0;
			if (hdr->node->frame_node && (hdr->node->frame_node->counter > 0))
				hdr->node->frame_node->counter--;
			hdr->node->frame_node = NULL;
			pthread_mutex_unlock(&alloc_list_mutex);

			pthread_mutex_lock(&free_list_mutex);
			list_add_tail(&hdr->node->free_list, &free_header);
			pthread_mutex_unlock(&free_list_mutex);

			hdr->node = NULL;
			hdr->flag = 0;
			real_free(hdr);
		} else {
			real_free(ptr);
		}
	}
}

__attribute__((destructor)) static void fini(void)
{
	char file_name[64];
	int cnt;

	cnt = sprintf(file_name, "%s/%d_total.log", LOG_PATH, getpid());
	if (cnt < 0)
		exit(1);
	record_all_to_file(file_name);

	cnt = sprintf(file_name, "%s/%d_total.doubtful.log", LOG_PATH, current_pid);
	if (cnt < 0) {
		exit(1);
	}

	record_doubtful_to_file(file_name);
}
