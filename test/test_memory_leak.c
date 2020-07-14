#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=10 ./test_memory_leak.elf 
 * */

int malloc_leak_cnt = 0;
int calloc_leak_cnt = 0;
int realloc_leak_cnt = 0;
int mmap_leak_cnt = 0;

#define MEM_SIZE	(1024)
void mmap_test4(void)
{
	char *mem0 = NULL;

	mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 1 * MEM_SIZE);

	mem0 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 2 * MEM_SIZE);

	mem0 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	mem0 = mmap(NULL, 4 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	mem0 = mmap(NULL, 5 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	mem0 = mmap(NULL, 6 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void mmap_test3(void)
{
	char *mem0 = NULL;

	mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 1 * MEM_SIZE);

	mem0 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 2 * MEM_SIZE);

	mem0 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	mem0 = mmap(NULL, 4 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	mem0 = mmap(NULL, 5 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void mmap_test2(void)
{
	char *mem0 = NULL;

	mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 1 * MEM_SIZE);

	mem0 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 2 * MEM_SIZE);

	mem0 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	mem0 = mmap(NULL, 4 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void mmap_test1(void)
{
	char *mem0 = NULL;

	mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 1 * MEM_SIZE);

	mem0 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	munmap(mem0, 2 * MEM_SIZE);

	mem0 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void mmap_test(int type)
{
	switch (type) {
	case 1:
		mmap_test1();
		break;
	case 2:
		mmap_test2();
		break;
	case 3:
		mmap_test3();
		break;
	default:
		mmap_test4();
		break;
	}
}

void realloc_test(int type)
{
	int *realloc_addr;
	switch (type) {
	case 1:
		realloc_addr = malloc(1300);
		realloc_addr = realloc(realloc_addr, 1300 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(1400);
		realloc_addr = realloc(realloc_addr, 1400 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(1500);
		realloc_addr = realloc(realloc_addr, 1500 * sizeof(int));
		break;
	case 2:
		realloc_addr = malloc(1600);
		realloc_addr = realloc(realloc_addr, 1600 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(1700);
		realloc_addr = realloc(realloc_addr, 1700 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(1800);
		realloc_addr = realloc(realloc_addr, 1800 * sizeof(int));
		realloc_addr = malloc(1900);
		realloc_addr = realloc(realloc_addr, 1900 * sizeof(int));
		break;
	case 3:
		realloc_addr = malloc(2000);
		realloc_addr = realloc(realloc_addr, 2000 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(2100);
		realloc_addr = realloc(realloc_addr, 2100 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(2200);
		realloc_addr = realloc(realloc_addr, 2200 * sizeof(int));
		realloc_addr = malloc(2300);
		realloc_addr = realloc(realloc_addr, 2300 * sizeof(int));
		realloc_addr = malloc(2400);
		realloc_addr = realloc(realloc_addr, 2400 * sizeof(int));
		break;
	case 4:
		realloc_addr = malloc(10);
		realloc_addr = realloc(realloc_addr, 10 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(20);
		realloc_addr = realloc(realloc_addr, 20 * sizeof(int));
		free(realloc_addr);
		realloc_addr = malloc(30);
		realloc_addr = realloc(realloc_addr, 30 * sizeof(int));
		realloc_addr = malloc(40);
		realloc_addr = realloc(realloc_addr, 40 * sizeof(int));
		realloc_addr = malloc(50);
		realloc_addr = realloc(realloc_addr, 50 * sizeof(int));
		realloc_addr = malloc(60);
		realloc_addr = realloc(realloc_addr, 60 * sizeof(int));
		break;
	default:
		break;
	}
}

void calloc_test(int type)
{
	int *calloc_addr;
	switch (type) {
	case 1:
		calloc_addr = calloc(100, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(200, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(300, sizeof(int));
		calloc_leak_cnt++;
		break;
	case 2:
		calloc_addr = calloc(400, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(500, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(600, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(700, sizeof(int));
		calloc_leak_cnt++;
		break;
	case 3:
		calloc_addr = calloc(800, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(900, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(1000, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(1100, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(1200, sizeof(int));
		calloc_leak_cnt++;
		break;
	case 4:
		calloc_addr = calloc(10, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(20, sizeof(int));
		calloc_leak_cnt++;
		free(calloc_addr);
		calloc_leak_cnt--;
		calloc_addr = calloc(30, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(40, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(50, sizeof(int));
		calloc_leak_cnt++;
		calloc_addr = calloc(60, sizeof(int));
		calloc_leak_cnt++;
		break;
	default:
		break;
	}
}

void malloc_test(int type)
{
	char *malloc_addr;
	switch (type) {
	case 1:
		malloc_addr = malloc(100);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(200);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(300);
		malloc_leak_cnt++;
		break;
	case 2:
		malloc_addr = malloc(400);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(500);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(600);
		malloc_leak_cnt++;
		malloc_addr = malloc(700);
		malloc_leak_cnt++;
		break;
	case 3:
		malloc_addr = malloc(800);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(900);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(1000);
		malloc_leak_cnt++;
		malloc_addr = malloc(1100);
		malloc_leak_cnt++;
		malloc_addr = malloc(1200);
		malloc_leak_cnt++;
		break;
	case 4:
		malloc_addr = malloc(10);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(20);
		malloc_leak_cnt++;
		free(malloc_addr);
		malloc_leak_cnt--;
		malloc_addr = malloc(30);
		malloc_leak_cnt++;
		malloc_addr = malloc(40);
		malloc_leak_cnt++;
		malloc_addr = malloc(50);
		malloc_leak_cnt++;
		malloc_addr = malloc(60);
		malloc_leak_cnt++;
		break;
	default:
		break;
	}
}

void parent_memory_alloc_test2(void)
{
	while (1) {
		malloc_test(2);
		calloc_test(2);
		realloc_test(2);
		mmap_test(2);
		sleep(10);
	}
}

#define CHILDREN_NAME "./test_child.elf"
void child_test(void)
{
	execl(CHILDREN_NAME, "test_child.elf", NULL);
}

void child_memory_alloc_test(void)
{
	unsigned int loop = 10;
	malloc_test(3);
	calloc_test(3);
	realloc_test(3);
	mmap_test(3);
	while (loop--) {
		malloc_test(4);
		calloc_test(4);
		realloc_test(4);
		mmap_test(4);
		sleep(10);
	}
}

void parent_memory_alloc_test1(void)
{
	malloc_test(1);
	calloc_test(1);
	realloc_test(1);
	mmap_test(1);
}

int main()
{
	pid_t child_pid1;
	pid_t child_pid2;

	parent_memory_alloc_test1();

	child_pid1 = fork();
	if (child_pid1 == 0) {
		child_memory_alloc_test();
	} else if (child_pid1 > 0) {
		child_pid2 = fork();
		if (child_pid2 == 0) {
			child_test();
		} else if (child_pid2 > 0) {
			parent_memory_alloc_test2();
		}
	}

	exit(1);
}
