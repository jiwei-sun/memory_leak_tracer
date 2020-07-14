#include <sys/mman.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_mmap.elf
 * Test result: There are no any leak memory,
 * so the $PID.doubtful.$timestamp.log, $PID_total*.log are all empty files.
 * */

#define MEM_SIZE	(2048)
int main()
{
	char *mem0 = NULL;
	char *mem1 = NULL;
	char *mem2 = NULL;

	mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sleep(4);

	mem1 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sleep(4);

	mem2 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sleep(4);

	munmap(mem0, 1 * MEM_SIZE);
	sleep(4);
	munmap(mem1, 2 * MEM_SIZE);
	sleep(4);
	munmap(mem2, 3 * MEM_SIZE);
	sleep(10);

	return 0;
}
