#include <stdlib.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_malloc.elf
 * Test result: There are no any leak memory,
 * so the $PID.doubtful.$timestamp.log, $PID_total*.log are all empty files.
 * */

int main()
{
	char *malloc_addr0, *malloc_addr1, *malloc_addr2;

	malloc_addr0 = malloc(100);
	sleep(4);
	malloc_addr1 = malloc(200);
	sleep(4);
	malloc_addr2 = malloc(300);
	sleep(4);
	free(malloc_addr1);
	sleep(4);
	free(malloc_addr0);
	sleep(4);
	free(malloc_addr2);

	sleep(10);

	return 0;
}
