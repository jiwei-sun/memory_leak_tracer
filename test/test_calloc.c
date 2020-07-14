#include <stdlib.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_calloc.elf
 * Test result: There are no any leak memory,
 * so the $PID.doubtful.$timestamp.log, $PID_total*.log are all empty files.
 * */

int main()
{
	int *calloc_addr0, *calloc_addr1, *calloc_addr2;

	calloc_addr0 = calloc(100, sizeof(int));
	sleep(4);
	calloc_addr1 = calloc(200, sizeof(int));
	sleep(4);
	calloc_addr2 = calloc(300, sizeof(int));
	sleep(4);
	free(calloc_addr1);
	sleep(4);
	free(calloc_addr0);
	sleep(4);
	free(calloc_addr2);

	sleep(10);

	return 0;
}
