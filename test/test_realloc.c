#include <stdlib.h>
#include <unistd.h>


/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_realloc.elf
 * Test result: There are no any leak memory,
 * so the $PID.doubtful.$timestamp.log, $PID_total*.log are all empty files.
 * */

int main()
{
	int *realloc_addr0 =  NULL;
	int *realloc_addr1 =  NULL;
	int *realloc_addr2 =  NULL;

	realloc_addr0 = malloc(100);
	realloc_addr0 = realloc(realloc_addr0, 100 * sizeof(int));
	sleep(4);
	realloc_addr0 = malloc(200);
	realloc_addr0 = realloc(realloc_addr0, 200 * sizeof(int));
	sleep(4);
	realloc_addr0 = malloc(300);
	realloc_addr0 = realloc(realloc_addr0, 300 * sizeof(int));
	sleep(4);
	free(realloc_addr1);
	sleep(4);
	free(realloc_addr0);
	sleep(4);
	free(realloc_addr2);

	sleep(10);

	return 0;
}
