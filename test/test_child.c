#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void fun1(char *mem)
{
	memset(mem, 0x0, 1024);
}

int main()
{
	char *mem_pool = malloc(100 * 1024 * 1024);
	char *mem_addr = malloc(1024);
	fun1(mem_addr);

	while(1) {
		char * mem = malloc(100);
		sleep(10);
		free(mem);
	}

	free(mem_addr);
	free(mem_pool);

	return 0;
}
