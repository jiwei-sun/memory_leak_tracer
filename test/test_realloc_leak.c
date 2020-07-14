#include <stdlib.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_realloc_leak.elf
 * Test result: Total memory leaks 4 * 400 bytes and 4 * 1200 bytes.
 *
 * $cat $PID_total.doubtful.log
 *
 * Call Trace counter: 4
 * ../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
 * ../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
 * ./test_realloc_leak.elf[0x4006b7]
 * /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
 * ./test_realloc_leak.elf[0x400549]
 *
 * Call Trace counter: 4
 * ../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
 * ../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
 * ./test_realloc_leak.elf[0x400647]
 * /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
 * ./test_realloc_leak.elf[0x400549]
 *
 * $ cat $PID_total.log
 *
 realloc addr 0x2376bf0, len 400, time_stamp:1565012355
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x400647]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x2377f40, len 1200, time_stamp:1565012361
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x4006b7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x2377540, len 400, time_stamp:1565012367
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x400647]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x2379360, len 1200, time_stamp:1565012373
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x4006b7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x2378870, len 400, time_stamp:1565012379
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x400647]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x237a0f0, len 1200, time_stamp:1565012385
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x4006b7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x2379830, len 400, time_stamp:1565012391
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x400647]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]


 realloc addr 0x237ae80, len 1200, time_stamp:1565012397
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f7aac31911d]
../src/libmem_leak_tracer.so(realloc+0x1db)[0x7f7aac31ac19]
./test_realloc_leak.elf[0x4006b7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f7aabf70f45]
./test_realloc_leak.elf[0x400549]
 *
 * */
int main()
{
	char *realloc_addr0;
	unsigned int i = 0;

	for (i = 0; i < 4; i++) {
		realloc_addr0 = malloc(100);
		realloc_addr0 = realloc(realloc_addr0, 100 * sizeof(int));
		sleep(2);
		realloc_addr0 = malloc(200);
		realloc_addr0 = realloc(realloc_addr0, 200 * sizeof(int));
		sleep(2);
		free(realloc_addr0);
		sleep(2);
		realloc_addr0 = malloc(300);
		realloc_addr0 = realloc(realloc_addr0, 300 * sizeof(int));
		sleep(2);
		realloc_addr0 = malloc(400);
		realloc_addr0 = realloc(realloc_addr0, 400 * sizeof(int));
		sleep(2);
		free(realloc_addr0);
		sleep(2);
	}
	sleep(10);

	return 0;
}
