#include <stdlib.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_calloc_leak.elf
 * Test result: Total memory leaks 4 * 400 bytes and 4 * 1200 bytes.
 *
 *
$ cat *_total.log


 calloc addr 0x1f98020, len 400, time_stamp:1565013360
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x4005e7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f994f0, len 1200, time_stamp:1565013366
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x400637]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f999c0, len 400, time_stamp:1565013372
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x4005e7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f9a710, len 1200, time_stamp:1565013378
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x400637]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f99dd0, len 400, time_stamp:1565013384
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x4005e7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f9b180, len 1200, time_stamp:1565013390
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x400637]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f9b650, len 400, time_stamp:1565013396
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x4005e7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


 calloc addr 0x1f9bda0, len 1200, time_stamp:1565013402
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x400637]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]
 *
$ cat *_total.doubtful.log


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x400637]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f375816011d]
../src/libmem_leak_tracer.so(calloc+0x11b)[0x7f3758161945]
./test_calloc_leak.elf[0x4005e7]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f3757db7f45]
./test_calloc_leak.elf[0x4004f9]

 *
 * The $PID*.doubtful.* are all empty files.
 * */

int main()
{
	int *calloc_addr0;
	unsigned int i = 0;

	for (i = 0; i < 4; i++) {
		calloc_addr0 = calloc(100, sizeof(int));
		sleep(2);
		calloc_addr0 = calloc(200, sizeof(int));
		sleep(2);
		free(calloc_addr0);
		sleep(2);
		calloc_addr0 = calloc(300, sizeof(int));
		sleep(2);
		calloc_addr0 = calloc(400, sizeof(int));
		sleep(2);
		free(calloc_addr0);
		sleep(2);

	}
	sleep(10);

	return 0;
}
