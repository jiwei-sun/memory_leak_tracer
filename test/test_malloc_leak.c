#include <stdlib.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_malloc_leak.elf
 * Test result: Total memory leaks 4 * 100 bytes and 4 * 300 bytes.
 *
 *
$ cat *_total.log


 malloc addr 0xdf6020, len 100, time_stamp:1565013566
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x4005e2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf7160, len 300, time_stamp:1565013572
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x400628]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf6bf0, len 100, time_stamp:1565013578
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x4005e2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf74e0, len 300, time_stamp:1565013584
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x400628]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf7d80, len 100, time_stamp:1565013590
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x4005e2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf83f0, len 300, time_stamp:1565013596
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x400628]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf7e00, len 100, time_stamp:1565013602
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x4005e2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


 malloc addr 0xdf8540, len 300, time_stamp:1565013608
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x400628]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]
 *
 *
$ cat *_total.doubtful.log


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x400628]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f4e2300c11d]
../src/libmem_leak_tracer.so(malloc+0x103)[0x7f4e2300d654]
./test_malloc_leak.elf[0x4005e2]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f4e22c63f45]
./test_malloc_leak.elf[0x4004f9]
 *
 * The $PID*.doubtful.* are all empty files.
 * */

int main()
{
	char *malloc_addr0;
	unsigned int i = 0;

	for (i = 0; i < 4; i++) {
		malloc_addr0 = malloc(100);
		sleep(2);
		malloc_addr0 = malloc(200);
		sleep(2);
		free(malloc_addr0);
		sleep(2);
		malloc_addr0 = malloc(300);
		sleep(2);
		malloc_addr0 = malloc(400);
		sleep(2);
		free(malloc_addr0);
		sleep(2);
	}
	sleep(10);

	return 0;
}
