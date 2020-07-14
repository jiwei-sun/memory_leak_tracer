#include <sys/mman.h>
#include <unistd.h>

/* LD_PRELOAD=../src/libmem_leak_tracer.so MEM_LEAK_LOOP_TIME=2 ./test_mmap_leak.elf
 * Test result: Total memory leaks 4 * 2048 bytes and 4 * 3 * 2048 bytes.
 *
 *
$ cat *_total.doubtful.log


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400686]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


Call Trace counter: 4
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400605]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]
 *
 *
$ cat *_total.log


 mmap addr 0x7f99f5707000, len 2048, time_stamp:1565013937
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400605]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f5705000, len 6144, time_stamp:1565013943
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400686]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f5704000, len 2048, time_stamp:1565013949
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400605]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f5702000, len 6144, time_stamp:1565013955
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400686]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f5701000, len 2048, time_stamp:1565013961
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400605]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f56ff000, len 6144, time_stamp:1565013967
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400686]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f56fe000, len 2048, time_stamp:1565013973
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400605]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]


 mmap addr 0x7f99f56fc000, len 6144, time_stamp:1565013979
../src/libmem_leak_tracer.so(mem_leak_backtrace+0x20)[0x7f99f52e011d]
../src/libmem_leak_tracer.so(mmap+0x108)[0x7f99f52e118b]
./test_mmap_leak.elf[0x400686]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf5)[0x7f99f4f37f45]
./test_mmap_leak.elf[0x4004f9]
 *
 * The $PID*.doubtful.* are all empty files.
 * */
#define MEM_SIZE	(2048)
int main()
{
	char *mem0 = NULL;

	unsigned int i = 0;

	for (i = 0; i < 4; i++) {
		mem0 = mmap(NULL, 1 * MEM_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		sleep(2);

		mem0 = mmap(NULL, 2 * MEM_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		sleep(2);

		munmap(mem0, 2 * MEM_SIZE);

		sleep(2);

		mem0 = mmap(NULL, 3 * MEM_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		sleep(2);
		mem0 = mmap(NULL, 4 * MEM_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		sleep(2);

		munmap(mem0, 4 * MEM_SIZE);
		sleep(2);
	}

	sleep(10);

	return 0;
}
