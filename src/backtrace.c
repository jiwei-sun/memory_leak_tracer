/* get backtrace
 *
 * Copyright (C) 2019 Sun Jiwei <jiwei.sun.bj@qq.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#include <execinfo.h>

/* Just support glibc since version 2.1,
 * If you want to use the tool on non-glibc or
 * there is no backtrace() when you use the tool,
 * Please rewrite the following two functions.
 * They can work on X86_64, and PPC32, but for ARM(32bit, 64bit),
 * MIPS(32bit, 64bit), we need rewrite the two functions
 * */
void mem_leak_backtrace_symbols_fd(void *const *buffer, int size, int fd)
{
	backtrace_symbols_fd(buffer, size, fd);
}

int mem_leak_backtrace(void **buffer, int size)
{
	int ret;

	ret = backtrace(buffer, size);

	return ret;
}

