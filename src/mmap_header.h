/* mmap header file
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
#ifndef _MMAP_HEADER_H
#define _MMAP_HEADER_H

#ifdef X86_64
/* For X86_64 */
#define __NR_mmap	(9)
#define __NR_munmap	(11)
/*There is no mmap2 in 64bit arch*/
#define __NR_mmap2	__NR_mmap
#endif

#ifdef X86_32
/* For X86_32 */
#define __NR_mmap	(90)
#define __NR_munmap	(91)
#define __NR_mmap2	(192)
#endif

#ifdef PPC64
/* For PPC64 */
#define __NR_mmap	(90)
#define __NR_munmap	(91)
/*There is no mmap2 in 64bit arch*/
#define __NR_mmap2	__NR_mmap
#endif

#ifdef PPC32
/* For PPC32 */
#define __NR_mmap	(90)
#define __NR_munmap	(91)
#define __NR_mmap2	(192)
#endif

#ifdef MIPS64_N32
/* For MIPS64_N32 */
#define __NR_mmap	(6009)
#define __NR_munmap	(6011)
/*There is no mmap2 in 64bit arch*/
#define __NR_mmap2	__NR_mmap
#endif

#ifdef MIPS64_O32
/* For MIPS64_N32 */
#define __NR_mmap	(4090)
#define __NR_munmap	(4091)
#define __NR_mmap2	(4210)
#endif

#ifdef MIPS64_64
/* For MIPS64_64 */
#define	__NR_mmap	(5009)
#define __NR_munmap	(5011)
/*There is no mmap2 in 64bit arch*/
#define __NR_mmap2	__NR_mmap
#endif

#ifdef MIPS32
/* For MIPS32 */
#define	__NR_mmap	(4090)
#define	__NR_munmap	(4091)
#define	__NR_mmap2	(4210)
#endif

#ifdef ARM64_32
/* For ARM64_32 */
#define __NR_munmap	(91)
#define __NR_mmap	(1058)
#define __NR_mmap2	(192)
#endif

#ifdef ARM64_64
/* For ARM64_64 */
#define __NR_mmap	(222)
#define __NR_munmap	(215)
#define __NR_mmap2	(__NR_mmap)
#endif

#ifdef ARM32
/* For ARM32 */
#ifndef EABI
#define	__NR_mmap	(0x900000 + 90)
#define	__NR_munmap	(0x900000 + 91)
#define	__NR_mmap2	(0x900000 + 192)
#else
#define __NR_mmap	(90)
#define __NR_munmap	(91)
#define __NR_mmap2	(192)
#endif
#endif

#endif
