/* define the APP ARCH
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
#ifndef _ARCH_H
#define _ARCH_H

#if 0
/* If you want to trace X86_64 APP */
//#define X86_64

/* If you want to trace X86_32 APP */
//#define X86_32

/* If you want to trace PPC_64 APP */
//#define PPC64

/* If you want to trace PPC_32 APP */
//#define PPC32

/* If you want to trace MIPS_32 APP on 32bit CPU */
//#define MIPS32

/* If you want to trace MIPS_64 APP on 64bit CPU */
//#define MIPS64_64

/* If you want to trace MIPS_32 APP on 64bit CPU(N32 ABI) */
//#define MIPS64_N32

/* If you want to trace MIPS_32 APP on 64bit CPU(O32 ABI) */
//#define MIPS64_O32

/* If you want to trace ARM_32 APP on 32bit CPU*/
//#define ARM32
/* If your APP is build with EABI toolchain, please define it */
//#define EABI

/* If you want to trace ARM_64 APP */
//#define ARM64_64

/* If you want to trace ARM_32 APP on 64bit CPU*/
//#define ARM64_32
#endif

#define X86_64
//#define PPC32
//#define PPC64
//#define ARM64_64
//#define ARM32
//#define EABI
//#define MIPS64_64
//#define MIPS32

#endif
