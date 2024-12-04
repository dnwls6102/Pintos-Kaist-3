#ifndef THREADS_VADDR_H
#define THREADS_VADDR_H

#include <debug.h>
#include <stdint.h>
#include <stdbool.h>

#include "threads/loader.h"

/* Functions and macros for working with virtual addresses.
 *
 * See pte.h for functions and macros specifically for x86
 * hardware page tables. */

/* Functions and macros for working with x86 hardware page tables.
 * See vaddr.h for more generic functions and macros for virtual addresses.
 *
 * Virtual addresses are structured as follows:
 *  63          48 47            39 38            30 29            21 20         12 11         0
 * +-------------+----------------+----------------+----------------+-------------+------------+
 * | Sign Extend |    Page-Map    | Page-Directory | Page-directory |  Page-Table |  Physical  |
 * |             | Level-4 Offset |    Pointer     |     Offset     |   Offset    |   Offset   |
 * +-------------+----------------+----------------+----------------+-------------+------------+
 *               |                |                |                |             |            |
 *               +------- 9 ------+------- 9 ------+------- 9 ------+----- 9 -----+---- 12 ----+
 *                                         Virtual Address
 */

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))

/* Page offset (bits 0:12). */
#define PGSHIFT 0						/* Index of first offset bit. */
#define PGBITS 12						/* Number of offset bits. */
#define PGSIZE (1 << PGBITS)			/* Bytes in a page. */
#define PGMASK BITMASK(PGSHIFT, PGBITS) /* Page offset bits (0:12). */

/* Offset within a page. */
#define pg_ofs(va) ((uint64_t)(va) & PGMASK)

#define pg_no(va) ((uint64_t)(va) >> PGBITS)

/* Round up to nearest page boundary. */
#define pg_round_up(va) ((void *)(((uint64_t)(va) + PGSIZE - 1) & ~PGMASK))

/* Round down to nearest page boundary. */
#define pg_round_down(va) (void *)((uint64_t)(va) & ~PGMASK)

/* Kernel virtual address start */
#define KERN_BASE LOADER_KERN_BASE

/* User stack start */
#define USER_STACK 0x47480000

/* Returns true if VADDR is a user virtual address. */
#define is_user_vaddr(vaddr) (!is_kernel_vaddr((vaddr)))

/* Returns true if VADDR is a kernel virtual address. */
#define is_kernel_vaddr(vaddr) ((uint64_t)(vaddr) >= KERN_BASE)

// FIXME: add checking
/* Returns kernel virtual address at which physical address PADDR
 *  is mapped. */
#define ptov(paddr) ((void *)(((uint64_t)paddr) + KERN_BASE))

/* Returns physical address at which kernel virtual address VADDR
 * is mapped. */
#define vtop(vaddr)                                \
	({                                             \
		ASSERT(is_kernel_vaddr(vaddr));            \
		((uint64_t)(vaddr) - (uint64_t)KERN_BASE); \
	})

#endif /* threads/vaddr.h */
