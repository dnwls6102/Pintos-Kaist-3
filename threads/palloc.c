#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/init.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* 페이지 할당기. 페이지 크기(또는 페이지 배수)로 메모리를 나누어 제공합니다.
   더 작은 단위를 할당하는 할당기는 malloc.h를 참조하세요.

   시스템 메모리는 "커널 풀"과 "유저 풀"로 나뉩니다. 유저 풀은 사용자
   (가상) 메모리 페이지에 사용되며, 커널 풀은 그 외 모든 작업에 사용됩니다.
   이렇게 나누는 이유는 사용자 프로세스가 과도하게 스왑을 수행하더라도
   커널이 자체 작업을 위한 메모리를 확보할 수 있도록 하기 위함입니다.

   기본적으로 시스템 RAM의 절반은 커널 풀에, 나머지 절반은 유저 풀에 할당됩니다.
   이는 커널 풀에는 매우 넉넉한 할당이지만, 데모 용도로는 적합합니다. */

/* 메모리 풀 구조체 */
struct pool
{
	struct lock lock;		 /* 상호 배제를 위한 락 */
	struct bitmap *used_map; /* 사용된 페이지 비트맵 */
	uint8_t *base;			 /* 풀의 시작 주소 */
};

/* 커널 데이터와 사용자 페이지용 두 개의 메모리 풀 */
static struct pool kernel_pool, user_pool;

/* 유저 풀에 할당할 최대 페이지 수 */
size_t user_page_limit = SIZE_MAX;
static void
init_pool(struct pool *p, void **bm_base, uint64_t start, uint64_t end);

static bool page_from_pool(const struct pool *, void *page);

/* 멀티부트 정보 구조체 */
struct multiboot_info
{
	uint32_t flags;
	uint32_t mem_low;
	uint32_t mem_high;
	uint32_t __unused[8];
	uint32_t mmap_len;
	uint32_t mmap_base;
};

/* e820 엔트리 구조체 */
struct e820_entry
{
	uint32_t size;
	uint32_t mem_lo;
	uint32_t mem_hi;
	uint32_t len_lo;
	uint32_t len_hi;
	uint32_t type;
};

/* ext_mem/base_mem 범위 정보를 나타내는 구조체 */
struct area
{
	uint64_t start;
	uint64_t end;
	uint64_t size;
};

#define BASE_MEM_THRESHOLD 0x100000
#define USABLE 1
#define ACPI_RECLAIMABLE 3
#define APPEND_HILO(hi, lo) (((uint64_t)((hi)) << 32) + (lo))

/* e820 엔트리를 순회하며 basemem과 extmem 범위를 분석합니다. */
static void
resolve_area_info(struct area *base_mem, struct area *ext_mem)
{
	struct multiboot_info *mb_info = ptov(MULTIBOOT_INFO);
	struct e820_entry *entries = ptov(mb_info->mmap_base);
	uint32_t i;

	for (i = 0; i < mb_info->mmap_len / sizeof(struct e820_entry); i++)
	{
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE)
		{
			uint64_t start = APPEND_HILO(entry->mem_hi, entry->mem_lo);
			uint64_t size = APPEND_HILO(entry->len_hi, entry->len_lo);
			uint64_t end = start + size;
			printf("%llx ~ %llx %d\n", start, end, entry->type);

			struct area *area = start < BASE_MEM_THRESHOLD ? base_mem : ext_mem;

			// 이 영역에 속하는 첫 번째 엔트리
			if (area->size == 0)
			{
				*area = (struct area){
					.start = start,
					.end = end,
					.size = size,
				};
			}
			else
			{ // 그렇지 않은 경우
				// 시작 주소 확장
				if (area->start > start)
					area->start = start;
				// 끝 주소 확장
				if (area->end < end)
					area->end = end;
				// 크기 확장
				area->size += size;
			}
		}
	}
}

/*
 * 메모리 풀 초기화.
 * 모든 페이지는 이 할당기가 관리하며 코드 페이지도 포함됩니다.
 * 기본적으로 메모리의 절반은 커널에, 절반은 유저에 할당합니다.
 * 가능한 한 base_mem 부분을 커널에 밀어 넣습니다.
 */
static void
populate_pools(struct area *base_mem, struct area *ext_mem)
{
	extern char _end;
	void *free_start = pg_round_up(&_end);

	uint64_t total_pages = (base_mem->size + ext_mem->size) / PGSIZE;
	uint64_t user_pages = total_pages / 2 > user_page_limit ? user_page_limit : total_pages / 2;
	uint64_t kern_pages = total_pages - user_pages;

	// E820 맵을 분석하여 각 풀의 메모리 영역을 확보합니다.
	enum
	{
		KERN_START,
		KERN,
		USER_START,
		USER
	} state = KERN_START;
	uint64_t rem = kern_pages;
	uint64_t region_start = 0, end = 0, start, size, size_in_pg;

	struct multiboot_info *mb_info = ptov(MULTIBOOT_INFO);
	struct e820_entry *entries = ptov(mb_info->mmap_base);

	uint32_t i;
	for (i = 0; i < mb_info->mmap_len / sizeof(struct e820_entry); i++)
	{
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE)
		{
			start = (uint64_t)ptov(APPEND_HILO(entry->mem_hi, entry->mem_lo));
			size = APPEND_HILO(entry->len_hi, entry->len_lo);
			end = start + size;
			size_in_pg = size / PGSIZE;

			if (state == KERN_START)
			{
				region_start = start;
				state = KERN;
			}

			switch (state)
			{
			case KERN:
				if (rem > size_in_pg)
				{
					rem -= size_in_pg;
					break;
				}
				// 커널 풀 생성
				init_pool(&kernel_pool,
						  &free_start, region_start, start + rem * PGSIZE);
				// 다음 상태로 전환
				if (rem == size_in_pg)
				{
					rem = user_pages;
					state = USER_START;
				}
				else
				{
					region_start = start + rem * PGSIZE;
					rem = user_pages - size_in_pg + rem;
					state = USER;
				}
				break;
			case USER_START:
				region_start = start;
				state = USER;
				break;
			case USER:
				if (rem > size_in_pg)
				{
					rem -= size_in_pg;
					break;
				}
				ASSERT(rem == size);
				break;
			default:
				NOT_REACHED();
			}
		}
	}

	// 유저 풀 생성
	init_pool(&user_pool, &free_start, region_start, end);

	// e820_entry를 순회합니다. 사용 가능한 영역 설정
	uint64_t usable_bound = (uint64_t)free_start;
	struct pool *pool;
	void *pool_end;
	size_t page_idx, page_cnt;

	for (i = 0; i < mb_info->mmap_len / sizeof(struct e820_entry); i++)
	{
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE)
		{
			uint64_t start = (uint64_t)
				ptov(APPEND_HILO(entry->mem_hi, entry->mem_lo));
			uint64_t size = APPEND_HILO(entry->len_hi, entry->len_lo);
			uint64_t end = start + size;

			// TODO: 0x1000 ~ 0x200000 추가
			if (end < usable_bound)
				continue;

			start = (uint64_t)
				pg_round_up(start >= usable_bound ? start : usable_bound);
		split:
			if (page_from_pool(&kernel_pool, (void *)start))
				pool = &kernel_pool;
			else if (page_from_pool(&user_pool, (void *)start))
				pool = &user_pool;
			else
				NOT_REACHED();

			pool_end = pool->base + bitmap_size(pool->used_map) * PGSIZE;
			page_idx = pg_no(start) - pg_no(pool->base);
			if ((uint64_t)pool_end < end)
			{
				page_cnt = ((uint64_t)pool_end - start) / PGSIZE;
				bitmap_set_multiple(pool->used_map, page_idx, page_cnt, false);
				start = (uint64_t)pool_end;
				goto split;
			}
			else
			{
				page_cnt = ((uint64_t)end - start) / PGSIZE;
				bitmap_set_multiple(pool->used_map, page_idx, page_cnt, false);
			}
		}
	}
}

/* 페이지 할당기를 초기화하고 메모리 크기를 반환합니다 */
uint64_t
palloc_init(void)
{
	/* 링크에 의해 기록된 커널의 끝.
	   kernel.lds.S를 참조하세요. */
	extern char _end;
	struct area base_mem = {.size = 0};
	struct area ext_mem = {.size = 0};

	resolve_area_info(&base_mem, &ext_mem);
	printf("Pintos booting with: \n");
	printf("\tbase_mem: 0x%llx ~ 0x%llx (사용 가능: %'llu kB)\n",
		   base_mem.start, base_mem.end, base_mem.size / 1024);
	printf("\text_mem: 0x%llx ~ 0x%llx (사용 가능: %'llu kB)\n",
		   ext_mem.start, ext_mem.end, ext_mem.size / 1024);
	populate_pools(&base_mem, &ext_mem);
	return ext_mem.end;
}

/* 연속된 PAGE_CNT 개의 빈 페이지를 얻어서 반환합니다.
   PAL_USER가 설정되어 있으면 유저 풀에서 페이지를 얻고,
   그렇지 않으면 커널 풀에서 페이지를 얻습니다.
   FLAGS에 PAL_ZERO가 설정되어 있으면 페이지는 0으로 채워집니다.
   사용할 수 있는 페이지가 부족하면 null 포인터를 반환합니다.
   그러나 FLAGS에 PAL_ASSERT가 설정되어 있으면 커널 패닉이 발생합니다. */
void *
palloc_get_multiple(enum palloc_flags flags, size_t page_cnt)
{
	struct pool *pool = flags & PAL_USER ? &user_pool : &kernel_pool;

	lock_acquire(&pool->lock);
	size_t page_idx = bitmap_scan_and_flip(pool->used_map, 0, page_cnt, false);
	lock_release(&pool->lock);
	void *pages;

	if (page_idx != BITMAP_ERROR)
		pages = pool->base + PGSIZE * page_idx;
	else
		pages = NULL;

	if (pages)
	{
		if (flags & PAL_ZERO)
			memset(pages, 0, PGSIZE * page_cnt);
	}
	else
	{
		if (flags & PAL_ASSERT)
			PANIC("palloc_get: out of pages");
	}

	return pages;
}

/* 단일 빈 페이지를 얻고 해당 커널 가상 주소를 반환합니다.
   PAL_USER가 설정되어 있으면 유저 풀에서 페이지를 얻고,
   그렇지 않으면 커널 풀에서 페이지를 얻습니다.
   FLAGS에 PAL_ZERO가 설정되어 있으면 페이지가 0으로 채워집니다.
   사용할 수 있는 페이지가 없으면 null 포인터를 반환합니다.
   그러나 FLAGS에 PAL_ASSERT가 설정되어 있으면 커널 패닉이 발생합니다. */
void *
palloc_get_page(enum palloc_flags flags)
{
	return palloc_get_multiple(flags, 1);
}

/* PAGES부터 시작하는 PAGE_CNT 개의 페이지를 해제합니다. */
void palloc_free_multiple(void *pages, size_t page_cnt)
{
	struct pool *pool;
	size_t page_idx;

	ASSERT(pg_ofs(pages) == 0);
	if (pages == NULL || page_cnt == 0)
		return;

	if (page_from_pool(&kernel_pool, pages))
		pool = &kernel_pool;
	else if (page_from_pool(&user_pool, pages))
		pool = &user_pool;
	else
		NOT_REACHED();

	page_idx = pg_no(pages) - pg_no(pool->base);

#ifndef NDEBUG
	memset(pages, 0xcc, PGSIZE * page_cnt);
#endif
	ASSERT(bitmap_all(pool->used_map, page_idx, page_cnt));
	bitmap_set_multiple(pool->used_map, page_idx, page_cnt, false);
}

/* PAGE에 있는 단일 페이지를 해제합니다. */
void palloc_free_page(void *page)
{
	palloc_free_multiple(page, 1);
}

/* START에서 END까지 P를 초기화합니다. */
static void
init_pool(struct pool *p, void **bm_base, uint64_t start, uint64_t end)
{
	/* 풀의 used_map을 해당 풀의 시작 주소에 배치합니다.
	   비트맵에 필요한 공간을 계산하고
	   풀의 크기에서 이를 뺍니다. */
	uint64_t pgcnt = (end - start) / PGSIZE;
	size_t bm_pages = DIV_ROUND_UP(bitmap_buf_size(pgcnt), PGSIZE) * PGSIZE;

	lock_init(&p->lock);
	p->used_map = bitmap_create_in_buf(pgcnt, *bm_base, bm_pages);
	p->base = (void *)start;

	// 모든 페이지를 사용 불가능 상태로 설정합니다.
	bitmap_set_all(p->used_map, true);

	*bm_base += bm_pages;
}

/* PAGE가 POOL에서 할당되었으면 true를 반환하고,
   그렇지 않으면 false를 반환합니다. */
static bool
page_from_pool(const struct pool *pool, void *page)
{
	size_t page_no = pg_no(page);
	size_t start_page = pg_no(pool->base);
	size_t end_page = start_page + bitmap_size(pool->used_map);
	return page_no >= start_page && page_no < end_page;
}
