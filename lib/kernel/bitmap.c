#include "bitmap.h"
#include <debug.h>
#include <limits.h>
#include <round.h>
#include <stdio.h>
#include "threads/malloc.h"
#ifdef FILESYS
#include "filesys/file.h"
#endif

/* 요소 타입.

   이것은 최소한 int와 같은 크기의 부호 없는 정수 타입이어야 합니다.

   각 비트는 비트맵의 하나의 비트를 나타냅니다.
   요소의 비트 0이 비트맵의 비트 K를 나타내면,
   요소의 비트 1은 비트맵의 비트 K+1을 나타내고,
   계속해서 그렇게 됩니다. */
typedef unsigned long elem_type;

/* 요소의 비트 수. */
#define ELEM_BITS (sizeof(elem_type) * CHAR_BIT)

/* 외부에서 볼 때, 비트맵은 비트의 배열입니다. 내부적으로는
   비트를 시뮬레이션하는 elem_type의 배열입니다. */
struct bitmap
{
	size_t bit_cnt;	 /* 비트 수. */
	elem_type *bits; /* 비트를 나타내는 요소들. */
};

/* BIT_IDX 번호의 비트를 포함하는 요소의 인덱스를 반환합니다. */
static inline size_t
elem_idx(size_t bit_idx)
{
	return bit_idx / ELEM_BITS;
}

/* BIT_IDX에 해당하는 비트만 켜진 elem_type을 반환합니다. */
static inline elem_type
bit_mask(size_t bit_idx)
{
	return (elem_type)1 << (bit_idx % ELEM_BITS);
}

/* BIT_CNT 비트에 필요한 요소의 수를 반환합니다. */
static inline size_t
elem_cnt(size_t bit_cnt)
{
	return DIV_ROUND_UP(bit_cnt, ELEM_BITS);
}

/* BIT_CNT 비트에 필요한 바이트 수를 반환합니다. */
static inline size_t
byte_cnt(size_t bit_cnt)
{
	return sizeof(elem_type) * elem_cnt(bit_cnt);
}

/* B의 비트에서 실제로 사용된 마지막 요소의 비트를 1로 설정하고 나머지는 0으로 설정한 비트 마스크를 반환합니다. */
static inline elem_type
last_mask(const struct bitmap *b)
{
	int last_bits = b->bit_cnt % ELEM_BITS;
	return last_bits ? ((elem_type)1 << last_bits) - 1 : (elem_type)-1;
}

/* 생성 및 파괴. */

/* B를 BIT_CNT 비트의 비트맵으로 초기화하고
   모든 비트를 false로 설정합니다.
   성공하면 true를 반환하고, 메모리 할당 실패 시 false를 반환합니다. */
struct bitmap *
bitmap_create(size_t bit_cnt)
{
	struct bitmap *b = malloc(sizeof *b);
	if (b != NULL)
	{
		b->bit_cnt = bit_cnt;
		b->bits = malloc(byte_cnt(bit_cnt));
		if (b->bits != NULL || bit_cnt == 0)
		{
			bitmap_set_all(b, false);
			return b;
		}
		free(b);
	}
	return NULL;
}

/* BIT_CNT 비트의 비트맵을 BLOCK에 미리 할당된 BLOCK_SIZE 바이트의 저장소에 생성하고 반환합니다.
   BLOCK_SIZE는 bitmap_needed_bytes(BIT_CNT) 이상이어야 합니다. */
struct bitmap *
bitmap_create_in_buf(size_t bit_cnt, void *block, size_t block_size UNUSED)
{
	struct bitmap *b = block;

	ASSERT(block_size >= bitmap_buf_size(bit_cnt));

	b->bit_cnt = bit_cnt;
	b->bits = (elem_type *)(b + 1);
	bitmap_set_all(b, false);
	return b;
}

/* bitmap_create_in_buf()와 함께 사용할 BIT_CNT 비트를 수용하는 데 필요한 바이트 수를 반환합니다. */
size_t
bitmap_buf_size(size_t bit_cnt)
{
	return sizeof(struct bitmap) + byte_cnt(bit_cnt);
}

/* 비트맵 B를 파괴하고 그 저장소를 해제합니다.
   bitmap_create_preallocated()로 생성된 비트맵에서는 사용하지 않습니다. */
void bitmap_destroy(struct bitmap *b)
{
	if (b != NULL)
	{
		free(b->bits);
		free(b);
	}
}

/* 비트맵 크기. */

/* B의 비트 수를 반환합니다. */
size_t
bitmap_size(const struct bitmap *b)
{
	return b->bit_cnt;
}

/* 단일 비트 설정 및 테스트. */

/* B에서 IDX 번호의 비트를 VALUE로 원자적으로 설정합니다. */
void bitmap_set(struct bitmap *b, size_t idx, bool value)
{
	ASSERT(b != NULL);
	ASSERT(idx < b->bit_cnt);
	if (value)
		bitmap_mark(b, idx);
	else
		bitmap_reset(b, idx);
}

/* B에서 BIT_IDX 번호의 비트를 true로 원자적으로 설정합니다. */
void bitmap_mark(struct bitmap *b, size_t bit_idx)
{
	size_t idx = elem_idx(bit_idx);
	elem_type mask = bit_mask(bit_idx);

	/* 이것은 `b->bits[idx] |= mask'와 동등하지만,
	   단일 프로세서 머신에서 원자성을 보장합니다. [IA32-v2b]의 OR 명령 설명을 참조하십시오. */
	asm("lock orq %1, %0" : "=m"(b->bits[idx]) : "r"(mask) : "cc");
}

/* B에서 BIT_IDX 번호의 비트를 false로 원자적으로 설정합니다. */
void bitmap_reset(struct bitmap *b, size_t bit_idx)
{
	size_t idx = elem_idx(bit_idx);
	elem_type mask = bit_mask(bit_idx);

	/* 이것은 `b->bits[idx] &= ~mask'와 동등하지만,
	   단일 프로세서 머신에서 원자성을 보장합니다. [IA32-v2a]의 AND 명령 설명을 참조하십시오. */
	asm("lock andq %1, %0" : "=m"(b->bits[idx]) : "r"(~mask) : "cc");
}

/* B에서 IDX 번호의 비트를 원자적으로 토글합니다;
   즉, true이면 false로 만들고,
   false이면 true로 만듭니다. */
void bitmap_flip(struct bitmap *b, size_t bit_idx)
{
	size_t idx = elem_idx(bit_idx);
	elem_type mask = bit_mask(bit_idx);

	/* 이것은 `b->bits[idx] ^= mask'와 동등하지만,
	   단일 프로세서 머신에서 원자성을 보장합니다. [IA32-v2b]의 XOR 명령 설명을 참조하십시오. */
	asm("lock xorq %1, %0" : "=m"(b->bits[idx]) : "r"(mask) : "cc");
}

/* B에서 IDX 번호의 비트 값을 반환합니다. */
bool bitmap_test(const struct bitmap *b, size_t idx)
{
	ASSERT(b != NULL);
	ASSERT(idx < b->bit_cnt);
	return (b->bits[elem_idx(idx)] & bit_mask(idx)) != 0;
}

/* 여러 비트 설정 및 테스트. */

/* B의 모든 비트를 VALUE로 설정합니다. */
void bitmap_set_all(struct bitmap *b, bool value)
{
	ASSERT(b != NULL);

	bitmap_set_multiple(b, 0, bitmap_size(b), value);
}

/* B에서 START에서 시작하여 CNT 비트를 VALUE로 설정합니다. */
void bitmap_set_multiple(struct bitmap *b, size_t start, size_t cnt, bool value)
{
	size_t i;

	ASSERT(b != NULL);
	ASSERT(start <= b->bit_cnt);
	ASSERT(start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		bitmap_set(b, start + i, value);
}

/* START와 START + CNT 사이의 B에서 VALUE로 설정된 비트 수를 반환합니다. */
size_t
bitmap_count(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
	size_t i, value_cnt;

	ASSERT(b != NULL);
	ASSERT(start <= b->bit_cnt);
	ASSERT(start + cnt <= b->bit_cnt);

	value_cnt = 0;
	for (i = 0; i < cnt; i++)
		if (bitmap_test(b, start + i) == value)
			value_cnt++;
	return value_cnt;
}

/* START와 START + CNT 사이의 B에서 VALUE로 설정된 비트가 있는지 확인하고, 있으면 true를 반환합니다. */
bool bitmap_contains(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
	size_t i;

	ASSERT(b != NULL);
	ASSERT(start <= b->bit_cnt);
	ASSERT(start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		if (bitmap_test(b, start + i) == value)
			return true;
	return false;
}

/* START와 START + CNT 사이의 B에서 true로 설정된 비트가 있는지 확인하고, 있으면 true를 반환합니다. */
bool bitmap_any(const struct bitmap *b, size_t start, size_t cnt)
{
	return bitmap_contains(b, start, cnt, true);
}

/* START와 START + CNT 사이의 B에서 true로 설정된 비트가 없는지 확인하고, 없으면 true를 반환합니다. */
bool bitmap_none(const struct bitmap *b, size_t start, size_t cnt)
{
	return !bitmap_contains(b, start, cnt, true);
}

/* START와 START + CNT 사이의 B에서 모든 비트가 true로 설정되어 있는지 확인하고, 그렇다면 true를 반환합니다. */
bool bitmap_all(const struct bitmap *b, size_t start, size_t cnt)
{
	return !bitmap_contains(b, start, cnt, false);
}

/* 설정된 비트 또는 설정되지 않은 비트 찾기. */

/* B에서 START 이후의 첫 번째 CNT 개의 연속 비트 그룹을 찾아서 반환합니다.
   모든 비트가 VALUE로 설정되어 있으면, 그 시작 인덱스를 반환합니다.
   그런 그룹이 없으면 BITMAP_ERROR를 반환합니다. */
size_t
bitmap_scan(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
	ASSERT(b != NULL);
	ASSERT(start <= b->bit_cnt);

	if (cnt <= b->bit_cnt)
	{
		size_t last = b->bit_cnt - cnt;
		size_t i;
		for (i = start; i <= last; i++)
			if (!bitmap_contains(b, i, cnt, !value))
				return i;
	}
	return BITMAP_ERROR;
}

/* B에서 START 이후의 첫 번째 CNT 개의 연속 비트 그룹을 찾아서,
   모두 !VALUE로 플립하고, 그룹의 첫 번째 비트 인덱스를 반환합니다.
   그런 그룹이 없으면 BITMAP_ERROR를 반환합니다.
   CNT가 0이면 0을 반환합니다.
   비트는 원자적으로 설정되지만, 비트를 테스트하는 것은 비트를 설정하는 것과 원자적이지 않습니다. */
size_t
bitmap_scan_and_flip(struct bitmap *b, size_t start, size_t cnt, bool value)
{
	size_t idx = bitmap_scan(b, start, cnt, value);
	if (idx != BITMAP_ERROR)
		bitmap_set_multiple(b, idx, cnt, !value);
	return idx;
}

/* 파일 입출력. */

#ifdef FILESYS
/* B를 파일에 저장하는 데 필요한 바이트 수를 반환합니다. */
size_t
bitmap_file_size(const struct bitmap *b)
{
	return byte_cnt(b->bit_cnt);
}

/* FILE에서 B를 읽습니다. 성공하면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool bitmap_read(struct bitmap *b, struct file *file)
{
	bool success = true;
	if (b->bit_cnt > 0)
	{
		off_t size = byte_cnt(b->bit_cnt);
		success = file_read_at(file, b->bits, size, 0) == size;
		b->bits[elem_cnt(b->bit_cnt) - 1] &= last_mask(b);
	}
	return success;
}

/* FILE에 B를 씁니다. 성공하면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
bool bitmap_write(const struct bitmap *b, struct file *file)
{
	off_t size = byte_cnt(b->bit_cnt);
	return file_write_at(file, b->bits, size, 0) == size;
}
#endif /* FILESYS */

/* 디버깅. */

/* B의 내용을 16진수로 콘솔에 덤프합니다. */
void bitmap_dump(const struct bitmap *b)
{
	hex_dump(0, b->bits, byte_cnt(b->bit_cnt), false);
}