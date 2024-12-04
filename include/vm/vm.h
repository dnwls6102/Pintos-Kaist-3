#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include "hash.h"

enum vm_type
{
	/* 초기화되지 않은 페이지 */
	VM_UNINIT = 0,
	/* 파일과 관련되지 않은 페이지, 즉 익명 페이지 */
	VM_ANON = 1,
	/* 파일과 관련된 페이지 */
	VM_FILE = 2,
	/* 페이지 캐시를 보유하는 페이지, 프로젝트 4용 */
	VM_PAGE_CACHE = 3,

	/* 상태를 저장하기 위한 비트 플래그 */

	/* 정보를 저장하기 위한 보조 비트 플래그 마커.
	 * int에 값을 담을 수 있는 한, 더 많은 마커를 추가할 수 있습니다. */
	VM_MARKER_0 = (1 << 3), // 0000 1000 (8)
	VM_MARKER_1 = (1 << 4), // 0001 0000 (16)

	/* 이 값을 초과하지 마십시오. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* "페이지"의 표현.
 * 이 구조체는 네 가지 "자식 클래스"를 가지는 일종의 "부모 클래스"입니다.
 * 자식 클래스는 uninit_page, file_page, anon_page, 그리고 페이지 캐시(project4)입니다.
 * 이 구조체의 사전 정의된 멤버를 제거하거나 수정하지 마십시오. */
struct page
{
	const struct page_operations *operations;
	void *va;			 /* 사용자 공간 관점의 주소 */
	struct frame *frame; /* 프레임에 대한 역참조 */

	/* 구현 영역 */
	/* Project 03 - Memory Management */
	// not_present: 해당 페이지가 물리 메모리에 로드되지 않았거나, 페이지 테이블에서 해당 페이지에 대한 엔트리가 없음
	bool not_present;	/* True: not-present page, false: writing r/o page.*/
	bool writable;		/* True: access was write, false: access was read. */
	bool user;			/* True: access by user, false: access by kernel. */
	uint64_t data_size; // page data 크기

	struct hash_elem page_table_elem; // hash 테이블에 포함되기 위함

	/* 각 유형의 데이터는 union에 바인딩됩니다.
	 * 각 함수는 현재 union을 자동으로 감지합니다. */
	union
	{
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* "프레임"의 표현 */
struct frame
{
	void *kva;		   /* 커널 가상 주소 */
	struct page *page; /* 페이지에 대한 역참조 */
};

/* 페이지 작업을 위한 함수 테이블.
 * 이것은 C에서 "인터페이스"를 구현하는 한 가지 방법입니다.
 * "메서드"의 테이블을 구조체의 멤버로 넣고,
 * 필요할 때 호출합니다. */
struct page_operations
{
	bool (*swap_in)(struct page *, void *);
	bool (*swap_out)(struct page *);
	void (*destroy)(struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page)                \
	if ((page)->operations->destroy) \
	(page)->operations->destroy(page)

/* 현재 프로세스의 메모리 공간 표현.
 * 이 구조체에 대해 특정 설계를 강요하지 않습니다.
 * 설계는 모두 여러분에게 달려 있습니다. */
struct supplemental_page_table
{
	struct hash page_table;
};

#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt,
						   void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
						 bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
									bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

#endif /* VM_VM_H */