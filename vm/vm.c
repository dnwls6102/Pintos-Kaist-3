/* vm.c: 가상 메모리 객체를 위한 일반 인터페이스. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/thread.h"
#include "vm/uninit.h"
#include "include/lib/kernel/hash.h"
#include "include/threads/vaddr.h"

/* 각 하위 시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* 프로젝트 4용 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* 위쪽 코드는 수정하지 마세요. */
	/* TODO: 여기에 필요한 추가 초기화 코드를 작성하세요. */
}

/* 페이지의 유형을 가져옵니다.
 * 이 함수는 페이지가 초기화된 후 해당 유형을 확인하려는 경우 유용합니다. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	// case VM_ANON:
	// 	return VM_TYEP(page->anon.type);
	default:
		return ty;
	}
}

/* supplemental 함수 */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* 초기화자를 사용하여 대기 중인 페이지 객체를 생성합니다.
 * 페이지를 직접 생성하지 말고 이 함수 또는 `vm_alloc_page`를 통해 생성하세요. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)
	printf("📌 vm_alloc_page_with_initializer: upage = %p\n", upage);

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* upage가 이미 점유(occupy)되어 있는지 확인합니다. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: 페이지를 생성하고 VM 유형에 따라 초기화자를 선택한 다음
		 * TODO: uninit_new를 호출하여 "uninit" 페이지 구조체를 초기화합니다.
		 * TODO: uninit_new 호출 후 필요한 필드를 수정하세요. */
		struct page *page = malloc(sizeof(struct page));
		ASSERT(page != NULL);

		// page->user = true;
		// page->not_present = true;
		if (VM_TYPE(type) == VM_ANON) // if (type == VM_ANON)로 하면 setup_stack일 때의 타입 인식 못 해서 false 리턴함
			uninit_new(page, upage, init, type, aux, anon_initializer);
		else if (VM_TYPE(type) == VM_FILE)
			uninit_new(page, upage, init, type, aux, file_backed_initializer);
		else
		{
			free(page);
			return false;
		}
		page->writable = writable;

		/* TODO: 페이지를 spt에 삽입합니다. */
		if (!spt_insert_page(spt, page))
			return false;
	}
	return true;
err:
	return false;
}

// /* spt에서 가상 주소를 찾아 페이지를 반환합니다.
//  * 에러가 발생하면 NULL을 반환합니다. */
// struct page *
// spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
// {
// 	struct page *page = NULL;
// 	/* TODO: 이 함수의 구현을 완료하세요. */
// 	struct hash_iterator i;

// 	hash_first(&i, &spt->page_table);
// 	while (hash_next(&i)) // hash 테이블의 요소를 순회
// 	{
// 		page = hash_entry(hash_cur(&i), struct page, page_table_elem); // 요소에서 페이지를 꺼냄
// 		if (page->va == va)											   // va에 해당하는 페이지가 있으면
// 			return page;											   // 해당 페이지를 반환
// 	}

// 	return NULL;
// }
/* Find VA from spt and return page. On error, return NULL. */
/* 매개변수로 넘겨받은 VA(가상 메모리 주소)와 대응되는 page를 (매개변수로 받은 supplemental page table에서) 찾아오는 함수*/
/* Supplemental Page Table 구현을 위해 작성 */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page *page = (struct page *)malloc(sizeof(struct page));
	/* TODO: Fill this function. */
	// pg_round_down으로 넘겨받은 va를 포함한 page의 시작 주소 찾기
	page->va = pg_round_down(va);
	// printf("va : %p, page -> va : %p \n", va, page -> va);
	//(추후 재고)spt_elem이 초기화되지 않았는데 오류가 안일어날까?
	// 오류가 일어나지 않는 이유 : 해시 테이블은 어차피 va값만 참고를 함
	// 다른 멤버의 값은 초기화되지 않아도 문제가 없음
	struct hash_elem *temp_elem = hash_find(&spt->page_table, &page->page_table_elem);
	free(page);
	if (temp_elem == NULL)
		return NULL;

	return hash_entry(temp_elem, struct page, page_table_elem);
}

/* 검증 후 PAGE를 spt에 삽입합니다. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;
	/* TODO: 이 함수의 구현을 완료하세요. */
	printf("📌 spt_insert_page: upage = %p\n", page->va);
	if (spt_find_page(spt, page->va) != NULL) // 보조 페이지 테이블에 해당 페이지의 va가 이미 존재하면
		return succ;						  // false 반환

	// 없으면 페이지 삽입
	if (hash_insert(&spt->page_table, &page->page_table_elem) == NULL)
		succ = true;

	return succ;
}

/* spt에서 페이지를 제거합니다. */
void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* 교체 정책에 따라 제거할 프레임을 가져옵니다. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: 교체 정책을 정의하고 구현하세요. */

	return victim;
}

/* 하나의 페이지를 교체하고 해당 프레임을 반환합니다.
 * 에러가 발생하면 NULL을 반환합니다. */
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: 교체할 페이지를 스왑 아웃하고 교체된 프레임을 반환하세요. */

	return NULL;
}

/* palloc()을 사용하여 프레임을 할당합니다.
 * 사용 가능한 페이지가 없을 경우 페이지를 교체하여 메모리를 확보한 후
 * 교체된 프레임을 반환합니다. 이 함수는 항상 유효한 주소를 반환합니다. */

// vm_get_frame을 구현한 후, 모든 유저 영역 페이지(PALLOC_USER)는 이 함수를 통해 할당되어야 함
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = malloc(sizeof(struct frame));
	ASSERT(frame != NULL);

	/* TODO: 프레임 할당 로직을 구현하세요. */
	// palloc_get_page를 호출하여 사용자 풀(user pool)에서 새 물리 페이지를 가져옴
	if ((frame->kva = palloc_get_page(PAL_USER)) != NULL)
	{
		frame->page = NULL;
		ASSERT(frame->page == NULL);
		return frame;
	}

	else
		// 페이지 할당 실패 시 나중에 스왑아웃 처리 필요 - 지금은 PANIC(”todo”) 로 표시
		PANIC("todo");
}

/* 스택을 확장하여 지정된 주소에 새 페이지를 할당합니다. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* 쓰기 보호된 페이지에 대한 예외를 처리합니다. */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* 페이지 예외를 처리하려고 시도합니다. 성공하면 true를 반환합니다. */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: 예외를 검증하고 처리하세요. */
	if (not_present) // 물리 메모리에 존재하지 않는 페이지인지 확인
	{
		if (!user)
			return false;
		if (addr == NULL) // 유저 영역이 아니거나, 읽기 전용 영역이거나, 주소가 유효하지 않으면 에러
			return false;

		if ((page = spt_find_page(spt, addr)) == NULL)
			return false;

		if (page->writable == false && write == true)
			return false;
	}

	return vm_do_claim_page(page);
}

/* 페이지를 해제합니다.
 * 이 함수는 수정하지 마세요. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* spt에서 지정된 가상 주소(VA)에 해당하는 페이지를 가져옵니다. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: 페이지 확보 로직을 구현하세요. */
	// SPT에 va가 등록이 되어있는지 확인
	// - va가 존재하지 않는다면 애초에 가상 메모리에 페이지가 할당 조차 안 된 것이기 때문에 물리 메모리에 연결할 수 없음
	if ((page = spt_find_page(&thread_current()->spt, va)) == NULL)
		return false;

	return vm_do_claim_page(page);
}

/* PAGE를 확보하고 MMU(메모리 관리 장치)를 설정합니다. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* 페이지와 프레임 간의 링크를 설정합니다. */
	frame->page = page;
	page->frame = frame;

	/* TODO: 페이지 테이블 항목을 삽입하여 페이지의 가상 주소(VA)를
	 * TODO: 프레임의 물리적 주소(PA)에 매핑하세요. */
	struct thread *cur = thread_current();
	spt_insert_page(&cur->spt, page);

	// 페이지 테이블에 가상 주소와 물리 주소간의 매핑을 추가
	pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);

	return swap_in(page, frame->kva);
}

/* 새 보조 페이지 테이블을 초기화합니다. */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	struct hash *h = &spt->page_table;
	hash_init(h, hash_func, less_func, h->aux);
}

/* 보조 페이지 테이블을 src에서 dst로 복사합니다. */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	return memcpy(dst, src, sizeof(struct supplemental_page_table));
}

/* 보조 페이지 테이블이 사용하는 리소스를 해제합니다. */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	struct hash *h = &spt->page_table;
	/* TODO: 스레드가 사용하는 보조 페이지 테이블의 모든 항목을 제거하고
	 * TODO: 수정된 내용을 스토리지에 기록하세요. */
	// hash_clear();
}
