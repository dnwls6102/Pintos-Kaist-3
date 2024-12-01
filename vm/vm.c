/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"

/* 보조 페이지 테이블 : 각각의 페이지에 대하여
   현재 페이지가 어느 곳에 저장되어 있는지(frame==물리 메모리에 있는지? disk==파일, 디스크에 있는지? swap==디스크의 스왑 영역에 있는지?)
   이에 대응하는 커널 가상주소를 가리키는 포인터 정보(GPT에 따르면 커널은 물리 메모리와 직접적으로 매핑된 주소를 가진다고 함)
   활성화가 되어있는지 안되어 있는지 등의 보조적 정보를 저장하는 자료구조
*/
/*
	Page Table을 관리하는 함수들 : threads/mmu.c에 구현되어 있음
*/

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/*
	페이지 종류에 따라서 다른 initialize 함수를 불러와야 함
*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	//spt에 할당이 안되어 있으면 : 할당하기
	//할당이 되어 있으면 : false? 아니면 그냥 넘어가기?(추후 재고)
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		//새로운 page를 만들어주기
		//vm_get_frame으로 할당하면 안되는 이유: lazy loading을 구현하기 위함
		//palloc_get_page로도 할당하지 않는 이유: 비슷한 맥락에서, palloc은 물리 메모리를 할당받기에 lazy loading에 부적합
		//여기서는 순수 가상 메모리에서만 존재하는 page가 필요한 것
		struct page* new_page = malloc(sizeof(struct page));

		//VM_TYPE으로 페이지 타입 알아내기
		if (VM_TYPE(type) == VM_ANON) //익명 페이지면
		{
			//uninit_new로 uninit page로 만들기
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE) //파일 페이지면
		{
			//uninit_new로 uninit page로 만들기
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		}
		else //그 외 : 지원하지 않는 유형의 페이지
		{
			free(new_page);
			goto err;
		}
		
		//페이지에 데이터 작성이 가능한지 여부를 따지는 bool 변수 초기화
		new_page -> has_permission = writable;
		//stack page인지 : false
		new_page -> is_stack = false;
		/* TODO: Insert the page into the spt. */
		//보조 페이지 테이블에 새로 만든 페이지 삽입 : 실패시 false
		if(!spt_insert_page(spt, new_page))
			goto err;
	}
	else	
		goto err;

	return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* 매개변수로 넘겨받은 VA(가상 메모리 주소)와 대응되는 page를 (매개변수로 받은 supplemental page table에서) 찾아오는 함수*/
/* Supplemental Page Table 구현을 위해 작성 */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = (struct page*)malloc(sizeof(struct page));
	/* TODO: Fill this function. */
	//pg_round_down으로 넘겨받은 va를 포함한 page의 시작 주소 찾기
	page -> va = pg_round_down(va);
	//(추후 재고)spt_elem이 초기화되지 않았는데 오류가 안일어날까?
	//오류가 일어나지 않는 이유 : 해시 테이블은 어차피 va값만 참고를 함
	//다른 멤버의 값은 초기화되지 않아도 문제가 없음
	struct hash_elem* temp_elem = hash_find(&spt -> hash_table, &page -> spt_elem);
	free(page);
	if (temp_elem == NULL)
		return NULL;

	return hash_entry(temp_elem, struct page, spt_elem);
}

/* Insert PAGE into spt with validation. */
/* 매개변수로 넘겨받은 page를, 매개변수로 넘겨받은 supplemental_page_table spt로 삽입하는 함수*/
/* Supplemental Page Table 구현을 위해 작성 */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */

	if (hash_insert(spt, &page -> spt_elem) == NULL)
		succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc_get_page()를 통해 user pool에서 새로운 물리 메모리 페이지를 가져오고 프레임도 할당해주는 함수
   이 함수를 구현했다면, 이후에는 유저공간에 페이지를 할당할 때 이 함수를 사용해야 함
*/
/* Frame Management 구현을 위해 작성 */
static struct frame *
vm_get_frame (void) {
	//frame 공간 할당
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
	ASSERT (frame != NULL);
	/* TODO: Fill this function. */
	frame -> kva = palloc_get_page(PAL_USER | PAL_ZERO);
	frame -> page = NULL;
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	//일단 주어진 주소를 토대로 spt에서 page를 찾기
	//만약 spt에서 page를 찾지 못했다 : 진짜 fault
	page = spt_find_page(spt, addr);

	if (addr == NULL || is_kernel_vaddr(addr))
		return false;

	//spt에서 page 정보를 복원한 경우 : 물리 메모리와 연결
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/* 가상 주소를 할당하기 위해 page를 요청하는 함수
   먼저 page를 얻은 후 그 page를 vm_do_claim_page에 넘겨줘야 할거임
*/
/* Frame Management 구현을 위해 작성 */
bool
vm_claim_page (void *va UNUSED) {
	//사용자 공간 page 할당
	struct page *page = spt_find_page(&thread_current() -> spt, va);
	/* TODO: Fill this function */
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* Frame(물리 공간 page)를 요청하는 함수
   먼저 vm_get_frame()으로 frame을 받은 후
   가상 주소 page와 frame을 서로 연결(주석 Set Links 부분에 구현이 되어있음)
   Page Table에 방금 연결한 정보를 추가해야 함
   return value는 작업이 성공 했는지 못했는지를 반환해야 함
*/
/* Frame Management 구현을 위해 작성 */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(pml4_set_page(thread_current() -> pml4, page -> va, frame -> kva, page -> has_permission) == false)
		return false;
	// else
	// 	return true;
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
/* 새로운 Supplemental Page Table을 생성*/
/* Supplemental Page Table 구현을 위해 작성 */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt -> hash_table, hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {

	//hash 자료구조 순회용 자료형 hash_iterator 변수 선언
	struct hash_iterator i;
	//file backed page인 경우 물리 메모리도 같이 얻어와야 함
	struct page* dst_page;

	hash_first (&i, &src -> hash_table);

	//src에 들어가 있는 spt_elem들을 모두 순회
	while (hash_next(&i))
	{
		//hash_entry로 page 구조체 복원 후 dst에 hash_insert
		struct page* temp_page = hash_entry(hash_cur(&i), struct page, spt_elem);
		enum vm_type type = temp_page -> operations -> type;
		void* upage = temp_page -> va;
		bool writable = temp_page -> has_permission;

		switch(type)
		{
			//부모 프로세스의 ANON 페이지 : 그냥 다시 UNINIT 페이지로 만들어주기
			//자식 프로세스가 이 페이지를 참조하게 되면 페이지 폴트가 날 것이고, 자연스럽게 물리 메모리와 매핑됨
			//만약 COW를 구현하기 위해서는 추가로 temp_page -> frame -> kva와 매핑해줘야 함
			case VM_ANON:
				if(!vm_alloc_page(type, upage, writable))
					return false;
				break;

			//부모 프로세스의 FILE_BACKED 페이지 : 자식 프로세스의 spt에 추가해주는 것은 물론
			//물리 메모리와 가상 메모리 페이지와도 연결해줘야 함

			case VM_FILE:
				//가상 메모리 할당 후
				//aux 매개변수로 원본 페이지의 file 정보를 전달
				if(!vm_alloc_page_with_initializer(type, upage, writable, NULL, &temp_page -> file))
					return false;
				
				//자식 프로세스의 spt에서 방금 넣은 페이지 찾아오기
				dst_page = spt_find_page(dst, upage);
				//file 정보 설정해주기
				if (!file_backed_initializer(dst_page, type, NULL))
					return false;
				
				//자식 프로세스의 page에 원본 page의 frame 정보 저장
				dst_page -> frame = temp_page -> frame;
				//link 설정
				dst_page -> frame -> page = dst_page;

				//page와 frame간의 매핑 정보 pml4에 등록
				if(!pml4_set_page(thread_current() -> pml4, dst_page -> va, dst_page -> frame -> kva, dst_page -> has_permission))
					return false;

				break;

			//부모 프로세스의 UNINIT 페이지 : UNINIT 상태로 유지
			//단, 해당 페이지가 갖고 있는 모든 정보를 동일하게 가지고 와야 함
			case VM_UNINIT:
				if(!vm_alloc_page_with_initializer(type, upage, writable, temp_page -> uninit.init, temp_page -> uninit.aux))
					return false;
				break;

			default:
				return false;
		}

	}
	return true;

}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
