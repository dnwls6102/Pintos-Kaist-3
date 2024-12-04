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
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		//새로운 page를 만들어주기
		//vm_get_frame으로 할당하면 안되는 이유: lazy loading을 구현하기 위함
		//palloc_get_page로도 할당하지 않는 이유: 비슷한 맥락에서, palloc은 물리 메모리를 할당받기에 lazy loading에 부적합
		//여기서는 순수 가상 메모리에서만 존재하는 page가 필요한 것
		struct page* new_page = (struct page *)malloc(sizeof(struct page));

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
	// printf("va : %p, page -> va : %p \n", va, page -> va);
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

	if (hash_insert(&spt -> hash_table, &page -> spt_elem) == NULL)
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
	if (frame -> kva == NULL)
		PANIC("TODO");
	frame -> page = NULL;
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	//매개변수로 받은 addr을 포함한 page의 주소를 받아와서
	//addr을 pg_round_down한 후 그 지점부터 메모리 공간을 PGSZIE만큼 추가로 할당시켜주기
	void * temp_addr = pg_round_down(addr);

	if (vm_alloc_page(VM_ANON | VM_MARKER_0, temp_addr, true) && vm_claim_page(temp_addr))
	{
		thread_current() -> stack_bottom = temp_addr;
	}

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

	if (addr == NULL || is_kernel_vaddr(addr))
		return false;

	//현재 메모리에 page가 없는 상황이라면
	if (not_present)
	{
		//일단 주어진 주소를 토대로 spt에서 page를 찾기
		//만약 spt에서 page를 찾지 못했다 : 진짜 fault
		page = spt_find_page(spt, addr);
		//spt에 page가 없다면
		if (page == NULL)
		{
			//유저 모드에서 페이지 폴트가 발생했는지, 커널 모드에서 페이지 폴트가 발생했는지 구분해야 함
			//유저 모드에서 발생했을 경우, 매개변수로 넘겨받은 rsp를 참조하면 된다
			//커널 모드에서 발생한 경우, 현재 커널 모드를 돌리는 스레드의 rsp를 참조해야 한다
			//커널 모드가 돌아가는 중에 페이지 폴트가 발생하고, 인터럽트 프레임의 rsp를 참고하면
			//그거는 커널 모드 전용 스택을 참고하는 것이 아닌, 커널 모드에 들어가기 직전에 돌아가던 스레드에 저장된 rsp를 참조하는 것이다

			void * stack_pointer = user ? f -> rsp : thread_current() -> stack_pointer;

			// printf("stack_pointer : %p, f -> rsp = %p\n", thread_current() -> stack_pointer, f -> rsp);

			// if (thread_current() -> stack_bottom >= addr && thread_current() -> stack_bottom - PGSIZE <= addr)

			//x86에서는 rsp에서 8바이트 이내인 곳에서 page fault를 발생시킨다
			if (stack_pointer - 8 <= addr && addr >= STACK_LIMIT && addr <= USER_STACK)
			{
				// printf("stack_pointer : %p, addr = %p\n", thread_current() -> stack_pointer, addr);
				//vm_stack_growth 호출
				vm_stack_growth(addr);
				return true;
			}
			
			return false;
		}
		
		//쓰기가 불가능한 페이지에 쓰기를 하려고 했다면
		if (write == true && page -> has_permission == false)
		{
			return false;
		}
		//spt에서 page 정보를 복원한 경우 : 물리 메모리와 연결
		return vm_do_claim_page (page);
	}
	
	//그 외 : return false
	return false;
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
		// printf("va : %p\n", temp_page -> va);
		bool writable = temp_page -> has_permission;

		switch(type)
		{
			//부모 프로세스의 ANON 페이지 : 그냥 다시 UNINIT 페이지로 만들어주기
			//자식 프로세스가 이 페이지를 참조하게 되면 페이지 폴트가 날 것이고, 자연스럽게 물리 메모리와 매핑됨
		
			case VM_ANON:
				if(!vm_alloc_page(type, upage, writable))
					return false;
				//fork 안되는 문제 해결 : ANON PAGE를 alloc만 하면 안됨
				//물리 주소를 가져와야 함
				//왜 claim까지 하는지 : 일단 어쨌든 frame을 위한 공간을 마련해야 하니까...
				//claim으로 임의의 kva를 얻어오고, temp_page의 kva로 덮어씌우는듯
				if (!vm_claim_page(upage))
          			return false;
				//memcpy
				//현재 자식 프로세스의 spt에 등록된 페이지 다시 불러오기
				struct page* dst_page = spt_find_page(dst, upage);
				//부모 페이지의 물리 주소를 자식 페이지로 복사하기
				memcpy(dst_page -> frame -> kva, temp_page -> frame -> kva, PGSIZE);
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
				if(!pml4_set_page(thread_current() -> pml4, dst_page -> va, temp_page -> frame -> kva, temp_page -> has_permission))
					return false;

				break;

			//부모 프로세스의 UNINIT 페이지 : UNINIT 상태로 유지
			//단, 해당 페이지가 갖고 있는 모든 정보를 동일하게 가지고 와야 함
			case VM_UNINIT:
				//Kernel panic in run: PANIC at ../../vm/vm.c:59 in vm_alloc_page_with_initializer(): assertion `VM_TYPE(type) != VM_UNINIT' failed. 해결
				//vm_alloc_page_with_initializer의 첫 번째 인자로 그냥 type을 넘겨버리게 된다면
				//ASSERT(VM_TYPE(type) != VM_UNINIT)에 걸리고 만다
				//원본 page의 operations.type을 가져오는 page_get_type함수를 활용해야 한다
				if(!vm_alloc_page_with_initializer(VM_ANON, upage, writable, temp_page -> uninit.init, temp_page -> uninit.aux))
					return false;
				break;

			default:
				return false;
		}

	}
	return true;

	// struct hash_iterator i;
    // hash_first(&i, &src->hash_table);
    // while (hash_next(&i))
    // {
    //     // src_page 정보
    //     struct page *src_page = hash_entry(hash_cur(&i), struct page, spt_elem);
    //     enum vm_type type = src_page->operations->type;
    //     void *upage = src_page->va;
    //     bool writable = src_page->has_permission;

    //     /* 1) type이 uninit이면 */
    //     if (type == VM_UNINIT)
    //     { // uninit page 생성 & 초기화
    //         vm_initializer *init = src_page->uninit.init;
    //         void *aux = src_page->uninit.aux;
    //         vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
    //         continue;
    //     }

    //     /* 2) type이 uninit이 아니면 */
    //     if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
    //         // init이랑 aux는 Lazy Loading에 필요함
    //         // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
    //         return false;

    //     // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
    //     if (!vm_claim_page(upage))
    //         return false;

    //     // 매핑된 프레임에 내용 로딩
    //     struct page *dst_page = spt_find_page(dst, upage);
    //     memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    // }
    // return true;

}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	//hash 자료구조 순회용 자료형 hash_iterator 변수 선언
	// struct hash_iterator i;
	// struct hash_elem *to_delete;

	// hash_first(&i, &spt -> hash_table);

	// //spt에 들어가 있는 spt_elem을 모두 순회
	// while(hash_next(&i))
	// {
	// 	to_delete = hash_cur(&i);
	// 	struct page* temp_page = hash_entry(hash_cur(&i), struct page, spt_elem);
	// 	// destroy(temp_page);
	// 	hash_delete(&spt -> hash_table, to_delete);
	// 	destroy(temp_page);
	// 	// vm_dealloc_page(temp_page);
	// 	// hash_delete(&spt -> hash_table, to_delete);
	// }

	//위 방식의 문제 : page 자체를 free할 방법이 없다
	//destroy(temp_page) 이후에 free(page)를 하게 되면, hash_elem의 앞/뒤 원소와의 연결도 끊김
	//정확히 하자면 hash_elem이 NULL로 초기화되니 앞/뒤 원소에 접근 자체가 불가능(쓰레기 값에 접근함)
	//free(page)를 하지 않으면 문제없이 돌아가지만, 메모리 누수가 발생함
	//while을 true로 걸고, free(page)를 하기 전에 미리 hash_next(&i)를 하면
	//문제가 없을 것 같긴 하지만 hash_clear를 통한 방식이 더 안정적이다

	//hash_clear 및 hash_destructor 정의를 통한 hash 멤버들 삭제
	//hash_clear 내부에서 page를 free하기 전에 미리 반복 인자를 다음 hash_elem으로 옮기기 때문에
	//메모리 참조 오류가 발생하지 않는다

	hash_clear(&spt->hash_table, hash_destructor);  // 해시 테이블의 모든 요소 제거

}
