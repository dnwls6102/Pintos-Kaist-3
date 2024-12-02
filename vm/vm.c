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
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    // upage가 이미 사용 중인지 확인합니다.
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
         
        // 1) 페이지를 생성하고,
        struct page *p = (struct page *)malloc(sizeof(struct page));
        
        // 2) type에 따라 초기화 함수를 가져와서
        bool (*page_initializer)(struct page *, enum vm_type, void *);

        switch (VM_TYPE(type))
        {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        }

        // 3) "uninit" 타입의 페이지로 초기화한다.
        uninit_new(p, upage, init, type, aux, page_initializer);

        // 필드 수정은 uninit_new를 호출한 이후에 해야 한다.
        p->writable = writable;

        // 4) 생성한 페이지를 SPT에 추가한다.
        return spt_insert_page(spt, p);
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* 매개변수로 넘겨받은 VA(가상 메모리 주소)와 대응되는 page를 (매개변수로 받은 supplemental page table에서) 찾아오는 함수*/
/* Supplemental Page Table 구현을 위해 작성 */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {

	struct page *page = NULL;
    /* TODO: Fill this function. */
    page = malloc(sizeof(struct page));
    struct hash_elem *e;

    // va에 해당하는 hash_elem 찾기
    page->va = va;
    e = hash_find(&spt, &page->hash_elem);

    // 있으면 e에 해당하는 페이지 반환
    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
	return page;
}

/* Insert PAGE into spt with validation. */
/* 매개변수로 넘겨받은 page를, 매개변수로 넘겨받은 supplemental_page_table spt로 삽입하는 함수*/
/* Supplemental Page Table 구현을 위해 작성 */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	return hash_insert(&spt, &page->hash_elem) == NULL ? true : false; // 존재하지 않을 경우에만 삽입
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
	struct frame *frame = NULL;
    /* TODO: Fill this function. */
    void *kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

    if (kva == NULL)   // page 할당 실패 -> 나중에 swap_out 처리
        PANIC("todo"); // OS를 중지시키고, 소스 파일명, 라인 번호, 함수명 등의 정보와 함께 사용자 지정 메시지를 출력

    frame = malloc(sizeof(struct frame)); // 프레임 할당
    frame->kva = kva;                      // 프레임 멤버 초기화

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
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
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        /* TODO: Validate the fault */
        page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;
        if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
    }
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
	struct page *page = NULL;
    /* TODO: Fill this function */
    // spt에서 va에 해당하는 page 찾기
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    return vm_do_claim_page(page);
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
	struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    // 가상 주소와 물리 주소를 매핑
    struct thread *current = thread_current();
    pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

    return swap_in(page, frame->kva); // uninit_initialize
}

unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* Initialize new supplemental page table */
/* 새로운 Supplemental Page Table을 생성*/
/* Supplemental Page Table 구현을 위해 작성 */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(spt, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
			struct hash_iterator i;
    hash_first(&i, &src->spt_hash);
    while (hash_next(&i))
    {
        // src_page 정보
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* 1) type이 uninit이면 */
        if (type == VM_UNINIT)
        { // uninit page 생성 & 초기화
            vm_initializer *init = src_page->uninit.init;
            void *aux = src_page->uninit.aux;
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
            continue;
        }

        /* 2) type이 uninit이 아니면 */
        if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
            // init이랑 aux는 Lazy Loading에 필요함
            // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
            return false;

        // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
        if (!vm_claim_page(upage))
            return false;

        // 매핑된 프레임에 내용 로딩
        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, hash_page_destroy); // 해시 테이블의 모든 요소를 제거
}
