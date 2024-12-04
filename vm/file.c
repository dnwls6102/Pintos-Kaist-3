/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	page -> status = FILE; //(추후 재고)

	struct file_page *file_page = &page->file;

	//uninit.aux => spt table copy에서 vm_alloc_page_with_initializer의 &temp_page -> file을 통해 전달됨
	//aux_for_lazy_load는 file_page 구조체와 동일
	struct aux_for_lazy_load* temp_aux = (struct aux_for_lazy_load *) page -> uninit.aux;
	
	file_page -> file = temp_aux -> file;
	file_page -> ofs = temp_aux -> ofs;
	file_page -> page_read_bytes = temp_aux -> page_read_bytes;
	file_page -> page_zero_bytes = temp_aux -> page_zero_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	//파일이 수정된 경우 이를 디스크에도 반영해 줘야 함
	if(pml4_is_dirty(thread_current() -> pml4, page -> va))
	{
		file_write_at(file_page -> file, page -> va, file_page -> page_read_bytes, file_page -> ofs);
		pml4_set_dirty(thread_current() -> pml4, page -> va, 0);
	}

	//page의 매핑 정보 삭제
	pml4_clear_page(thread_current() -> pml4, page -> va);
}

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	
	//load_segment를 구현하면 됨

	//aux로 받은 정보 구조체로 받아오기
	struct aux_for_lazy_load *temp = (struct aux_for_lazy_load *)aux;

	//파일 로드
	file_seek(temp -> file, temp -> ofs);

	//페이지 로드
	if(file_read(temp -> file, page -> frame -> kva, temp -> page_read_bytes) != (int)temp -> page_read_bytes)
	{
		//프레임 해제, 페이지는 해제하면 안됨
		palloc_free_page(page -> frame -> kva);
		return false;
	}

	//데이터를 쓰고 남은 부분을 0으로 초기화
	memset(page -> frame -> kva + temp -> page_read_bytes, 0, temp -> page_zero_bytes);

	return true;

}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	//동일한 파일에 대하여 여러 프로세스가 매핑을 진행할 수 있음
	//file_reopen함수를 사용하면, 동일한 파일이지만 다른 파일 디스크립터를 반환시켜줌
	struct file* f = file_reopen(file);
	//성공적으로 매핑이 이루어졌을 경우 반환할 주소 start_addr
	void * start_addr = addr;
	//이 파일을 저장하는 데에 몇 개의 페이지가 사용되었는지를 저장할 int 변수 used_pages
	//나중에 unmap할때 필요함
	int used_pages;
	//만약 파일 길이가 페이지 하나 크기보다 크다면
	if (length > PGSIZE)
	{
		//PGSIZE에 딱 맞아 떨어지지 않으면
		if (length % PGSIZE)
			used_pages = length / PGSIZE + 1;
		//PGSIZE의 배수만큼 딱 맞아 떨어지면
		else
			used_pages = length / PGSIZE;
	}
	//PGSIZE보다 작거나 같으면 : 1
	else
		used_pages = 1;

	//read_bytes 값을 굳이 한번 더 판정하는 이유
	//파일의 전체를 읽는 것이 아닌, 일부만 읽는 요청이 발생할 수 있음
	size_t read_bytes = file_length(f) < length ? file_length(f) : length;
	//zero_bytes : 페이지에 파일 데이터를 할당한 후 남은 공간을 0으로 초기화할 공간
	//read_bytes를 PGSIZE로 나눈 나머지 값이 곧 데이터가 쓰일 공간이니, PGSIZE - read_bytes % PGSIZE를 zero_bytes로 설정한다
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);

	//load_segment를 가져와서 file 가져오기
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		//aux? 보조 데이터(auxiliary data)를 의미함
		//매개변수에서 요구하는 aux의 자료형 : void 포인터
		//그러니까 그냥 내가 자료형 아무거나 선언해서 전달해도 무방함
		struct aux_for_lazy_load *aux = (struct aux_for_lazy_load*)malloc(sizeof(struct aux_for_lazy_load));
		
		//aux 공간 할당 실패 시 : return false
		if (aux == NULL)
			return false;

		//aux 멤버 초기화
		aux -> file = file;
		aux -> ofs = offset;
		aux -> page_read_bytes = page_read_bytes;
		aux -> page_zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, start_addr,
					writable, lazy_load_segment, aux))
		{
			free(aux);
			return NULL;
		}

		//file이 저장된 페이지에 페이지를 얼마나 사용했는지를 저장하기
		struct page* p = spt_find_page(&thread_current() -> spt, addr);
		p -> file_page_used = used_pages;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return start_addr;
	
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current() -> spt;
	struct page *p = spt_find_page(spt, addr);
	int count = p -> file_page_used;
	for(int i = 0; i < count; i++)
	{
		if(p)
			destroy(p);
		addr += PGSIZE;
		p = spt_find_page(spt, addr);
	}
}
