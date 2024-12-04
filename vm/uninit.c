/* uninit.c: 초기화되지 않은 페이지의 구현.
 *
 * 모든 페이지는 초기화되지 않은 페이지로 태어납니다. 첫 번째 페이지 폴트가 발생하면,
 * 핸들러 체인은 uninit_initialize (page->operations.swap_in)를 호출합니다.
 * uninit_initialize 함수는 페이지 객체를 초기화하여 페이지를 특정 페이지
 * 객체(익명, 파일, 페이지 캐시)로 변환하고, vm_alloc_page_with_initializer
 * 함수에서 전달된 초기화 콜백을 호출합니다.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

// static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void uninit_new(struct page *page, void *va, vm_initializer *init,
				enum vm_type type, void *aux,
				bool (*initializer)(struct page *, enum vm_type, void *))
{
	ASSERT(page != NULL);

	*page = (struct page){
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page){
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}};
}

/* Initalize the page on first fault */
// static bool
// uninit_initialize(struct page *page, void *kva)
// {
// 	struct uninit_page *uninit = &page->uninit;

// 	/* Fetch first, page_initialize may overwrite the values */
// 	vm_initializer *init = uninit->init;
// 	void *aux = uninit->aux;

// 	/* TODO: You may need to fix this function. */
// 	return uninit->page_initializer(page, uninit->type, kva) && // anon_initializer() || filebacked_initializer()
// 		   (init ? init(page, aux) : true);						// lazy_load_segment()
// }

/* uninit_initialize 고쳐보깅 */
bool uninit_initialize(struct page *page, void *kva)
{
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;
	int succ = false;

	/* TODO: You may need to fix this function. */
	if (uninit->type == VM_ANON || uninit->type == VM_ANON | VM_MARKER_0)
		succ = anon_initializer(page, VM_ANON, kva);
	else if (uninit->type == VM_FILE)
		succ = file_backed_initializer(page, VM_FILE, kva);
	else
		return false;

	if (succ)
		return (init ? init(page, aux) : true); // lazy_load_segment()
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy(struct page *page)
{
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */
}
