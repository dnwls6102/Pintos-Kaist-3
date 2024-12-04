#ifndef VM_UNINIT_H
#define VM_UNINIT_H
#include "vm/vm.h"

struct page;
enum vm_type;

typedef bool vm_initializer(struct page *, void *aux);

/* Uninitlialized page. The type for implementing the
 * "Lazy loading". */
struct uninit_page
{
	/* Initiate the contets of the page */
	vm_initializer *init; // uninit page를 초기화
	enum vm_type type;	  // uninit이 어떤 타입(anon 혹은 file)의 페이지가 될지 저장
	void *aux;
	/* Initiate the struct page and maps the pa to the va */
	bool (*page_initializer)(struct page *, enum vm_type, void *kva); // uninit->type에 맞는 초기화 함수를 가리키는 포인터
};

void uninit_new(struct page *page, void *va, vm_initializer *init,
				enum vm_type type, void *aux,
				bool (*initializer)(struct page *, enum vm_type, void *kva));
bool uninit_initialize(struct page *page, void *kva);
#endif
