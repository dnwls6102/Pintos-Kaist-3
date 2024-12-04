#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page
{
    enum vm_type type;

    /* Project03 - Anonymous page */
    struct file *f;         // file, offset
    struct disk *swap_disk; // 스왑 영역의 위치
};

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);

#endif
