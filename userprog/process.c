#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct thread * get_child_process(int tid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	//thread 구조체의 name 멤버에 올바른 테스트 이름을 저장하기 
	char *temp;
	strtok_r(file_name, " ", &temp);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	//printf("initd생성 완료\n");
	if (tid == TID_ERROR)
	{
		palloc_free_page (fn_copy);
		//printf("사실안됨ㅋ\n");
	}
	
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	//현재 스레드 정보 불러오기
	struct thread* current_t = thread_current();
	//깃북에서 요구한 대로 레지스터 정보들을 다 옮기기 위해서는
	//생성하는 스레드(부모 스레드)의 인터럽트 프레임을 전달해야 함
	//rsp()함수를 통해 인터럽트 프레임의 시작 주소를 가져오기
	//레지스터 정보는 페이지의 맨 위에 저장되에 있다
	//struct intr_frame* f = pg_round_up(rrsp()) - sizeof(struct intr_frame);

	//위 방식대로 하면 제대로 안될수도 있을 우려가 있다
	//그냥 매개변수로 인터럽트 프레임 받아와서 하기
	//Kernel Panic 오류 : sizeof(sturct intr_frame *)로 하면 오류가 남
	//이유 : 포인터 변수는 주소값만 저장하는 변수라서 크기가 작음 : sizeof(struct intr_frame *) : 8 sizeof(struct intr_frame) : 192
	memcpy(&current_t -> parent_if, if_, sizeof(struct intr_frame));

	/*프로세스를 복제하고, 만약 실패하면 그대로 return*/
	int tid;
	tid = thread_create (name, PRI_DEFAULT, __do_fork, current_t);
	if (tid == TID_ERROR)
		return tid;

	struct thread * child = get_child_process(tid);

	//sema_down을 해줘서 자식 스레드가 do_fork를 완벽하게 하는 것을 보장
	sema_down(&child -> fork_sema);
	

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
		return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	//만약 메모리 할당을 못받은거면 return
	if (parent_page == NULL)
		return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	//PAL_USER | PAL_ZERO의 의미 : 사용자 공간에 메모리 공간을 할당받을건데, 그것들을 다 0으로 초기화 해달라
	//PAL_USER : 사용자 공간의 메모리 공간을 할당하는 것을 요청하는 flag
	//PAL_USER를 하지 않으면 기본적으로 커널 공간의 메모리 공간을 할당해줌
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false;
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent -> parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0; //자식 프로세스의 리턴값을 0으로 설정

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	//주석 작성 필요
	//FDT_COUNT_LIMIT
	// error: expected identifier before numeric constant 오류 해결:
	//올바르지 않은 수식(fd_idx -> FDT_COUNT_LIMIT)을 적을 경우 발생했었음
	//multi-oom에서 이 조건에 걸려서 10개가 채워지지 않은 상태에서 exit(-2)로 넘어감
	// if (parent -> fd_idx > FDT_COUNT_LIMIT)
	// 	goto error;
	
	current -> fd_idx = parent -> fd_idx;
	struct file *file;
	//FDT_COUNT_LIMIT
	for (int fd = 0; fd < FDT_COUNT_LIMIT; fd++)
	{
		file = parent -> fdt[fd];
		if (file == NULL)
			continue;
		
		if (file > STDERR)
			current -> fdt[fd] = file_duplicate(file);
		else
			current -> fdt[fd] = file;
	}

	//성공적으로 복제 완료하면 sema 풀어주기
	sema_up(&current -> fork_sema);

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	sema_up(&current -> fork_sema);
	//thread_exit ();
	exit(-2);
}

void argument_stack(char* argv[], int argc, struct intr_frame* _if)
{
	char *argv_addr[100]; //명령어가 스택에 저장된 주소를 저장하는 배열 argv_addr
	int argv_len; //명령어의 길이를 저장하는 argv_len(주소값 연산을 위함)

	//입력받은 명령어를 stack에 push하는데, 오른쪽에서 왼쪽으로 push한다
	//4바이트 alignment를 위해 필요할 경우 padding을 넣어준다 (64비트니까 8바이트 alignment?)
	//문자열의 시작 주소를 push해준다
	//그 후 argv와 argc도 push해주고
	//다음 명령어(여기서는 return adress)의 주소도 push해준다

	//스택의 시작 주소 : setup_stack에서 초기화 함. _if -> rsp에 저장되어 있음

	//스택 초기화 첫 번째 작업 : argv에 저장된 명령어들을 스택에 넣어주기
	//유저 스택의 top은 스택에서 가장 주소값이 큰 곳이 아니라, 가장 작은 곳
	//위에서 아래로 자라는 구조이기 때문에, _if -> rsp에서 감산을 해줘야 함
	for (int i = argc - 1; i >= 0; i--)
	{
		//오류 해결 : Page fault at 0x47480000: not present error reading page in user context.
		//strlen(argv[i] + 1)로 연산을 해버려서 오류가 난 것으로 보여짐
		argv_len = strlen(argv[i]) + 1; //+1까지 해주는 이유: null 문자의 길이까지 고려해야 하니까
		_if -> rsp -= argv_len; //주소값 연산 해주기
		memcpy(_if -> rsp, argv[i], argv_len); //_if -> rsp로 argv_len만큼 argv[i]의 내용을 옮기기 == 스택에 명령어 push
		argv_addr[i] = _if -> rsp; //명령어가 저장된 주소(스택에서의 명령어 시작점)을 argv_addr[i]에 저장
		//0번째가 아닌 i번째 인덱스에 저장하는 이유 : 어차피 나중에 주소도 스택에 넣을텐데, 이 때 i번째부터 넣으면 됨
	}

	//8비트 allignment를 위한 while 반복문
	while (_if -> rsp % 8 != 0)
	{
		_if -> rsp -= 1; //스택 포인터가 가리키는 주소가 8로 나누어 떨어질때까지 반복해줘야 함
		*(uint8_t *)(_if -> rsp) = 0; //스택 포인터가 현재 가리키고 있는 주소에 내장된 값을 0으로 함
	}

	//스택 초기화의 두 번째 작업 : 스택에 저장된 명령어들의 (스택에 저장된)주소를 스택에 push하기

	//명령어가 더 이상 없다는 것을 나타내기 위해 스택의 현재 위치에서 8바이트만큼 더한 위치에(8바이트 alignment를 위함. 4바이트면 4바이트만큼)
	//sizeof(char*)만큼 0으로 채워준다
	//사실상 argv[4] = 0 이라는 의미

	_if -> rsp -= 8;
	memset(_if -> rsp, 0, sizeof(char *));

	//나머지 명령어들이 저장된 주소를 stack에 push
	for (int i = argc - 1; i >= 0; i--)
	{
		_if -> rsp -= 8; //8바이트 alignment 지켜주기
		memcpy(_if -> rsp, &argv_addr[i], sizeof(char *)); //sizeof(char *)만큼의 공간에 주소값 저장하기
	}

	//이후 argv와 argc를 차례대로 push
	char *argv_start = _if -> rsp;

	//fake return address인 0을 push
	_if -> rsp -= 8;
	memset(_if -> rsp, 0, sizeof(void *));

	_if -> R.rsi = argv_start; //%rsi가 argv의 주소를 가리키게 함
	// _if -> R.rsi = _if -> rsp + 8;
	_if -> R.rdi = argc; //%rdi를 argc로 설정
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	char *temp, *save_ptr; //argv에 저장할 문자열 temp, strtok_r 함수를 사용하는 데에 필요한 문자열 save_ptr
	char* argv[64]; //커맨드라인 받아낼 array argv
	int argc = 0;

	/*Project 2 : Command Line Parsing*/

	/*strtok_r(char *str, const char *delim, char **saveptr)함수
	str : 분할할 원본 문자열의 시작 주소. 첫 번째 호출에서 원본 문자열을 지정하고, 이후 호출에서는 NULL을 전달해 다음 토큰을 가져옴
	delim : 문자열을 구분지을 구분자 문자열
	saveptr : 문자열의 현재 위치를 저장할 포인터. 함수가 한 번 호출되면 saveptr에 마지막으로 문자열을 나눈 위치가 기록됨
	*/

	//argv에 커맨드 저장
	//예: echo x y z라는 커맨드가 들어왔다면
	//argv[0]에 echo, argv[1]에 x, argv[2]에 y, argv[3]에 z가 들어감
	for (temp = strtok_r(file_name, " ", &save_ptr); temp != NULL; temp = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc++] = temp; 
	}

	/* And then load the binary */
	success = load (file_name, &_if);

	if (!success) //프로세스 생성에 성공하지 못하면
	{
		/* If load failed, quit. */
		palloc_free_page (file_name);
		return -1; //스레드 삭제
	}
		
	/*Project 2 : Command Line Parsing*/	
	argument_stack(argv, argc, &_if);
	//디버깅용
	//hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);

	palloc_free_page (file_name);

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	//매개변수로 건네받은 tid를 가진 자식 프로세스 가져오기
	struct thread* child_thread = get_child_process(child_tid);
	//그런 자식 없다면 return
	if (child_thread == NULL)
		return -1;
	
	//자식 프로세스가 종료될 때(라기보단 종료 직전)까지 기다리기
	sema_down(&child_thread -> wait_sema);

	//종료된 것이 확인되면, 현재 프로세스의 child_list에서 종료된 자식 삭제
	list_remove(&child_thread -> child_elem);

	//자식 프로세스에게 진짜 종료되도 좋다는 시그널 보내기
	sema_up(&child_thread -> exit_sema);

	//자식 스레드의 상태 return
	/*
	Executing 'exec-boundary':
	(exec-boundary) begin
	(child-simple) run
	child-simple: exit(81)
	(exec-boundary) fork
	(exec-boundary) wait
	(exec-boundary) wait: FAILED
	exec-boundary: exit(1)
	오류 해결 : return 값을 child_thread의 status가 아닌 exit_status로 해줘야 함
	status는 무조건 0, 1, 2, 3으로 고정되어 있음.
	*/
	return child_thread -> exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	//주석 작성 필요
	// for (int fd = 0; fd < curr -> fd_idx ; fd++)
	// 	close(fd);
	for (int i = 3; i < FDT_COUNT_LIMIT; i++)
	{
		if (curr->fdt[i] != NULL)
			close(i);
	}
	palloc_free_multiple(curr -> fdt, FDT_PAGES);

	file_close(curr -> running_file);

	process_cleanup ();

	//종료 임박했다는 시그널을 부모에게 보내기
	sema_up(&curr->wait_sema);
	//종료되도 좋다는 시그널을 부모로부터 받기
	sema_down(&curr -> exit_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;
	//현재 프로세스에 실행중인 파일 등록
	t -> running_file = file;
	//실행 중인 파일에 write할 수 없도록 deny하기
	//global lock만으로는 부족한걸까?
	//filesys_lock : 운영체제 상에서 프로세스/스레드가 파일을 조작하는 행위 자체에 대한 lock
	//하나의 프로세스가 filesys_lock을 소유하고 있으면, 나머지 프로세스는 자기 차례에 (다른 파일에 대해서도) open, close 등이 불가능
	//file_deny_write : 특정 파일을 프로세스 / 스레드가 조작하는 행위에 대한 세마포어
	//어느 프로세스가 A라는 파일을 실행 중이라면, 다른 프로세스는 자신의 턴이 오더라도 그 파일에 대한 조작을 할 수 없음.(다른 파일에 대한 조작은 가능)
	file_deny_write(file);
	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	//Kernel PANIC at ../../filesys/inode.c:304 in inode_allow_write(): assertion `inode->deny_write_cnt > 0' failed. 오류 해결
	//파일 열자마자 닫아버리면 file의 inode의 deny_write_cnt가 0이 되어버려 이후에 file_close가 이루어지지 않는다.
	//file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

//tid를 통해서 현재 스레드의 자식 스레드 구조체를 받아오는 함수
struct thread *
get_child_process(int tid)
{
	struct thread* current_t = thread_current();
	struct thread* temp;

	//현재 스레드의 child_list 순회
	for (struct list_elem* t = list_begin(&current_t -> child_list); t != list_end(&current_t -> child_list); t = list_next(t))
	{	
		//list_elem에서 thread 구조체 복원
		temp = list_entry(t, struct thread, child_elem);

		//만약 temp의 tid가 매개변수 tid과 같다면
		if (temp -> tid == tid)
			return temp;
	}
	//일치하는 tid가 없다면
	return NULL;
}

int process_add_file(struct file* f)
{
	struct thread *current_t = thread_current();
	
	//현재 스레드의 fd_idx가 한계 수치보다 작고, 테이블에 빈 공간을 만날때까지
	while(current_t -> fd_idx <= FDT_COUNT_LIMIT && current_t -> fdt[current_t -> fd_idx] != NULL)
	{
		//fd_idx 증가
		current_t -> fd_idx += 1;
	}
	//현재 fdt가 한계까지 꽉 찬 경우
	if (current_t -> fd_idx > FDT_COUNT_LIMIT)
		return -1; //바로 return
	//현재 스레드의 fdt의 빈 공간에 매개변수로 입력받은 파일 할당
	current_t -> fdt[current_t -> fd_idx] = f;

	//할당된 파일의 fdt에서의 인덱스를 리턴
	return current_t -> fd_idx;

}

//없으면 NULL 반환
struct file* process_get_file(int fd)
{
	//현재 스레드 정보 갖고오기
	struct thread* current_t = thread_current();
	//매개변수로 받아온 파일 디스크립터와 일치하는 파일 정보가 들어갈 변수 result_file
	struct file* result_file = NULL;
	
	// //현재 스레드의 fdt 전체 순회
	// //3부터 순회하는 이유 : 0에는 stdin, 1에는 stdout, 2에는 stderr가 예약됨
	// for (int i = 3; i <= current_t -> fd_idx; i++)
	// {
	// 	//만약 fdt[fd]에 파일이 할당되어 있으면
	// 	if (i == fd)
	// 		result_file = current_t -> fdt[i]; //result_file에 복사
	// }

	if (fd >= 0 && fd <= FDT_COUNT_LIMIT)
		result_file = current_t -> fdt[fd];

	return result_file;
}


void process_close_file(int fd)
{
	//현재 스레드 정보 가져오기
	struct thread* current_t = thread_current();
	//매개변수로 받은 파일 디스크립터 인덱스가 0미만(오류)이거나, 최대 한도보다 크면
	if (fd < 0 || fd >= FDT_COUNT_LIMIT)
		return;
	//fdt에서 매개변수로 받아온 fd 인덱스의 파일 할당 해제
	current_t -> fdt[fd] = NULL;
	return;
}