#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	//파일 간의 경쟁 상황을 막기 위한 global lock 초기화
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	//Linux에서 시스템 콜의 번호는 rax에 저장됨
	uint64_t number = f -> R.rax;
	//나머지 인자의 레지스터 순서 : %rdi, %rsi, %rdx, %r10, %r8, %r9
	//참고 : https://rninche01.tistory.com/entry/Linux-system-call-table-%EC%A0%95%EB%A6%ACx86-x64
	//리턴값이 있는 시스템 콜의 경우, 리턴 값을 %rax(32비트면 %eax)에 저장해야 한다
	switch(number)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			//void exit(int status)
			exit(f -> R.rdi);
			break;
		case SYS_EXEC:
			//int exec(const char *file)
			f -> R.rax = exec(f -> R.rdi);
			break;
		case SYS_WAIT:
			//int wait(pid_t)
			f -> R.rax = wait(f -> R.rdi);
			break;
		case SYS_FORK:
			//pid_t fork(const char *thread_name)
			f -> R.rax = fork(f -> R.rdi);
		case SYS_OPEN:
			//int open(const char *file)
			f -> R.rax = open(f -> R.rdi);
		case SYS_CLOSE:
			//void close(int fd)
			close(f -> R.rdi);
		case SYS_CREATE:
			//bool create(const char *file, unsigned initial_size)
			f -> R.rax = create(f -> R.rdi, f -> R.rsi);
		case SYS_REMOVE:
			//bool remove(const char *file)
			f -> R.rax = remove(f -> R.rdi);
		case SYS_FILESIZE:
			//int filesize(int fd)
			f -> R.rax = filesize(f -> R.rdi);
		case SYS_READ:
			//int read(int fd, void *buffer, unsigned length)
			f -> R.rax = read(f -> R.rdi, f -> R.rsi, f -> R.rdx);
		case SYS_WRITE:
			//int write(int fd, const void *buffer, unsigned length)
			f -> R.rax = write(f -> R.rdi, f -> R.rsi, f -> R.rdx);
		case SYS_SEEK:
			//void seek(int fd, unsigned position)
			seek(f -> R.rdi, f -> R.rsi);
		case SYS_TELL:
			//unsigned tell(int fd)
			tell(f -> R.rdi);
		
		default:
			exit(-1);
	}

	thread_exit ();
}

//유저가 건네준 메모리 주소가 유효한지를 판별하는 함수 check_address
void check_address(void * address)
{
	//현재 스레드에서 pml4를 받아오기 위해 현재 스레드 정보 받아오기
	//pml4 : Page Map Level 4, x86-64 아키텍처에서 가상 주소를 물리 주소로 변환할때 사용함
	struct thread * current_t = thread_current();

	//건네받은 주소가 커널 영역의 주소거나, NULL이거나, 현재 스레드의 페이지 맵 레벨 4 테이블에 주소가 없는 경우
	if (is_kernel_vaddr(address) || address == NULL || pml4_get_page(current_t -> pml4, address) == NULL)
	{	
		//실행 종료
		exit(-1);
	}
}

//void halt(void) NO_RETURN
void halt(void)
{
	power_off();
}

//void exit(int status) NO_RETURN
void exit(int status)
{
	//프로세스 이름 : exit(status)가 출력되어야 함
	printf("%s: exit(%d)\n", thread_current() -> name, thread_current() -> status);

	thread_exit();
}

//int exec(const char *cmd_line)
int exec(const char *cmd_line)
{
	//만약 cmd_line이 유효하지 않다면
	if (cmd_line == NULL)
		exit(-1);
	
	//원본 cmd_line의 복사본을 담을 char 포인터 변수 temp_str
	//process_exec을 호출해 커맨드 라인을 파싱하는 과정을 거쳐야 하는데
	//cmd_line은 const char이기 때문에 수정이 불가능함
	char * temp_str;
	//palloc_get_page로 메모리 공간 할당 받기(할당할 공간이 없으면 NULL 반환)
	//메모리 공간 할당을 palloc으로 받는 이유
	//커널 공간에서 메모리 공간을 정렬하고 보호하기 위함
	temp_str = palloc_get_page(0);
	//palloc으로 페이지 공간을 할당하지 못하면 exit하기
	if (temp_str == NULL)
		exit(-1);
	//cmd_line의 내용을 temp_str로 PGSIZE(페이지 크기)만큼 복사
	//strcpy를 안쓰고 strlcpy를 쓰는 이유 : string.h에 쓰지 말라고 선언되어 있음
	strlcpy(cmd_line, temp_str, PGSIZE);

	//process_exec을 실행에 실패하면 exit
	if(process_exec(temp_str) == -1)
		exit(-1);
	
}

//int wait(pid_t)
int wait(int pid)
{
	return process_wait(pid);
}

//pid_t fork(const char *thread_name)
int fork(const char *thread_name)
{	
	//fork를 요청한 스레드가 유효한 스레드인지 확인
	check_address(thread_name);

	//process_fork 호출(자식의 pid return)
	return process_fork(thread_current(), NULL);
}

int open (const char *file)
{

}

void close(int fd) {
	//구현하기
    return;
}

bool create(const char *file, unsigned initial_size)
{

}

bool remove(const char *file)
{

}

int filesize(int fd)
{

}

int read(int fd, void *buffer, unsigned size)
{

}

int write(int fd, const void *buffer, unsigned length)
{

}

void seek (int fd, unsigned position)
{

}

unsigned tell (int fd)
{
	
}