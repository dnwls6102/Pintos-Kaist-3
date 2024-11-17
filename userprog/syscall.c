#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
int fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

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
	//printf ("system call!\n");
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
			/*
			../../userprog/syscall.c:234:6: error: conflicting types for ‘remove’
			../../userprog/syscall.c:87:17: note: previous implicit declaration of ‘remove’ was here
    		f -> R.rax = remove(f -> R.rdi);
			//프로토타입이 선언된 파일(lib/user/syscall.h)를 포함하지 않고 바로 써서 나온 오류
			*/
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
	printf("OPEN\n");
	//매개변수로 건네받은 file이 유효한지 검사
	check_address(file);
	//파일을 여는 도중에 다른 프로세스가 파일 디스크립터를 해제하는 것을 방지
	lock_acquire(&filesys_lock);
	//열려고 하는 파일의 file descriptor 반환
	struct file* open_file = filesys_open(file);
	//만약 파일 open에 실패했다면
	if (open_file == NULL)
	{	
		//lock 풀어주고 바로 return
		lock_release(&filesys_lock);
		return -1;
	}

	//process의 fdt에 file을 할당하기
	//오류가 나면 -1을 반환, 그렇지 않다면 파일의 인덱스 반환
	int fd = process_add_file(file);

	//fdt에 할당을 실패했다면 : 파일 닫기
	if (fd == -1)
		file_close(open_file);

	//lock 해제
	lock_release(&filesys_lock);

	return fd;
}

void close(int fd) {
	//구현하기
    return;
}

bool create(const char *file, unsigned initial_size)
{
	//매개변수로 건네받은 file이 유효한지 검사
	check_address(file);
	//파일을 생성하는 중에 다른 프로세스가 이 파일이 포함된 디렉터리 구조를 변경하려고 하면 안됨
	lock_acquire(&filesys_lock);
	//결과값 저장
	bool result = filesys_create(file, initial_size);
	//lock 해제
	lock_release(&filesys_lock);

	return result;
}

bool remove(const char *file)
{
	//file이 유효한지 검사
	check_address(file);
	//create와 비슷한 맥락에서, 삭제하려는 순간 그 파일이 포함된 디렉터리 구조가 변경되면 안됨
	lock_acquire(&filesys_lock);
	//결과값 저장
	bool result = filesys_remove(file);
	//lock 해제
	lock_release(&filesys_lock);

	return result;
}

int filesize(int fd)
{
	//매개변수로 입력받은 fd와 동일한 값을 지닌 file 가져오기
	struct file* f = process_get_file(fd);
	//만약 유효하지 않은 파일이다 : return -1
	if (f == NULL)
		return -1;
	//파일의 크기 반환
	return file_length(f);
}

//fd에서 얼마만큼의 데이터를 읽었는지를(크기를) 반환
int read(int fd, void *buffer, unsigned size)
{
	//buffer가 유효한지 검사
	check_address(buffer);
	int result;
	//매개변수로 입력받은 fd와 동일한 값을 지닌 file 가져오기
	struct file* f = process_get_file(fd);
	//파일이 유효하지 않거나, stdout, stderr를 읽으려고 하는 경우
	if (f == NULL || f == STDOUT || f == STDERR)
		return -1;
	//읽어오는 도중에 write가 일어나면 안되니 lock 걸기
	lock_acquire(&filesys_lock); 
	//만약 매개변수 fd가 0이다 == stdin에 저장된 데이터를 읽겠다
	//input_getc()로 읽어오면 됨
	if (f == STDIN)
	{
		int i = 0;
		char c;
		//매개변수 size만큼
		for (i; i < size; i++)
		{
			//input_getc()로 stdin에서 한 글자 읽어오기
			c = input_getc();
			//buffer에 stdin에서 가져온 문자 입력
			//오류나면 포인터 형변환 해보기
			//error: invalid use of void expression
			//형변환 해주니 문제 해결
			*(char *)(buffer++) = c;
			//문자열 종료 문자 만나면 break
			if (c == '\0')
				break;
		}
		//lock 풀어주기
		lock_release(&filesys_lock);
		return i;
	}
		
	//file_read로 f의 데이터를 size만큼 읽어와서 buffer에 저장
	result = file_read(f, buffer, size);
	//lock 풀어주기
	lock_release(&filesys_lock);
	
	return result;

}

//fd 파일에 buffer에 있는 내용을 length만큼 작성
int write(int fd, const void *buffer, unsigned length)
{
	//buffer가 유효한지 확인
	check_address(buffer);
	int result = -1;
	struct file* f = process_get_file(fd);
	//만약 파일이 유효하지 않거나, STDIN에 데이터를 작성하려고 하면
	if (f == NULL || f == STDIN)
	{
		return result;
	}
	//write하는 동안 파일이 삭제되면 안되므로 lock
	lock_acquire(&filesys_lock);
	//만약 stdin으로 쓰는거면 : putbuf 함수로 입력
	if (f == STDOUT || f == STDERR)
	{
		putbuf(buffer, length);
		lock_release(&filesys_lock);
		return length;
	}
	result = file_write(f, buffer, length);
	lock_release(&filesys_lock);
	return result;

}

void seek (int fd, unsigned position)
{
	struct file* f = process_get_file(fd);
	//파일이 유효하지 않거나, 지금 STDIN과 STDERR 사이를 읽고 있는 경우 return
	if (f == NULL || (f >= STDIN && f <= STDERR))
		return;

	file_seek(f, position);
}

unsigned tell (int fd)
{
	struct file* f = process_get_file(fd);
	//파일이 유효하지 않거나, 지금 STDIN과 STDERR 사이를 읽고 있는 경우 return
	if (f == NULL || (f >= STDIN && f <= STDERR))
		return -1;

	return file_tell(f);
}