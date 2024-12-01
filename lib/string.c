#include <string.h>
#include <debug.h>

/* SRC에서 DST로 SIZE 바이트를 복사합니다. 두 메모리 블록이 겹치지 않아야 합니다.
   DST를 반환합니다. */
void *
memcpy(void *dst_, const void *src_, size_t size)
{
	unsigned char *dst = dst_;
	const unsigned char *src = src_;

	ASSERT(dst != NULL || size == 0);
	ASSERT(src != NULL || size == 0);

	while (size-- > 0)
		*dst++ = *src++;

	return dst_;
}

/* SRC에서 DST로 SIZE 바이트를 복사합니다. 두 메모리 블록이 겹칠 수 있습니다.
   DST를 반환합니다. */
void *
memmove(void *dst_, const void *src_, size_t size)
{
	unsigned char *dst = dst_;
	const unsigned char *src = src_;

	ASSERT(dst != NULL || size == 0);
	ASSERT(src != NULL || size == 0);

	if (dst < src)
	{
		while (size-- > 0)
			*dst++ = *src++;
	}
	else
	{
		dst += size;
		src += size;
		while (size-- > 0)
			*--dst = *--src;
	}

	return dst;
}

/* A와 B의 두 블록에서 SIZE 바이트의 첫 번째 차이 나는 바이트를 찾습니다.
   A의 바이트가 더 크면 양수 값을 반환하고, B의 바이트가 더 크면 음수 값을 반환하며,
   A와 B가 같으면 0을 반환합니다. */
int memcmp(const void *a_, const void *b_, size_t size)
{
	const unsigned char *a = a_;
	const unsigned char *b = b_;

	ASSERT(a != NULL || size == 0);
	ASSERT(b != NULL || size == 0);

	for (; size-- > 0; a++, b++)
		if (*a != *b)
			return *a > *b ? +1 : -1;
	return 0;
}

/* 문자열 A와 B에서 첫 번째 차이 나는 문자를 찾습니다.
   A의 문자가 더 크면 양수 값을 반환하고, B의 문자가 더 크면 음수 값을 반환하며,
   A와 B가 같으면 0을 반환합니다. */
int strcmp(const char *a_, const char *b_)
{
	const unsigned char *a = (const unsigned char *)a_;
	const unsigned char *b = (const unsigned char *)b_;

	ASSERT(a != NULL);
	ASSERT(b != NULL);

	while (*a != '\0' && *a == *b)
	{
		a++;
		b++;
	}

	return *a < *b ? -1 : *a > *b;
}

/* BLOCK의 처음 SIZE 바이트에서 CH의 첫 번째 발생 위치를 반환합니다.
   CH가 BLOCK에 없으면 null 포인터를 반환합니다. */
void *
memchr(const void *block_, int ch_, size_t size)
{
	const unsigned char *block = block_;
	unsigned char ch = ch_;

	ASSERT(block != NULL || size == 0);

	for (; size-- > 0; block++)
		if (*block == ch)
			return (void *)block;

	return NULL;
}

/* STRING에서 C의 첫 번째 발생 위치를 찾고 반환합니다. C가 STRING에 없으면
   null 포인터를 반환합니다. C가 '\0'이면 STRING의 끝에 있는 null 종료자에 대한 포인터를 반환합니다. */
char *
strchr(const char *string, int c_)
{
	char c = c_;

	ASSERT(string);

	for (;;)
		if (*string == c)
			return (char *)string;
		else if (*string == '\0')
			return NULL;
		else
			string++;
}

/* STRING의 초기 부분에서 STOP에 없는 문자의 길이를 반환합니다. */
size_t
strcspn(const char *string, const char *stop)
{
	size_t length;

	for (length = 0; string[length] != '\0'; length++)
		if (strchr(stop, string[length]) != NULL)
			break;
	return length;
}

/* STRING에서 STOP에 있는 첫 번째 문자의 포인터를 반환합니다.
   STRING에 STOP에 있는 문자가 없으면 null 포인터를 반환합니다. */
char *
strpbrk(const char *string, const char *stop)
{
	for (; *string != '\0'; string++)
		if (strchr(stop, *string) != NULL)
			return (char *)string;
	return NULL;
}

/* STRING에서 C의 마지막 발생 위치를 반환합니다.
   C가 STRING에 없으면 null 포인터를 반환합니다. */
char *
strrchr(const char *string, int c_)
{
	char c = c_;
	const char *p = NULL;

	for (; *string != '\0'; string++)
		if (*string == c)
			p = string;
	return (char *)p;
}

/* STRING의 초기 부분에서 SKIP에 있는 문자의 길이를 반환합니다. */
size_t
strspn(const char *string, const char *skip)
{
	size_t length;

	for (length = 0; string[length] != '\0'; length++)
		if (strchr(skip, string[length]) == NULL)
			break;
	return length;
}

/* HAYSTACK 내에서 NEEDLE의 첫 번째 발생 위치를 반환합니다.
   NEEDLE이 HAYSTACK에 없으면 null 포인터를 반환합니다. */
char *
strstr(const char *haystack, const char *needle)
{
	size_t haystack_len = strlen(haystack);
	size_t needle_len = strlen(needle);

	if (haystack_len >= needle_len)
	{
		size_t i;

		for (i = 0; i <= haystack_len - needle_len; i++)
			if (!memcmp(haystack + i, needle, needle_len))
				return (char *)haystack + i;
	}

	return NULL;
}

/* DELIMITERS로 구분된 토큰으로 문자열을 나눕니다.
   이 함수가 처음 호출될 때 S는 토큰화할 문자열이어야 하며,
   이후 호출에서는 null 포인터여야 합니다.
   SAVE_PTR는 토크나이저의 위치를 추적하는 데 사용되는 `char *' 변수의 주소입니다.
   매번 반환 값은 문자열의 다음 토큰이거나, 더 이상 토큰이 없으면 null 포인터입니다. */
char *
strtok_r(char *s, const char *delimiters, char **save_ptr)
{
	char *token;

	ASSERT(delimiters != NULL);
	ASSERT(save_ptr != NULL);

	/* S가 null이 아니면 S에서 시작합니다.
	   S가 null이면 저장된 위치에서 시작합니다. */
	if (s == NULL)
		s = *save_ptr;
	ASSERT(s != NULL);

	/* 현재 위치에서 DELIMITERS를 건너뜁니다. */
	while (strchr(delimiters, *s) != NULL)
	{
		/* strchr()는 null 바이트를 검색할 때 항상 null이 아닌 값을 반환합니다.
		   모든 문자열은 null 바이트(끝에)가 포함되어 있기 때문입니다. */
		if (*s == '\0')
		{
			*save_ptr = s;
			return NULL;
		}

		s++;
	}

	/* 문자열의 끝까지 비-DELIMITERS를 건너뜁니다. */
	token = s;
	while (strchr(delimiters, *s) == NULL)
		s++;
	if (*s != '\0')
	{
		*s = '\0';
		*save_ptr = s + 1;
	}
	else
		*save_ptr = s;
	return token;
}

/* DST의 SIZE 바이트를 VALUE로 설정합니다. */
void *
memset(void *dst_, int value, size_t size)
{
	unsigned char *dst = dst_;

	ASSERT(dst != NULL || size == 0);

	while (size-- > 0)
		*dst++ = value;

	return dst_;
}

/* STRING의 길이를 반환합니다. */
size_t
strlen(const char *string)
{
	const char *p;

	ASSERT(string);

	for (p = string; *p != '\0'; p++)
		continue;
	return p - string;
}

/* STRING의 길이가 MAXLEN보다 작으면 실제 길이를 반환합니다.
   그렇지 않으면 MAXLEN을 반환합니다. */
size_t
strnlen(const char *string, size_t maxlen)
{
	size_t length;

	for (length = 0; string[length] != '\0' && length < maxlen; length++)
		continue;
	return length;
}

/* 문자열 SRC를 DST로 복사합니다. SRC가 SIZE - 1 문자보다 길면
   SIZE - 1 문자만 복사됩니다. null 종료자는 SIZE가 0이 아닌 한 항상 DST에 기록됩니다.
   null 종료자를 포함하지 않는 SRC의 길이를 반환합니다. */
size_t
strlcpy(char *dst, const char *src, size_t size)
{
	size_t src_len;

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	src_len = strlen(src);
	if (size > 0)
	{
		size_t dst_len = size - 1;
		if (src_len < dst_len)
			dst_len = src_len;
		memcpy(dst, src, dst_len);
		dst[dst_len] = '\0';
	}
	return src_len;
}

/* 문자열 SRC를 DST에 연결합니다. 연결된 문자열은 SIZE - 1 문자로 제한됩니다.
   null 종료자는 SIZE가 0이 아닌 한 항상 DST에 기록됩니다.
   null 종료자를 포함하지 않는 연결된 문자열의 길이를 반환합니다. */
size_t
strlcat(char *dst, const char *src, size_t size)
{
	size_t src_len, dst_len;

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	src_len = strlen(src);
	dst_len = strlen(dst);
	if (size > 0 && dst_len < size)
	{
		size_t copy_cnt = size - dst_len - 1;
		if (src_len < copy_cnt)
			copy_cnt = src_len;
		memcpy(dst + dst_len, src, copy_cnt);
		dst[dst_len + copy_cnt] = '\0';
	}
	return src_len + dst_len;
}