#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>	// for mmap

const size_t SIZE = 1024;
typedef long (*JittedFunc)(long);

static void* alloc_writable_memory(size_t size)
{
    void* ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == (void*)-1) {
        perror("mmap");
        return NULL;
    }
    return ptr;
}

static void copy_code_into_memory(unsigned char* m)
{
	unsigned char code[] = {
		0x48, 0x89, 0xf8, 		// mov %rdi, %rax
		0x48, 0x83, 0xc0, 0x01, // add $1, %rax
		0xc3					// ret
	};
    memcpy(m, code, sizeof(code));
}

static int make_memory_executable(void* m, size_t size)
{
	if (mprotect(m, size, PROT_READ | PROT_EXEC) == -1) {
		perror("mprotect");
		return -1;
	}
	return 0;
}

static void run_code(void)
{
	JittedFunc func;
	int result;
	void* m = alloc_writable_memory(SIZE);

	copy_code_into_memory(m);
	make_memory_executable(m, SIZE);

	func = m;
	result = func(1000);
	printf("result = %d\n", result);
}

int main(int argc, char *argv[])
{
    run_code();
    return 0;
}
