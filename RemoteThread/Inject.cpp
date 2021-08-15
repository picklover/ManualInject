#include <windows.h>
#include <stdio.h>
#include <assert.h>
char dllnamepath[128];
int main(int argc,char* argv[])
{
	if (argc != 3)
	{
		printf("Usage: inject pid dllpath\n");
		return 0;
	}
	int pid = atoi(argv[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	assert(hProcess);
	char* namebuffer = (char*)VirtualAllocEx(hProcess, 0, strlen(argv[2]) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	assert(namebuffer);
	WriteProcessMemory(hProcess, namebuffer, argv[2], strlen(argv[2]) + 1, NULL);
	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA,namebuffer, 0, NULL);
	return 0;
}