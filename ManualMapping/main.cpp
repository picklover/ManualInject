#include "minject.h"

BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

int main(int argc,char* argv[])
{

	if (argc != 3)
	{
		printf("[Usage]: minject targetProcess dllfile\n");
		return 0;
	}

	EnableDebugPrivilege();
	
	ManualInject(argv[1],argv[2]);

	system("PAUSE");
	return 0;
}