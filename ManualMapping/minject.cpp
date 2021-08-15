#include "minject.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0c) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0c) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData) return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = pData->_oep;

	//fix relocation table

	BYTE* LocationDelta = pBase - pData->_imagebase; //offset
	if (pData->RelocSize && LocationDelta)
	{
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pData->RelocAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			for (UINT i = 0; i != AmountOfEntries; i++, pRelativeInfo++)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}


	if (pData->ImportSize)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pData->ImportAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
			if (!pThunkRef)
				pThunkRef = pFuncRef;
			for (; *pThunkRef; pThunkRef++, pFuncRef++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			pImportDescr++;
		}
	}

	if (pData->TlsSize)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pData->TlsAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	DWORD dwCheck = 0;
	if (!GetFileAttributesA(szDllFile))
	{
		printf("File doesn't exist\n");
		return false;
	}

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		printf("Open the file failed!\n");
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		printf("FileSize is invalid.\n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData)
	{
		printf("Memory allocating failed\n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Memory allocation failed: 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}

	}

	printf("ImageBase:0x%I64X\n", pTargetBase);

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);
	data._oep = reinterpret_cast<f_DLL_ENTRY_POINT>(pTargetBase + pOldOptHeader->AddressOfEntryPoint);
	data._imagebase = pOldOptHeader->ImageBase;

	data.RelocSize    = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	data.RelocAddress = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	data.ImportSize = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	data.ImportAddress = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	data.TlsSize = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	data.TlsAddress = pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Can't map sections: 0x%X\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
				return false;
			}
		}
	}
	delete[] pSrcData;

	WriteProcessMemory(hProc, pTargetBase, &data,sizeof(data), nullptr);

	
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("Memory allocation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x200, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread)
	{
		printf("create thread failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return true;
 }

 DWORD GetPID(const char* szProc)
 {
	 PROCESSENTRY32 PE32{ 0 };
	 PE32.dwSize = sizeof(PE32);
	 HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	 if (hSnap == INVALID_HANDLE_VALUE)
	 {
		 DWORD Err = GetLastError();
		 printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		 return -1;
	 }
	 DWORD PID = 0;
	 BOOL bRet = Process32First(hSnap, &PE32);
	 while (bRet)
	 {
		 if (!strcmp(szProc, PE32.szExeFile))
		 {
			 PID = PE32.th32ProcessID;
			 break;
		 }
		 bRet = Process32Next(hSnap, &PE32);
	 }
	 CloseHandle(hSnap);
	 return PID;
 }
 void ManualInject(const char* szProc, const char* szDllFile)
 {
	 HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPID(szProc));
	 if (!hProc)
	 {
		 DWORD Err = GetLastError();
		 printf("OpenProcess failed: 0x%x\n", Err);
		 return;
	 }

	 if (ManualMap(hProc, szDllFile))
		 printf("Injection Success!\n");
	 else
		 printf("Injection failed!\n");
	 CloseHandle(hProc);
	 return;
 }