#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA    = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress  = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDLL, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	HINSTANCE hMod;
	ULONGLONG _imagebase;

	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	f_DLL_ENTRY_POINT _oep;

	//  manual loadlibrary
	DWORD RelocSize;
	DWORD RelocAddress;
	DWORD ImportSize;
	DWORD ImportAddress;
	DWORD TlsSize;
	DWORD TlsAddress;
};

void ManualInject(const char* szProc, const char* szDllFile);