/*
    This file is licensed under a Creative Commons "Share Alike" license
    https://creativecommons.org/licenses/by-sa/4.0/

    You must indicate that derivative work 
    "Is derived from Cedric Halbronn's 
    'Exploitation 4011 - Windows Kernel Exploitation' 
    class, available at https://ost2.fyi"
*/

#pragma once
#include <windows.h>

#define CORE_ID_0 0
#define CORE_ID_1 1

void early_exit(int);
int get_core_count(void);
BOOL set_thread_priority(HANDLE, int);
BOOL set_priority(int);
BOOL set_priority_and_class(int, int);
BOOL pin_name_to_cpu(char*, size_t, BOOL);
HANDLE xCreateThread(void*, void*, PDWORD, BOOL );
DWORD GetProcessIDByName(const wchar_t*);
void CreateProcessFromHandle(HANDLE);
int spwan_cmd_system();