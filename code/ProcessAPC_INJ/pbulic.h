#pragma once
#include<ntifs.h>


//提示：
//ethread = threadList - 0x2f8
//switchCount = (ULONG*)ethread + 85;
typedef struct
{
    //R3 = 0x28
    DWORD64 Unown0[5];
    DWORD64 DirectoryTableBase;   //指向页目录表基地址
    LIST_ENTRY ThreadListHead; //双向链表, 该链表记录了该进程的所有线程
                                //ethread = thread - 0x2f8
    ULONG ProcessLock;  //自旋锁，用于保护数据同步
}KPROCESS_WIN11, *PKPROCESS_WIN11;

typedef struct
{
    DWORD64 LoadLibraryW;
    WCHAR DllPath[128];
}INJDLL_INBUFFER, *PINJDLL_INBUFFER;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

#define SystemProcessInformation 5


NTSTATUS ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

#define IoPassCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED|METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoInjectDll CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED|METHOD_OUT_DIRECT, FILE_ANY_ACCESS)