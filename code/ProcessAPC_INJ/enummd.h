#pragma once
#include<ntddk.h>

typedef struct _PEB_LDR_DATA_64
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;    //∞≤º”‘ÿÀ≥–Ú≈≈¡–
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitalizationOrderModuleList;
} PEB_LDR_DATA_64, * PPEB_LDR_DATA_64;

typedef struct _LDR_DATA_TABLE_ENTRY_64
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDataStamp;
		PVOID LoadedImports;
	};

	PVOID EntryPointActivationContext;
	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY_64, * PLDR_DATA_TABLE_ENTRY_64;


typedef struct 
{
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA_64 Ldr;
}PEB64, *PPEB64;



DWORD64 GetModuleHandleByName(PEPROCESS Process, PWCHAR ModName);






