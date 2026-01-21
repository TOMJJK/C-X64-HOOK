#pragma once
#include "enummd.h"


PPEB PsGetProcessPeb(PEPROCESS);
NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SrcProcess, PVOID SourceAddr,
    PEPROCESS TargetProcess, PVOID TargetAddr,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberBytesCopied);

DWORD64 GetModuleHandleByName(PEPROCESS Process, PWCHAR ModName)
{
    PPEB64 peb = NULL;
    DWORD64 mdBase = 0;
    PVOID buffer = NULL;
    NTSTATUS status = 0;
    DWORD64 dwRet = 0;
    PPEB_LDR_DATA_64 ldr = NULL;
    PEPROCESS psCur = NULL;
    PLDR_DATA_TABLE_ENTRY_64 ldrData = NULL;


    psCur = PsGetCurrentProcess();

    do
    {
        if (Process == NULL || ModName == NULL)
        {
            KdPrint(("参数错误\n"));
            break;
        }

        if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
        {
            KdPrint(("目标进程已结束\n"));
            break;
        }

        buffer = ExAllocatePool(PagedPool, 4096);

        if (buffer == NULL)
        {
            KdPrint(("内存不足\n"));
            break;
        }

        RtlZeroMemory(buffer, PAGE_SIZE);

        peb = PsGetProcessPeb(Process);

        if (peb == NULL)
        {
            KdPrint(("peb = 0\n"));
            break;
        }

        //读PEB
        status = MmCopyVirtualMemory(
            Process,
            (PVOID)peb,
            psCur,
            buffer,
            sizeof(PEB64),
            KernelMode,
            &dwRet);

        if (!NT_SUCCESS(status) || dwRet == 0)
        {
            KdPrint(("读内存错误peb\n"));
            break;
        }

        peb = (PPEB64)buffer;

        ldr = peb->Ldr;

        status = MmCopyVirtualMemory(
            Process,
            (PVOID)ldr,
            psCur,
            buffer,
            sizeof(PEB_LDR_DATA_64),
            KernelMode,
            &dwRet);

        if (!NT_SUCCESS(status) || dwRet == 0)
        {
            KdPrint(("读内存错误 ldr \n"));
            break;
        }

        ldr = (PPEB_LDR_DATA_64)buffer;

        PVOID head = (PVOID)ldr->InLoadOrderModuleList.Flink;
        PVOID empty = (PVOID)ldr->InLoadOrderModuleList.Blink;
        PVOID entry = (PVOID)ldr->InLoadOrderModuleList.Flink;

        //KdPrint(("模块名称\t模块基地址\t模块大小\t路径\n"));

        ldrData = (PLDR_DATA_TABLE_ENTRY_64)buffer;

        while (TRUE)
        {
            MmCopyVirtualMemory(
                Process,
                entry,
                psCur,
                buffer,
                sizeof(LDR_DATA_TABLE_ENTRY_64),
                KernelMode,
                &dwRet);

            //读到错误内存
            if (ldrData->InLoadOrderLinks.Flink == NULL)
            {
                break;
            }

            //空节点，不需要输出信息
            if (ldrData->InLoadOrderLinks.Flink == head)
            {
                break;
            }

            DWORD64 nextEntry = (PVOID)ldrData->InLoadOrderLinks.Flink;
            PWCHAR modName = ldrData->BaseDllName.Buffer;
            DWORD64 modBase = ldrData->DllBase;
            DWORD64 modSize = ldrData->SizeOfImage;
            ULONG nameLen = ldrData->BaseDllName.Length;


            //保证缓冲区干净
            RtlZeroMemory(buffer, 256);

            MmCopyVirtualMemory(Process, (PVOID)modName,
                psCur, buffer,
                nameLen,
                KernelMode,
                &dwRet);

            modName = (PWCHAR)buffer;

            if(wcscmp(modName, ModName) == 0)
            {
                mdBase = modBase;

                KdPrint(("%ls = %llX\n", modName, modBase));
                break;
            }

            
            //KdPrint(("%ws\t%0llX\t%0llX\n",
            //    modName, modBase,
            //    modSize));

            entry = nextEntry;

            RtlZeroMemory((PVOID)ldrData, sizeof(LDR_DATA_TABLE_ENTRY_64));
        }

    } while (FALSE);

    if (buffer)
    {
        ExFreePool(buffer);
    }

    return mdBase;
}