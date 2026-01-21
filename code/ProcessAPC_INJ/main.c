#pragma once
#include "pbulic.h"
#include<ntstatus.h>
#include "enummd.h"


#pragma comment(lib, "ntoskrnl.lib")

#define OriginalApcEnvironment 0

typedef struct
{
    DWORD64  Level;  //关卡数
    DWORD64  PassFunction; //过关函数
}PASSCE_DATA;

VOID KeInitializeApc(
    PRKAPC Apc,
    PETHREAD Thread,
    ULONG ApcEnvironment,
    PVOID KernelRoutine,
    PVOID RundownRoutine,
    PVOID NormalRoutine,
    KPROCESSOR_MODE ApcMode,
    PVOID NormalContext);

BOOLEAN KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgment1,
    PVOID SystemArgment2,
    KPRIORITY PriorityBoost);

//---------------------------------------------------------------

DWORD64 g_LastProcess = 0;
DWORD64 g_INJDLL = 0;

//---------------------------------------------------------


BOOLEAN DispatchInjDll(PEPROCESS Process, PVOID LoadLibaryAddr, PWCHAR DllPath);
ULONG GetTagetProcessIdByName(PWCHAR ProcessName);
BOOLEAN DispatchPassCE(DWORD64 LevelId);
PETHREAD GetProcessActiveThread(PEPROCESS Process);
BOOLEAN PostUserThreadApc(PETHREAD Thread, PVOID CallbackAddr, PVOID CallbackContext);
//------------------------------------------------------------------------


VOID KernelRoutine(
    PKAPC Apc, 
    PVOID* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2)
{
    KdPrint(("内核回调 - 用户APC\n"));

    ExFreePool((PVOID)Apc);

}


VOID AlertThreadKernelRoutine(
    PKAPC Apc,
    PVOID* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2)
{

    KIRQL irql = KeGetCurrentIrql();

    KdPrint(("内核回调 - 挂起线程 Irql = %d\n", irql));

    ExFreePool((PVOID)Apc);

}

VOID AlertThreadNormalRoutine(PVOID Context, PVOID Sys1, PVOID Sys2)
{
    ULONG tid = 0;
    LARGE_INTEGER time = { 0 };

    KIRQL irql = KeGetCurrentIrql();

    tid = HandleToUlong(PsGetCurrentThreadId());
    KdPrint(("irql = %d\n", irql));
    KdPrint(("当前线程 tid = %d\n", tid));

    time.QuadPart = 0;

    KeDelayExecutionThread(UserMode, TRUE, &time);
}


VOID DriverUnload(PDRIVER_OBJECT Driver)
{
    UNICODE_STRING win32Name = RTL_CONSTANT_STRING(L"\\??\\APC_TOOL_WIN32");

    IoDeleteSymbolicLink(&win32Name);
    
    if (Driver->DeviceObject != NULL)
    {
        IoDeleteDevice(Driver->DeviceObject);
    }

    KdPrint(("驱动卸载\n"));
}


VOID InjectApc()
{
    PETHREAD ts = NULL;
    DWORD64 callbackRoutine = 0x3ee0000;
    DWORD64 callbackArgument = 0;
    ULONG tid = 4112;
    PVOID buffer = NULL;

    NTSTATUS st = PsLookupThreadByThreadId(ULongToHandle(tid), &ts);

    do
    {
        if (ts == NULL)
        {
            KdPrint(("ts = 0\n"));
            break;
        }

        KdPrint(("ts = %0llX\n", ts));

        buffer = ExAllocatePool(NonPagedPool, sizeof(KAPC));

        if (buffer == NULL)
        {
            KdPrint(("buffer = 0\n"));
            break;
        }

        RtlZeroMemory(buffer, sizeof(KAPC));

        PKAPC apc = (PKAPC)buffer;

        KeInitializeApc(
            apc,
            ts,
            OriginalApcEnvironment,
            (PVOID)KernelRoutine,
            NULL,
            (PVOID)callbackRoutine,
            UserMode,
            (PVOID)callbackArgument);

        BOOLEAN bRet = KeInsertQueueApc(
            apc,
            NULL,
            NULL,
            0);

        if (!bRet)
        {
            KdPrint(("apc注入失败\n"));
        }
        else
        {
            KdPrint(("注入成功\n"));
        }

        //-----------------------------------------------
        //插入内核APIC，挂起线程
        //-----------------------------------------------
        buffer = NULL;

        buffer = ExAllocatePool(NonPagedPool, sizeof(KAPC));

        if (buffer)
        {
            RtlZeroMemory(buffer, sizeof(KAPC));
        }

        apc = (PKAPC)buffer;

        KeInitializeApc(apc, ts,
            OriginalApcEnvironment,
            AlertThreadKernelRoutine,
            NULL,
            AlertThreadNormalRoutine,
            KernelMode,
            NULL);

        bRet = KeInsertQueueApc(apc,
            NULL,
            NULL,
            0);

        if (bRet)
        {
            KdPrint(("内核APC插入成功\n"));
        }
        else
        {
            KdPrint(("内核APC插入失败\n"));
        }

    } while (FALSE);
}

/// <summary>
/// CreateFile：打开进程
/// </summary>
/// <param name="Device"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS CreateFn(PDEVICE_OBJECT Device, PIRP Irp)
{

    PEPROCESS ps = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG pid = GetTagetProcessIdByName(L"Tutorial-x86_64.exe");

    do
    {
        if (pid == 0)
        {
            KdPrint(("目标进程未运行\n"));
        }

        PsLookupProcessByProcessId(UlongToHandle(pid), &ps);


        if (ps == NULL)
        {
            KdPrint(("未知错误\n"));
            break;
        }

        if (PsGetProcessExitStatus(ps) != STATUS_PENDING)
        {
            KdPrint(("目标进程结束\n"));
            break;
        }

        g_LastProcess = (DWORD64)ps;

        status = STATUS_SUCCESS;

    } while (FALSE);

    //减少引用计数
    if (ps != NULL)
    {
        ObDereferenceObject((PVOID)ps);
    }

    KdPrint(("打开设备\n"));

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

/// <summary>
/// CloseHandle：关闭进程
/// </summary>
/// <param name="Device"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS CloseFn(PDEVICE_OBJECT Device, PIRP Irp)
{
    KdPrint(("关闭设备\n"));

    g_LastProcess = 0;
    g_INJDLL = 0;

    Irp->IoStatus.Status = 0;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}



NTSTATUS IoControlFn(PDEVICE_OBJECT Device, PIRP Irp)
{
    NTSTATUS status = 0;
    BOOLEAN bRet = FALSE;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    PVOID inBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuffer = MmGetSystemAddressForMdl(Irp->MdlAddress);

    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    ULONG ioCode = stack->Parameters.DeviceIoControl.IoControlCode;

    do
    {
        KdPrint(("inBuffer = %0llX outBuffer = %0llX\n", inBuffer, outBuffer));
        KdPrint(("outBuffer = %ls\n", outBuffer));

        //检查参数
        if (inBuffer == NULL || outBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            KdPrint(("参数错误\n"));
            break;
        }

        //检查地址
        if (!MmIsAddressValid(inBuffer) || !MmIsAddressValid(outBuffer))
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            KdPrint(("参数错误\n"));
            break;
        }

        switch (ioCode)
        {
        case IoInjectDll:
        {
            DWORD64 loadfn = ((PINJDLL_INBUFFER)inBuffer)->LoadLibraryW;
            PWCHAR dllPath = ((PINJDLL_INBUFFER)inBuffer)->DllPath;

            KdPrint(("dllPath = %ls\n", dllPath));

            if (DispatchInjDll(g_LastProcess, loadfn, dllPath) == FALSE)
            {
                status = STATUS_UNSUCCESSFUL;
            }

            break;
        }

        case IoPassCE:
        {
            ULONG id = *(ULONG*)inBuffer;

            KdPrint(("passCE id = %d\n", id));

            if (DispatchPassCE(id) == FALSE)
            {
                status = STATUS_UNSUCCESSFUL;
            }

            break;
        }

        default:
            break;
        }
    } while (FALSE);

    if (!NT_SUCCESS(status))
    {
        //成功写入字节数
        outLength = 0;
        wcscpy_s(outBuffer, 128, L"驱动没有提供该功能");
    }
    else
    {
        wcscpy_s(outBuffer, 128, L"执行成功!!!");
    }

    Irp->IoStatus.Status = 0;
    Irp->IoStatus.Information = outLength;

    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}



static PASSCE_DATA g_PassCE[] = {
    {1, 0},{2, 0x1000 }, {3, 0 },
    {4, 0},{5, 0},{6,0},
    {7, 0}, {8, 0}, {9, 0x1440} 
};



/// <summary>
/// PassCE调度函数
/// </summary>
/// <returns></returns>
BOOLEAN DispatchPassCE(DWORD64 LevelId)
{
    BOOLEAN bRet = FALSE;
    DWORD64 hDll = 0;

    do
    {
        //已经执行过注入操作
        if (g_INJDLL == 1)
        {
            hDll = GetModuleHandleByName(g_LastProcess, L"ProcessAPC_INJ_DLL.dll");
        }

        KdPrint(("hDll = %llX\n", hDll));

        if (hDll == 0)
        {
            break;
        }

        ULONG id = LevelId - 1;

        if (g_PassCE[id].PassFunction == 0)
        {
            break;
        }

        DWORD64 apcRoutine = hDll + g_PassCE[id].PassFunction;

        PETHREAD postThread = GetProcessActiveThread(g_LastProcess);

        if (postThread == NULL)
        {
            break;
        }
        
        bRet = PostUserThreadApc(postThread, (PVOID)apcRoutine, NULL);


    } while (FALSE);

    return bRet;

}

/// <summary>
/// 枚举系统进程
/// </summary>
/// <returns></returns>
ULONG EnumSystemProcesGetPidByName(PWCHAR ProcessName)
{
    ULONG dwBufferSize = 0;
    PVOID lpProcessInformation = NULL;
    ULONG dwRet = 0;

    NTSTATUS st = ZwQuerySystemInformation(
        SystemProcessInformation,
        NULL,
        0,
        &dwBufferSize);

    do
    {
        if (st != STATUS_INFO_LENGTH_MISMATCH)
        {
            KdPrint(("query1 st = %X\n", st));
            break;
        }

        //防止越界
        dwBufferSize += 1024;

        lpProcessInformation = ExAllocatePool(PagedPool, dwBufferSize);

        if (lpProcessInformation == NULL)
        {
            KdPrint(("系统内存不足\n"));
            break;
        }

        RtlZeroMemory(lpProcessInformation, dwBufferSize);

        st = ZwQuerySystemInformation(
            SystemProcessInformation,
            lpProcessInformation,
            dwBufferSize,
            &dwBufferSize);

        if (!NT_SUCCESS(st))
        {
            KdPrint(("查询系统进程失败 st = %0X\n", st));
            break;
        }

        PSYSTEM_PROCESS_INFORMATION lpProcess =
            (PSYSTEM_PROCESS_INFORMATION)lpProcessInformation;

        for (;;)
        {

            //最后一个节点
            if (lpProcess->NextEntryOffset == 0 && lpProcess->UniqueProcessId == 0)
            {
                break;
            }

            ULONG psId = lpProcess->UniqueProcessId;
            PWCHAR psName = lpProcess->ImageName.Buffer;

            //idle = null
            if (psName != NULL && wcscmp(psName, ProcessName) == 0)
            {
                dwRet = psId;

                KdPrint(("%ws - %d\n", psName, psId));
                break;
            }



            //处理最后一个节点不为空的情况
            if (lpProcess->NextEntryOffset == 0)
            {
                break;
            }

            //到下一个结构
            lpProcess = (PSYSTEM_PROCESS_INFORMATION)((DWORD64)lpProcess + lpProcess->NextEntryOffset);
        }

    } while (FALSE);


    if (lpProcessInformation)
    {
        ExFreePool(lpProcessInformation);
    }

    return dwRet;
}

/// <summary>
/// 进程名找进程ID
/// </summary>
/// <param name="ProcessName"></param>
/// <returns></returns>
ULONG GetTagetProcessIdByName(PWCHAR ProcessName)
{
    ULONG pid = 0;

    //包装函数进行参数检查，底层函数不检查参数
    if (ProcessName != NULL && wcslen(ProcessName) > 0)
    {
        pid = EnumSystemProcesGetPidByName(ProcessName);
    }

    return pid;
}

/// <summary>
/// 进程取活跃线程
/// </summary>
/// <returns></returns>
PETHREAD GetProcessActiveThread(PEPROCESS Process)
{
    /*
    执行流程：
    1、取进程线程列表
    2、取最活跃线程
    */

    PETHREAD curThread = NULL;
    KIRQL oldIrql = 0;

    ULONG maxSwitchCount = 0;
    PETHREAD maxActiveThread = NULL;

    PLIST_ENTRY threadList = &((PKPROCESS_WIN11)Process)->ThreadListHead;
    PKSPIN_LOCK threadLock = (PKSPIN_LOCK)(&((PKPROCESS_WIN11)Process)->ProcessLock);


    do
    {
        if (threadList == NULL)
        {
            KdPrint(("threadList == 0\n"));
            break;
        }

        KeAcquireSpinLock(threadLock, &oldIrql);


        PLIST_ENTRY curLink = threadList->Flink;

        while (TRUE)
        {
            curThread = (PETHREAD)((DWORD64)curLink - 0x2f8);

            if (!MmIsAddressValid((PVOID)curLink))
            {
                break;
            }

            ObReferenceObject((PVOID)curThread);

            ULONG switchCount = *(ULONG*)((ULONG*)curThread + 85);

            if (switchCount > maxSwitchCount)
            {
                maxSwitchCount = switchCount;
                maxActiveThread = curThread;
            }

            ObDereferenceObject((PVOID)curThread);

            //处理最后一个节点
            if (curLink->Flink == threadList)
            {
                break;
            }

            //步进到下一个节点
            curLink = curLink->Flink;

        }

        KeReleaseSpinLock(threadLock, oldIrql);



    } while (FALSE);

    //检查目标线程是否结束
    if (maxActiveThread != NULL && 
        PsGetThreadExitStatus(maxActiveThread) != STATUS_PENDING)
    {
        maxActiveThread = NULL;
    }
    else
    {
        KdPrint(("tid = %d\n", HandleToUlong(PsGetThreadId(maxActiveThread))));
    }

    return maxActiveThread;
}


/// <summary>
/// 线程投递用户模式APC
/// </summary>
/// <returns></returns>
BOOLEAN PostUserThreadApc(PETHREAD Thread, PVOID CallbackAddr, PVOID CallbackContext)
{
    BOOLEAN bRet = FALSE;
    PKAPC apc = NULL;
    PVOID buffer = NULL;

    do
    {
        if (CallbackAddr == NULL)
        {
            KdPrint(("apc回调 = 0\n"));
            break;
        }

        //----------------------------------------------------
        //先投递用户APC
        //----------------------------------------------------
        buffer = ExAllocatePool(NonPagedPool, sizeof(KAPC));

        if (buffer == NULL)
        {
            KdPrint(("buffer1 = 0\n"));
            break;
        }

        RtlZeroMemory(buffer, sizeof(KAPC));

        apc = (PKAPC)buffer;

        KeInitializeApc(apc,
            Thread,
            OriginalApcEnvironment,
            KernelRoutine,
            NULL,
            CallbackAddr,
            UserMode,
            CallbackContext);

        bRet = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

        if (!bRet)
        {
            KdPrint(("投递用户APC失败\n"));
            break;
        }

        //------------------------------------------------------
        //再投递内核APC - 挂起线程
        //------------------------------------------------------
        buffer = NULL;
        
        buffer = ExAllocatePool(NonPagedPool, sizeof(KAPC));

        if (buffer == NULL)
        {
            KdPrint(("buffer2 = 0\n"));
            break;
        }

        RtlZeroMemory(buffer, sizeof(KAPC));

        apc = (PKAPC)buffer;

        KeInitializeApc(apc,
            Thread,
            OriginalApcEnvironment,
            AlertThreadKernelRoutine,
            NULL,
            AlertThreadNormalRoutine,
            KernelMode,
            NULL);

        bRet = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

        if (!bRet)
        {
            KdPrint(("插入内核APC失败\n"));
            break;
        }

        //可忽略
        bRet = TRUE;

    } while (FALSE);


    return bRet;
}

/// <summary>
/// 进程申请远程内存写入DLL路径
/// </summary>
/// <param name="Process"></param>
/// <returns></returns>
PVOID AllocDllPath(PEPROCESS Process, PWCHAR DllPath)
{
    KAPC_STATE stack = { 0 };
    PVOID allocBase = NULL;
    NTSTATUS status = 0;

    KIRQL irql = KeGetCurrentIrql();

    DWORD64 allocSize = 4096;

    __try
    {
        KeStackAttachProcess(Process, &stack);

        status = ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &allocBase,
            0,
            &allocSize,
            MEM_COMMIT,
            PAGE_READWRITE);

        if (NT_SUCCESS(status) && allocBase != NULL)
        {
            //写入DLL路径
            KdPrint(("dllPath = %0llX\n", allocBase));
            wcscpy_s((PWCHAR)allocBase, 256, DllPath);
        }

        KeUnstackDetachProcess(&stack);
    }
    __except(1)
    {
        KeUnstackDetachProcess(&stack);

        if (KeGetCurrentIrql() != irql)
        {
            KeLowerIrql(irql);
        }

        KdPrint(("申请内存失败\n"));
    }

    if (!NT_SUCCESS(status))
    {
        KdPrint(("allocmem st = %X\n", status));
    }

    return allocBase;
}

/// <summary>
/// 注入DLL
/// </summary>
/// <returns></returns>
BOOLEAN DispatchInjDll(PEPROCESS Process, PVOID LoadLibaryAddr, PWCHAR DllPath)
{
    /*
    工作流程：
    1、申请远程内存
    2、执行LoadLibaray加载DLL
    
    */

    BOOLEAN bRet = FALSE;
    PVOID buffer = NULL;

    do
    {
        if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
        {
            KdPrint(("allcInj 目标进程已结束\n"));
            break;
        }

        //查看是否重复注入
        DWORD64 hDll = GetModuleHandleByName(g_LastProcess, L"ProcessAPC_INJ_DLL.dll");

        if (hDll != 0)
        {
            bRet = TRUE;
            break;
        }

        buffer = AllocDllPath(Process, DllPath);

        if (buffer == NULL)
        {
            KdPrint(("injDll buffer = 0\n"));
            break;
        }

        PETHREAD postThread = GetProcessActiveThread(Process);

        if (postThread == NULL)
        {
            KdPrint(("postThread = 0\n"));
            break;
        }

        KdPrint(("postThread = %llX\n", postThread));

        //确保线程没有结束
        if (PsGetThreadExitStatus(postThread) != STATUS_PENDING)
        {
            KdPrint(("postThread 已结束\n"));
            break;
        }

        //增加引用计数
        ObReferenceObject((PVOID)postThread);

        bRet = PostUserThreadApc(postThread, LoadLibaryAddr, buffer);
        
        ObDereferenceObject((PVOID)postThread);

        if (!bRet)
        {
            KdPrint(("injDll 注入失败\n"));
            break;
        }

        bRet = TRUE;
    } while (FALSE);

    if (bRet = TRUE)
    {
        g_INJDLL = 1;
    }

    return bRet;
}

//Main
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_OBJECT devObj = NULL;
    UNICODE_STRING win32Name = RTL_CONSTANT_STRING(L"\\??\\APC_TOOL_WIN32");
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\APC_TOOL_DEVICE");

    do
    {
        status = IoCreateDevice(Driver,
            NULL,
            &devName,
            FILE_DEVICE_UNKNOWN,
            0,
            TRUE,
            &devObj);

        if (!NT_SUCCESS(status))
        {
            KdPrint(("创建设备失败\n"));
            break;
        }

        status = IoCreateSymbolicLink(&win32Name, &devName);

        if (!NT_SUCCESS(status))
        {
            KdPrint(("创建符号链接失败\n"));
            break;
        }

        Driver->DriverUnload = DriverUnload;

        Driver->MajorFunction[IRP_MJ_CREATE] = CreateFn;
        Driver->MajorFunction[IRP_MJ_CLOSE] = CloseFn;
        Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlFn;

        status = STATUS_SUCCESS;

        KdPrint(("驱动加载成功\n"));

    } while (FALSE);

    if (!NT_SUCCESS(status))
    {
        if (devObj != NULL)
        {
            IoDeleteDevice(&devObj);
        }
    }

    return status;
}

//Debug
NTSTATUS DriverEntry_Test(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    /*
    函数说明：
    1、查看指定进程是否运行
    2、获取目标进程对象和最活跃线程
    3、申请远程内存，注入DLL
    */
    PEPROCESS ps = NULL;
    PETHREAD ts = NULL;
    ULONG pid = 832;
    ULONG tid = 0;
    PVOID lpLoadLibraryW = 0x7FF9B81DF7C0;

    WCHAR psName[] = { L"Tutorial-x86_64.exe" };
    WCHAR dllPath[] = { L"C:\\Users\\admin\\Desktop\\ProcessAPC_INJ_DLL.dll" };

    pid = GetTagetProcessIdByName(psName);

    NTSTATUS st = PsLookupProcessByProcessId(ULongToHandle(pid), &ps);


    GetModuleHandleByName(ps, L"ntdll.dll");

    return STATUS_UNSUCCESSFUL;

    do
    {
        if (!NT_SUCCESS(st))
        {
            KdPrint(("无效PID\n"));
            break;
        }

        if (PsGetProcessExitStatus(ps) != STATUS_PENDING)
        {
            KdPrint(("目标进程已结束\n"));
            break;
        }

        KdPrint(("ps = %0llX\n", ps));

        PLIST_ENTRY threadList = &((PKPROCESS_WIN11)ps)->ThreadListHead;
        PKSPIN_LOCK threadLock = (PKSPIN_LOCK)(&((PKPROCESS_WIN11)ps)->ProcessLock);

        PETHREAD curThread = NULL;
        KIRQL oldIrql = 0;

        if (threadList == NULL)
        {
            KdPrint(("threadList == 0\n"));
            break;
        }

        KeAcquireSpinLock(threadLock, &oldIrql);


        PLIST_ENTRY curLink = threadList->Flink;

        while(TRUE)
        {
            curThread = (PETHREAD)((DWORD64)curLink - 0x2f8);

            if (!MmIsAddressValid((PVOID)curLink))
            {
                break;
            }

            ObReferenceObject((PVOID)curThread);

            tid = HandleToUlong(PsGetThreadId(curThread));
            ULONG switchCount = *(ULONG*)((ULONG*)curThread + 85);

            KdPrint(("------------------------------------------\n"));

            KdPrint(("tid = %d switchCount = %d ethread = %0llX\n", 
                tid, switchCount, curThread));

            KdPrint(("------------------------------------------\n"));

            ObDereferenceObject((PVOID)curThread);

            //处理最后一个节点
            if (curLink->Flink == threadList)
            {
                break;
            }

            //步进到下一个节点
            curLink = curLink->Flink;

        }

        KeReleaseSpinLock(threadLock, oldIrql);

        //初始化APC
        

        //资源清理
        ObDereferenceObject((PVOID)ps);

    } while (FALSE);


    return STATUS_UNSUCCESSFUL;
}