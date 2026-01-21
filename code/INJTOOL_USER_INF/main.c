#pragma once
#include<Windows.h>
#include<winternl.h>

#pragma comment(lib, "ntdll.lib")

#define IoPassCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED|METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoInjectDll CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED|METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define EXPORT_STDCALL(name, bytes) \
    __pragma(comment(linker, "/export:"#name"=_"#name"@"#bytes))

HANDLE hDriver = NULL;

typedef struct
{
    DWORD64 LoadLibraryW;
    WCHAR DllPath[128];
}INJDLL_INBUFFER;

__declspec(dllexport)
VOID __stdcall Test()
{
    return 1;
}

/// <summary>
/// 连接设备
/// </summary>
/// <returns></returns>
#pragma comment(linker, "/export:ConnectDriver=_ConnectDriver@0")
__declspec(dllexport)
ULONG __stdcall ConnectDriver()
{
    BOOLEAN bRet = FALSE;
    ULONG dwRet = 0;

    WCHAR win32Name[] = {L"\\\\.\\APC_TOOL_WIN32"};

    HANDLE hFile = CreateFileW(win32Name,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    do
    {
        if (hFile == INVALID_HANDLE_VALUE)
        {
            break;
        }

        hDriver = hFile;

        bRet = TRUE;

    } while (FALSE);

    if (bRet)
    {
        dwRet = 1;
    }
    else
    {
        dwRet = 0;
    }

    return bRet;
}

/// <summary>
/// 注入DLL
/// </summary>
/// <returns></returns>
EXPORT_STDCALL(InjectDll, 16)
__declspec(dllexport)
ULONG __stdcall InjectDll(PCHAR DllPath, DWORD64 LoadLibraryW64, PCHAR TextBuffer)
{
    INJDLL_INBUFFER inbuffer = { 0 };
    WCHAR outBuffer[128] = { 0 };
    ULONG dwRet = 0;

    UNICODE_STRING dllPathW = { 0 };
    UNICODE_STRING dllPathA = { 0 };

    wcscpy_s(outBuffer, 128, L"白日依山尽, 黄河入海流");

    inbuffer.LoadLibraryW = LoadLibraryW64;

    RtlInitAnsiString(&dllPathA, DllPath);
    RtlAnsiStringToUnicodeString(&dllPathW, &dllPathA, TRUE);

    wcscpy_s((PVOID)&inbuffer.DllPath, 128, dllPathW.Buffer);

    RtlFreeUnicodeString(&dllPathW);


    BOOLEAN bRet = DeviceIoControl(hDriver,
        IoInjectDll,
        (PVOID)&inbuffer,
        sizeof(INJDLL_INBUFFER),
        &outBuffer,
        sizeof(outBuffer),
        &dwRet,
        NULL);

    if (dwRet == 0)
    {
        dwRet = 0;
        wcscpy_s(TextBuffer, 128, outBuffer);
    }
    else
    {
        dwRet = 1;
    }

    return dwRet;
}

EXPORT_STDCALL(PassCE,8)
__declspec(dllexport)
ULONG __stdcall PassCE(PVOID LevelId, PWCHAR TextBuffer)
{
    PVOID inbuffer = 0;
    WCHAR outBuffer[128] = { 0 };
    ULONG dwRet = 0;

    inbuffer = LevelId;

    wcscpy_s(outBuffer, 128, L"欲穷千里目，更上一层楼");

    BOOLEAN bRet = DeviceIoControl(hDriver,
        IoPassCE,
        &inbuffer,
        sizeof(PVOID),
        &outBuffer,
        sizeof(outBuffer),
        &dwRet,
        NULL);

    if (dwRet == 0)
    {
        dwRet = 0;
        wcscpy_s(TextBuffer, 128, outBuffer);
    }
    else
    {
        dwRet = 1;
    }

    return dwRet;
}


BOOLEAN WINAPI DllMain(HMODULE Handle, DWORD Reason, DWORD Reserved)
{
    return TRUE;
}