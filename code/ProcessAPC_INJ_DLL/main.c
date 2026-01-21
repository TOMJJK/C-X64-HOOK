#pragma once
#include<Windows.h>
#include<winternl.h>

#pragma comment(lib, "ntdll.lib")

/* CE7.5
第二关："Tutorial-x86_64.exe"+325A70] + 7F8
第三关："Tutorial-x86_64.exe"+325A80] + 7F8
第四关："Tutorial-x86_64.exe"+325AA0] + 818 = float
        "Tutorial-x86_64.exe"+325AA0] + 820 = double
第五关："Tutorial-x86_64.exe"+325AB0] + 7E0] + 0
第六关："Tutorial-x86_64.exe"+325AD0] + 0
第七关："Tutorial-x86_64.exe"+325AE0] + 7E0
第八关："Tutorial-x86_64.exe"+325B00] + 10 + 18 + 0 + 18
第九关："Tutorial-x86_64.exe"+325B10] + 888 + 8
*/

typedef struct
{
    DWORD64 Level;  //关卡数
    PVOID   PassFunction; //过关函数
}MN_TABLE;

typedef struct
{
    DWORD64 unk_0;

    float HP;
    DWORD unk_1;
    DWORD unk_2;
    DWORD unk_3;

    union
    {
        UCHAR u[16];
        struct
        {
            UCHAR Align;
            UCHAR Name[1];
        }PlayerName;
    }u;

}CE19_PLAYER, * PCE19_PLAYER;

typedef struct
{
    ULONG Camp; //阵营
    UCHAR Name[28];
}PLAYER_INFO;

typedef struct
{
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
}PUSH_REGS;

VOID PassCE2();
VOID PassCE9();

//利用导出表快速定位函数
__declspec(dllexport)
MN_TABLE g_INFO[9] = {
    {1, 0},
    {2, (PVOID)PassCE2},
    {3, 0},
    {4, 0},
    {5, 0},
    {6, 0},
    {7, 0},
    {8, 0},
    {9, 0} };


#pragma comment(linker, "/export:PassCE2")
VOID PassCE2()
{
    //CE7.6 = "Tutorial-x86_64.exe"+34EC10] + 7F8
    HMODULE hMain = GetModuleHandle(L"Tutorial-x86_64.exe");

    if (hMain == NULL)
    {
        MessageBox(NULL, L"获取主模块失败", L"错误", MB_OK);
        return;
    }

    //获取基地址
    DWORD64 lpBase = (DWORD64)hMain + 0x34EC10;
    lpBase = *(DWORD64*)lpBase;
    ULONG* lpData = (ULONG*)(lpBase + 0x7F8);
    InterlockedExchange(lpData, 1000);

}

PLAYER_INFO g_PlayerName[] = { 
    {1, "Dave"},
    {1, "Eric"}, 
    {2, "HAL"}, 
    {2, "KITT"} };

UCHAR g_RegContext[4096] = { 0 };

extern VOID GetSrcRegs();
extern DWORD64 g_Regs[4];

__declspec(dllexport)
VOID JumpFn()
{
    GetSrcRegs();
    RtlCaptureContext((PCONTEXT)&g_RegContext);
    PassCE9();
}

DWORD64 GetMainExe()
{
    WCHAR dllName[] = {L"Tutorial-x86_64.exe"};
    DWORD64 hMain = 0;

    __try
    {
        hMain = (DWORD64)GetModuleHandle(dllName);
    }
    __except(1)
    {
        hMain = 0x100000000;
    }

    return hMain;
}


VOID PassCE9()
{
    //"Tutorial-x86_64.exe"+34ECB0] + 888 + 8
    //01500000 - 68 78563412            - push 12345678
    //01500005 - C7 44 24 04 00000007   - mov[rsp + 04], 07000000
    //0150000D - C3                     - ret


    //旧代码
    //"Tutorial-x86_64.exe" + 49996 - 48 C7 45 E0 00000000 - mov qword ptr[rbp - 20], 00000000 { 0 }
    //"Tutorial-x86_64.exe" + 4999E - 48 C7 45 F8 00000000 - mov qword ptr[rbp - 08], 00000000 { 0 }
    //"Tutorial-x86_64.exe" + 499A6 - 90                   - nop
    PCONTEXT regContext = (PCONTEXT)&g_RegContext;

    DWORD64 hMain = GetMainExe();
    DWORD64 retAddr = hMain + 0x499A6;

    //恢复环境
    PUSH_REGS* regs = (PUSH_REGS*)g_Regs;


    regContext->Rax = regs->Rax;
    regContext->Rcx = regs->Rcx;
    regContext->Rdx = regs->Rdx;

    //---------------------------------------------------------------------

    //RCX = 人物基地址
    PCE19_PLAYER player = (PCE19_PLAYER)regContext->Rbx;

    //hp = rbx + 8
    float hp = 0.0f;
    PCHAR name = &player->u.PlayerName.Name;

    do
    {
        //指定玩家扣血少
        if (strcmp(name, "Dave") == 0)
        {
            hp = 1.0f;
            break;
        }

        if (strcmp(name, "Eric") == 0)
        {
            hp = 1.0f;
            break;
        }

        //---------------------------------------------
        //秒杀敌人
        //---------------------------------------------
        //"Tutorial-x86_64.exe" + 34ECB0] + 888 + 8
        DWORD64 temp = hMain + 0x34ECB0;
        temp = *(DWORD64*)temp;

        DWORD64* playerArray = (DWORD64*)(temp + 0x888);

        for (ULONG i = 0; ; i++)
        {
            DWORD64* player_i = playerArray + i;

            //到数组尾部
            if ((*player_i & 0xff0000) == 0)
            {
                break;
            }

            PCE19_PLAYER curPlayer = (PCE19_PLAYER)(*player_i);

            //判断玩家
            for (ULONG j = 0; j < 4; j++)
            {
                if (strcmp(&curPlayer->u.PlayerName.Name, g_PlayerName[j].Name) == 0)
                {
                    //敌对阵营
                    if (g_PlayerName[j].Camp == 2)
                    {
                        //血量清零
                        hp = curPlayer->HP;
                    }

                    break;
                }
            }

            //需要判断，否则打死KITE情况下HAL不会受到伤害
            //因为KITT是数组最后一个人，先死的情况下，hp总数为0
            if (hp != 0.0f)
            {
                break;
            }

        }

    } while (FALSE);

    regContext->Rsi = (ULONG)hp;



    //---------------------------------------------------------------------
    //模拟执行旧代码 -- 虚拟化代码
    //mov qword ptr[rbp - 20], 00000000
    //mov qword ptr[rbp - 08], 00000000
    //----------------------------------------------------------------------
    DWORD64 rbp = regContext->Rbp;
    DWORD64* rbp20 = (DWORD64*)(rbp - 0x20);
    DWORD64* rbp08 = (DWORD64*)(rbp - 0x8);

    *rbp20 = 0;
    *rbp08 = 0;

    //写返回地址
    regContext->Rip = retAddr;

    //调整Rsp
    //add rsp, 40
    regContext->Rsp = regContext->Rsp + 40;

    //恢复执行
    RtlRestoreContext(regContext, NULL);
}



BOOL g_HookCE9 = FALSE;


__declspec(dllexport)
VOID HookCE9()
{
    /*
    1、获取原函数信息
    2、写入HOOK代码
    */
    
    //"Tutorial-x86_64.exe"+34ECB0] + 888 + 8
    //01500000 - 68 78563412            - push 12345678
    //01500005 - C7 44 24 04 00000007   - mov[rsp + 04], 07000000
    //0150000D - C3                     - ret


    //旧代码
    //"Tutorial-x86_64.exe" + 49996 - 48 C7 45 E0 00000000 - mov qword ptr[rbp - 20], 00000000 { 0 }
    //"Tutorial-x86_64.exe" + 4999E - 48 C7 45 F8 00000000 - mov qword ptr[rbp - 08], 00000000 { 0 }
    //"Tutorial-x86_64.exe" + 499A6 - 90                   - nop

    UCHAR hookFunction[] = { 0x68, 00, 00, 00, 00,
                            0xC7, 0x44, 0x24, 0x04, 0x00,
                            00, 00, 00, 0xC3, 0x90, 0x90};

    do
    {
        //已经安装HOOK
        if (g_HookCE9 == TRUE)
        {
            break;
        }

        //获取HOOK点
        DWORD64 hMain = GetMainExe();
        DWORD64* hookEntry = (DWORD64*)(hMain + 0x49996);

        //已经被HOOK
        if (*hookEntry != 0xE045C748)
        {
            break;
        }

        ULONG lowAddr = (ULONG)JumpFn;
        ULONG highAddr = (ULONG)((DWORD64)JumpFn >> 32);

        //构建HOOK函数
        ULONG* jumpLow = (ULONG*)&hookFunction[1];
        ULONG* jumpHigh = (ULONG*)&hookFunction[9];

        *jumpLow = lowAddr;
        *jumpHigh = highAddr;

        DWORD oldProtect = 0;

        //更改内存属性
        VirtualProtect(hookEntry, 16, PAGE_EXECUTE_READWRITE, &oldProtect);

        //写入HOOK代码
        RtlCopyMemory((PVOID)hookEntry, (PVOID)hookFunction, sizeof(hookFunction));

        //恢复内存属性
        VirtualProtect(hookEntry, 16, oldProtect, &oldProtect);


        g_HookCE9 = TRUE;

    } while (FALSE);

}


//加载标志 = FALSE
DWORD64 g_Loaded = 0;

BOOL DllMain(HINSTANCE hDll, ULONG dwReason, ULONG Reserved)
{
    //线程加载
    if (dwReason == DLL_THREAD_ATTACH)
    {
        if (InterlockedExchange(&g_Loaded, 1) == 0)
        {
            MessageBox(NULL, L"注入成功!!!", L"提示", MB_OK);
        }
    }

    return TRUE;
}






