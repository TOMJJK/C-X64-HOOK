# C-X64-HOOK
C语言书写HOOK代码，实现任意位置HOOK

#实现原理：

1、利用汇编语言获取rax、rcx、rdx值

2、RtlCaptureContext获取当前执行环境

3、调用Hook处理函数: 恢复CONTEXT，并将变量映射到寄存器

4、模拟劫持点源代码执行效果

5、修改rsp、rip原执行点

6、RtlRestoreContext恢复执行环境

#注意事项
1、使用VS2022编译时需要关闭堆栈检查，使用release生成代码，确保代码最大优化

#执行效果

CE9打队友掉1滴血，打敌人秒杀

#项目结构

INJTOOL_USER_INF：驱动用户接口

ProcessAPC_INJ：驱动模块

ProcessAPC_INJ_DLL：注入模块

#关键项目：ProcessAPC_INJ_DLL

PassCE9：劫持处理函数

HookCE9：劫持函数

JumpFn：跳转模板

...

#教程已更新到B站
