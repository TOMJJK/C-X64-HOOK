public g_Regs

.data
;rax, rcx, rdx
g_Regs dq 0, 0, 0, 0

.code
GetSrcRegs proc

	;------------------------------------------------
	;先将rax、rcx、rdx值保存到堆栈
	;再保存到g_Regs
	;------------------------------------------------
	push rax
	push rcx
	push rdx

	mov rax, offset g_Regs
	mov [rax+16], rdx		;rdx
	mov [rax+8], rcx		;rcx
	
	mov rcx, [rsp+16]		;rax
	mov [rax], rcx

	pop rax
	pop rax
	pop rax
	
	mov rax, offset g_Regs	;return g_Regs

	ret

GetSrcRegs endp
end
