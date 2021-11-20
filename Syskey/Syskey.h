#pragma once

#include <cstdint>
#include "Syscaller.h"

namespace nt
{
	extern "C"
	{
		inline auto fnNtUserGetAsyncKeyState(int, int)->std::int16_t;
		// mov r10, rcx
		// mov rax, rdx		-> idx will be replaced on call
		// syscall
		// ret
	}

	inline std::uint32_t numCallIdx = 0x0;
	inline auto GetKey(int key)
	{
		if (!numCallIdx)
			numCallIdx = syscaller::GetIdx(L"win32u.dll", "NtUserGetAsyncKeyState");

		return nt::fnNtUserGetAsyncKeyState(key, numCallIdx);
	}
}
