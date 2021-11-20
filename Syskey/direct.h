#pragma once

#include <cstdint>

namespace direct
{
	extern "C"
	{
		__forceinline auto __peb_ldte()->std::uint64_t;
		// mov rax, qword ptr gs:[60h]	-> NtCurrentPeb()
		// mov rax, [rax + 18h]
		// mov rax, [rax + 10h]
		// ; mov rax, [rax]
		// ret
	}
}
