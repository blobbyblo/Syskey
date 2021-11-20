#pragma once

#include <cstdint>
#include "direct.h"
#include "native.h"

namespace syscaller
{
	inline auto GetModule(const wchar_t* module_name) -> std::uint64_t
	{
		PLDR_DATA_TABLE_ENTRY lib = (PLDR_DATA_TABLE_ENTRY)(direct::__peb_ldte());

		while (lib->BaseDllName.Buffer != 0x0)
		{
			std::uint64_t base = 0;
			bool string_match = false;
			auto current_name = lib->BaseDllName.Buffer;

			base = reinterpret_cast<std::uint64_t>(lib->DllBase);
			lib = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(lib->InLoadOrderLinks.Flink);

			if (!base)
				continue;

			for (auto i = 0; i < lib->BaseDllName.Length; i++)
			{
				if (current_name[i] == '\0' || module_name[i] == '\0')
				{
					break;
				}
				else
				{
					if (current_name[i] == module_name[i])
					{
						string_match = true;
						continue;
					}
					else
					{
						string_match = false;
						break;
					}
				}
			}

			if (string_match)
				return base;
		}

		return { };
	}

	inline auto GetFunction(const wchar_t* module_name, const char* function_name) -> std::uint64_t
	{
		auto module_address = syscaller::GetModule(module_name);
		if (!module_address)
			return 0x0;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADERS>(module_address);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return 0x0;

		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64S>(reinterpret_cast<std::uint8_t*>(module_address) + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
			return 0x0;

		auto image_export_va = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!image_export_va)
			return 0x0;

		auto image_export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORYS>(reinterpret_cast<std::uint8_t*>(module_address) + image_export_va);

		auto address_functions = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint8_t*>(module_address) + image_export_dir->AddressOfFunctions);
		auto address_names = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uint8_t*>(module_address) + image_export_dir->AddressOfNames);
		auto address_ordinals = reinterpret_cast<std::uint16_t*>(reinterpret_cast<std::uint8_t*>(module_address) + image_export_dir->AddressOfNameOrdinals);

		for (auto i = 0; i < image_export_dir->NumberOfNames; i++)
		{
			auto string_match = false;
			char* current_name = reinterpret_cast<char*>(module_address) + address_names[i];

			for (auto i = 0;; i++)
			{
				if (current_name[i] == '\0' || function_name[i] == '\0')
				{
					break;
				}
				else
				{
					if (current_name[i] == function_name[i])
					{
						string_match = true;
						continue;
					}
					else
					{
						string_match = false;
						break;
					}
				}
			}

			if (string_match)
			{
				return reinterpret_cast<std::uint64_t>((std::uint8_t*)module_address + address_functions[address_ordinals[i]]);
			}
		}
		return 0x0;
	}

	inline auto GetIdx(const wchar_t* module_name, const char* function_name) -> const std::uint32_t
	{
		auto exported_function = GetFunction(module_name, function_name);
		if (!exported_function)
			return { };

		return *reinterpret_cast<std::uint32_t*>(exported_function + 4);
	}
}
