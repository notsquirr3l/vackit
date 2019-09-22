#include "iat.h"

#include <Windows.h>

c_iat::c_iat(const std::string& module) {
	this->_module = reinterpret_cast<uintptr_t>(GetModuleHandleA(module.c_str()));
}

c_iat::~c_iat() {
	for (const auto& hook : this->_hooks) {
		this->hook(hook.module, hook.method, hook.original);
	}
}

void c_iat::hook(const std::string& importmodule, const std::string& method, const void* hook) {
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(this->_module + reinterpret_cast<PIMAGE_DOS_HEADER>(this->_module)->e_lfanew);

	auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(this->_module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (auto import = imports; import->Name; ++import) {
		auto module_name = reinterpret_cast<const char*>(this->_module + import->Name);

		if (std::strcmp(module_name, importmodule.c_str()))
			continue;

		auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->_module + import->OriginalFirstThunk);
		auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->_module + import->FirstThunk);

		for (; original_first_thunk->u1.AddressOfData; ++original_first_thunk, ++first_thunk) {
			auto name = reinterpret_cast<const char*>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->_module + original_first_thunk->u1.AddressOfData)->Name);

			if (method != name)
				continue;

			auto addr = &first_thunk->u1.Function;

			DWORD protection;
			VirtualProtect((void*)addr, sizeof(hook), PAGE_READWRITE, &protection);
			*addr = reinterpret_cast<std::uintptr_t>(hook);
			VirtualProtect((void*)addr, sizeof(hook), protection, &protection);

			break;
		}

		break;
	}
}