#include "iat.h"
#include "memory.h"

#include <Windows.h>
#include <assert.h>

#include <string>
#include <fstream>

#define DUMPED_FOLDER    L"C:\\VACDUMPS\\"

#define STEAMSERVICE_DLL "SteamService.dll"
#define STEAMSERVICE_SIG "74 47 6A 01 6A 00"

#define JMP 0xEB

static auto           iat           = c_iat("SteamService.dll");
static std::uintptr_t address       = 0;
static std::uint8_t   original_byte = 0;

void patch_byte(std::uintptr_t address, std::uint8_t byte) {
	DWORD protection;
	VirtualProtect(reinterpret_cast<void*>(address), sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &protection);
	*reinterpret_cast<uint8_t*>(address) = byte;
	VirtualProtect(reinterpret_cast<void*>(address), sizeof(std::uint8_t), protection, &protection);
}

// https://gist.github.com/underscorediscovery/81308642d0325fd386237cfa3b44785c#file-hash_fnv1a-h-L9

const uint32_t hash_32_fnv1a(const void* key, const uint32_t len) {
	const char* data = (char*)key;
	uint32_t hash = 0x811c9dc5;
	uint32_t prime = 0x1000193;

	for (auto i = 0; i < len; ++i) {
		uint8_t value = data[i];
		hash = hash ^ value;
		hash *= prime;
	}

	return hash;
} //hash_32_fnv1a

HMODULE WINAPI LoadLibraryExWHk(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	auto module = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

	// assert module exists
	assert(module != nullptr);

	// check if VAC module
	if (GetProcAddress(module, "_runfunc@20") == nullptr)
		return module;

	// assert directory exists or can be made
	assert(CreateDirectoryW(DUMPED_FOLDER, NULL) || GetLastError() == ERROR_ALREADY_EXISTS);

	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module) + dos_header->e_lfanew);

	auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uintptr_t>(&nt_headers->OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader);

	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		auto section = section_header++;

		if (std::strstr(reinterpret_cast<const char*>(section->Name), ".text")) {
			wchar_t path[MAX_PATH + 1] = { 0 };

			auto hash = hash_32_fnv1a(reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(module) + section->PointerToRawData), section->SizeOfRawData);
			auto name = std::wstring(lpLibFileName);;

			name = name.substr(name.find_last_of(L'\\'), name.size());
			name = name.substr(0, name.find_last_of(L"."));

			std::swprintf(reinterpret_cast<wchar_t*>(&path), sizeof(path), L"%s\\%s_%i.bin", DUMPED_FOLDER, name.c_str(), hash);

			CopyFileW(lpLibFileName, path, FALSE);

			break;
		}
	}

	return module;
}

bool enable_dumper() {
	if (!address)
		address = find_pattern(STEAMSERVICE_DLL, STEAMSERVICE_SIG);

	if (address == 0)
		return false;

	auto byte = *reinterpret_cast<std::uint8_t*>(address);

	original_byte = byte;
	
	patch_byte(address, JMP);

	iat.hook("KERNEL32.dll", "LoadLibraryExW", &LoadLibraryExWHk);

	return true;
}

bool disable_dumper() {
	// assert that the pattern has already been found
	assert(address != 0);

	iat.hook("KERNEL32.dll", "LoadLibraryExW", &LoadLibraryExW);

	patch_byte(address, original_byte);

	return true;
}

BOOL WINAPI DllMain(HMODULE hmodule, DWORD dwreason, LPVOID lpreserved) {
	switch (dwreason) {
	case DLL_PROCESS_ATTACH:
		return enable_dumper();

	case DLL_PROCESS_DETACH:
		return disable_dumper(); // called on process exit!
	}

	return TRUE;
}