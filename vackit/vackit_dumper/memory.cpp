#include "memory.h"

#include <Windows.h>

#include <vector>

std::uintptr_t find_pattern(const std::string& module, const std::string& pattern) {
	return find_pattern(reinterpret_cast<uintptr_t>(GetModuleHandleA(module.c_str())), pattern);
}

std::uintptr_t find_pattern(const std::uintptr_t& module, const std::string& pattern) {
	return find_pattern(module, pattern, reinterpret_cast<PIMAGE_NT_HEADERS>(module + reinterpret_cast<PIMAGE_DOS_HEADER>(module)->e_lfanew)->OptionalHeader.SizeOfImage);
}

std::uintptr_t find_pattern(const std::uintptr_t& address, const std::string& pattern, const std::uintptr_t& range) {
	static auto pattern_to_byte = [](std::string pattern) {
		auto bytes = std::vector<int>() = {};
		auto start = const_cast<char*>(pattern.c_str());
		auto end = const_cast<char*>(pattern.c_str()) + pattern.length();

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;

				if (*current == '?')
					++current;

				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}

		return bytes;
	};

	auto pattern_bytes = pattern_to_byte(pattern.c_str());
	auto scan_bytes = reinterpret_cast<std::uint8_t*>(address);

	auto s = pattern_bytes.size();
	auto d = pattern_bytes.data();

	for (auto i = 0ul; i < range - s; ++i) {
		bool found = true;

		for (auto j = 0ul; j < s; ++j) {
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}

		if (found)
			return reinterpret_cast<uintptr_t>(&scan_bytes[i]);
	}

	return 0;
}