#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <iostream>

extern std::uintptr_t find_pattern(const std::string& module, const std::string& pattern);
extern std::uintptr_t find_pattern(const std::uintptr_t& module, const std::string& pattern);
extern std::uintptr_t find_pattern(const std::uintptr_t& address, const std::string& pattern, const std::uintptr_t& range);

#endif