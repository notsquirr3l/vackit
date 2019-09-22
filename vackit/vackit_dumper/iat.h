#ifndef _HOOK_IAT_H_
#define _HOOK_IAT_H_

#include <iostream>
#include <vector>

class c_iat {
public:
	c_iat(const std::string& module);
	~c_iat();

	void hook(const std::string& importmodule, const std::string& method, const void* hook);

private:
	struct fnhook {
		std::string module;
		std::string method;

		void* original;
	};

	std::vector<fnhook> _hooks;
	std::uintptr_t _module;
};

#endif