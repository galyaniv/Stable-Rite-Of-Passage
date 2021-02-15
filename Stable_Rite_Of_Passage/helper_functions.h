#pragma once
#include "includes.h"


namespace helper_functions {

	PVOID memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len);

	DWORD64 SearchRopGadgets(const void* ropGadget, size_t ropGadgetSize);

}