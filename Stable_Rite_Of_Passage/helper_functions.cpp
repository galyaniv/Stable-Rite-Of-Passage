#include "includes.h"

PVOID helper_functions::memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
	if (haystack == NULL) return NULL;
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL;
	if (needle_len == 0) return NULL;

	for (const char* h = (char*)haystack; haystack_len >= needle_len; h++, haystack_len--) {
		if (!memcmp(h, needle, needle_len)) {
			return (void*)h;
		}
	}
	return NULL;
}

DWORD64 helper_functions::SearchRopGadgets(const void* gadgetOPCode, size_t gadgetSize) {
	DWORD i = 0;
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	if (hModuleNtdll == NULL) return 0;
	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)hModuleNtdll;
	PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)hModuleNtdll + imageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(imageNtHeaders);

	DWORD numberOfSections = imageNtHeaders->FileHeader.NumberOfSections;

	for (i = 0; i < numberOfSections; i++) {
		if (lstrcmp((LPCWSTR)imageSectionHeader->Name, L".text")) break;
	}

	DWORD64 gadgetAddress = (DWORD64)helper_functions::memmem((char*)imageSectionHeader, imageSectionHeader->SizeOfRawData, gadgetOPCode, gadgetSize);

	if (gadgetAddress != NULL) return gadgetAddress;

	CloseHandle(hModuleNtdll);
	return NULL;
}