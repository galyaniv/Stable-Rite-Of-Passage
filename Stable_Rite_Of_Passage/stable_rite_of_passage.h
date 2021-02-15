#pragma once
#include "includes.h"


class srop_class {
public:

	SROP_INFO* data;
	srop_class(SROP_INFO* info) : data(info) {

	}
	~srop_class() {
		free(data);
	}

	DWORD FindThreadForHijacking();
	DWORD CreateSharedSectionWithPayload();
	PVOID CreateSharedSection();

	DWORD CreateROP();

	DWORD Start();

};

