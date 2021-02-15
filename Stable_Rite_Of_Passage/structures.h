#pragma once
#include "includes.h"


struct REMOTE_THREAD_INFO {
	DWORD threadId;
	DWORD processId;
	HANDLE hThread;
	HANDLE hProcess;
};

struct REMOTE_THREAD_CONTEXT_INFO
{
	DWORD64 oldR14;
	DWORD64 oldRIP;
	DWORD64 oldRSP;
	DWORD64 newRIP;
	DWORD64 newRSP;
};

struct MAPPED_SECTION_INFO
{
	HANDLE hRemoteSection;
};

struct PAYLOAD_INFO
{
	BYTE* payload;
	DWORD payloadSize;
};

struct ROP_INFO
{
	PDWORD64 ROP;
	DWORD64 ROPSize;
};

struct SROP_INFO {
	REMOTE_THREAD_INFO remote_thread_info;
	REMOTE_THREAD_CONTEXT_INFO context_info;
	PAYLOAD_INFO payload_info;
	MAPPED_SECTION_INFO section_info;
	ROP_INFO rop_info;
};



