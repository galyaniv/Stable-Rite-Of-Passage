#include "includes.h"

#define PROCESS_ID  4384

int main() {

	SROP_INFO* info = (SROP_INFO*)::malloc(sizeof(SROP_INFO));
	srop_class srop(info);
	srop.data->remote_thread_info.processId = PROCESS_ID;
	srop.data->remote_thread_info.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, srop.data->remote_thread_info.processId);

	if (!srop.data->remote_thread_info.hProcess) {
		cout << "[-] Unable to get process handle\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	DWORD success = srop.Start();

	if (!success) {
		cout << "[-] Stable Rite of Passage Failed :(\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	cout << "[+] Stable Rite of Passage Succedded!!!\n"  << endl;
	return 1;
}