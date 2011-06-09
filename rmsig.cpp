#include "stdafx.h"

void SafeWriteFile(HANDLE hFile, LPCVOID pBuffer, DWORD dwSize)
{
	DWORD dwBytesWrite;
	BOOL bRet = WriteFile(hFile, pBuffer, dwSize, &dwBytesWrite, NULL);
	tp::throw_winerr_when(!bRet || dwBytesWrite != dwSize);
}

int wmain_internal(int argc, wchar_t* argv[])
{
	if (argc < 3)
	{
		wprintf(L"usage: rmsig <PE-FILE> <NEW_FILE>\nRemove signature from PE file.");
		return 1;
	}

	SETOP(L"Open Source Image File");
	HANDLE hFileSrc = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	tp::throw_winerr_when(hFileSrc == NULL);
	ON_LEAVE_1(CloseHandle(hFileSrc), HANDLE, hFileSrc);

	SETOP(L"Map Source Image file");
	HANDLE hMap = CreateFileMapping(hFileSrc, NULL, PAGE_READONLY, 0, 0, NULL);
	tp::throw_winerr_when(hMap == NULL);
	ON_LEAVE_1(CloseHandle(hMap), HANDLE, hMap);

	SETOP(L"Map view of Source Image file");
	unsigned char* lpFileBase = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	tp::throw_winerr_when(lpFileBase == NULL);

	SETOP(L"Parse Source Image File");
	PIMAGE_DOS_HEADER doshdr = (PIMAGE_DOS_HEADER)lpFileBase;
	tp::throw_when(doshdr->e_magic != IMAGE_DOS_SIGNATURE, L"Invalid Image File");

	DWORD dwCoffBasePos = doshdr->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER;
	DWORD dwChecksumPos = dwCoffBasePos + 64;
	DWORD dwCertOffsetPos = dwCoffBasePos + 128;
	DWORD dwCertLengthPos = dwCoffBasePos + 132;
	PIMAGE_DATA_DIRECTORY certdir = (PIMAGE_DATA_DIRECTORY)(lpFileBase + dwCertOffsetPos);
	DWORD dwCertOffset = certdir->VirtualAddress;
	DWORD dwCertLength = certdir->Size;

	SETOP(L"Open Target File");
	HANDLE hFileDst = CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	tp::throw_winerr_when(hFileDst == NULL);
	ON_LEAVE_1(CloseHandle(hFileDst), HANDLE, hFileDst);

	SETOP(L"Write Target File");
	LPCVOID pNullByte_4 = (LPCVOID)L"\0\0\0\0";

	SafeWriteFile(hFileDst, lpFileBase, dwChecksumPos);
	SafeWriteFile(hFileDst, pNullByte_4, 4);
	SafeWriteFile(hFileDst, lpFileBase + dwChecksumPos + 4, dwCertOffsetPos - dwChecksumPos - 4);
	SafeWriteFile(hFileDst, pNullByte_4, 4);
	SafeWriteFile(hFileDst, pNullByte_4, 4);
	SafeWriteFile(hFileDst, lpFileBase + dwCertLengthPos + 4, dwCertOffset - dwCertLengthPos -4);

	return 0;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_CTYPE, "");
	wprintf(L"rmsig\n");

	try
	{
		wmain_internal(argc, argv);
	}
	catch (tp::exception& e)
	{
		wprintf(L"error: %s\ncurrent operation: %s\n", e.err->desc().c_str(), e.oplist.c_str());
		return 1;
	}

	return 0;
}