#include <Windows.h>

#define RtlOffsetToPointer(Module, Pointer) PBYTE(PBYTE(Module) + DWORD(Pointer))

INT main(INT argc, LPCSTR argv[]) {
	
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
		if (hFileMapping != ERROR) {
			LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, NULL, NULL, NULL);
			PIMAGE_DOS_HEADER ImageDosHeader = PIMAGE_DOS_HEADER(pMapping);
			if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
				PIMAGE_NT_HEADERS ImageNtHeaders = PIMAGE_NT_HEADERS(RtlOffsetToPointer(pMapping, ImageDosHeader->e_lfanew));
				if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
					MessageBoxA(NULL, "This is the valid PE file", "PE Check", MB_OK);
				}
				else {
					MessageBoxA(NULL, "This is the invalid PE file", "PE Check", MB_OK);
				}
				UnmapViewOfFile(pMapping);
				CloseHandle(hFileMapping);
				CloseHandle(hFile);
			}
			else {
				MessageBoxA(NULL, "This is the invalid PE file", "PE Check", MB_OK);
			}
			CloseHandle(hFileMapping);
		}
		CloseHandle(hFile);
	}
	return 0;
}