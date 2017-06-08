#include<Windows.h>
#include<CommCtrl.h>
#include "resource.h"

#define IDD_SECTIONTABLE 104
#define IDC_SECTIONLIST 1001
#define RtlOffsetToPointer(Module,Pointer) PBYTE(PBYTE(Module) + DWORD(Pointer))

#pragma comment( lib, "comctl32.lib")
#pragma comment( lib, "comdlg32.lib")

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);


WORD NoOfSections = 0;
CHAR buffer[512];
LPVOID pMapping;
OPENFILENAME ofn;
CHAR *FilterString = TEXT("Executable Files (*.exe or *.dll)");
BOOL ValidPE;
HANDLE hFile, hMapping;
PIMAGE_DOS_HEADER ImageDosHeader;
PIMAGE_NT_HEADERS ImageNtHeaders;
PIMAGE_SECTION_HEADER ImageSectionHeader;

INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR CommandLine, INT nCmdShow) {
	hInstance = GetModuleHandle(NULL);
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFilter = FilterString;
	ofn.lpstrFile = buffer;
	ofn.nMaxFile = 512;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	if (GetOpenFileName(&ofn)) {
		hFile = CreateFile(buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
			if (hMapping != NULL) {
				pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, NULL, NULL, NULL);
				if (pMapping != NULL) {
					ImageDosHeader = PIMAGE_DOS_HEADER(pMapping);
					if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
						ImageNtHeaders = PIMAGE_NT_HEADERS(RtlOffsetToPointer(pMapping, ImageDosHeader->e_lfanew));
						if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
							ValidPE = TRUE;
						}
						else {
							ValidPE = FALSE;
						}
					}
					else {
						ValidPE = FALSE;
					}
				}
			}
		}
	}
	if (ValidPE == TRUE) {
		//Call Here ShowSection Info
		PIMAGE_NT_HEADERS ImageNtHeaders2 = PIMAGE_NT_HEADERS(RtlOffsetToPointer(pMapping, ImageDosHeader->e_lfanew));
		NoOfSections = ImageNtHeaders2->FileHeader.NumberOfSections;
		DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_SECTIONTABLE), NULL, (DLGPROC)DialogProc, 0);
	}
	else {
		MessageBox(NULL, "Invalid PE", "Section Info", MB_OK);
	}
	ExitProcess(NULL);
	InitCommonControls();
	return 0;
}



static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	LVCOLUMN lvc;
	LVITEM lvi;
	if (uMsg == WM_INITDIALOG) {
		lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		lvc.fmt = LVCFMT_LEFT;
		lvc.cx = 80;
		lvc.iSubItem = 0;
		lvc.pszText = "Section";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 0, (LPARAM)&lvc);
		lvc.iSubItem += 1;
		lvc.fmt = LVCFMT_RIGHT;
		lvc.pszText = "V. Size";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 1, (LPARAM)&lvc);
		lvc.iSubItem += 1;
		lvc.pszText = "V. Address";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 2, (LPARAM)&lvc);
		lvc.iSubItem += 1;
		lvc.pszText = "Size Raw Data";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 3, (LPARAM)&lvc);
		lvc.iSubItem += 1;
		lvc.pszText = "Raw Offset";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 4, (LPARAM)&lvc);
		lvc.iSubItem += 1;
		lvc.pszText = "Characteristics";
		SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 1, (LPARAM)&lvc);
		lvi.mask = LVIF_TEXT;
		lvi.iItem = 0;
		while (NoOfSections > 0) {
			lvi.iSubItem = 0;
			RtlZeroMemory(&buffer, 9);
			LPSTR Name1 = (LPSTR)ImageSectionHeader->Name;
			lstrcpyn(buffer, Name1, 8);
			lvi.pszText = buffer;
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, (LPARAM)&lvi);
			wsprintf(buffer, "%081x", ImageSectionHeader->Misc.VirtualSize);
			lvi.pszText = buffer;
			lvi.iSubItem += 1;
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, (LPARAM)&lvi);
			wsprintf(buffer, "%081x", ImageSectionHeader->VirtualAddress);
			lvi.pszText = buffer;
			lvi.iSubItem += 1; 
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, (LPARAM)&lvi);
			wsprintf(buffer, "%081x", ImageSectionHeader->SizeOfRawData);
			lvi.pszText = buffer;
			lvi.iSubItem += 1;
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, (LPARAM)&lvi);
			wsprintf(buffer, "%081x", ImageSectionHeader->PointerToRawData);
			lvi.pszText = buffer;
			lvi.iSubItem += 1;
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, (LPARAM)&lvi);
			wsprintf(buffer, "%081x", ImageSectionHeader->Characteristics);
			lvi.pszText = buffer;
			lvi.iSubItem += 1;
			SendDlgItemMessage(hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, (LPARAM)&lvi);
			lvi.iItem += 1;
			NoOfSections -= 1;
			ImageSectionHeader += sizeof(IMAGE_SECTION_HEADER);
		}
	}
	else if (uMsg == WM_CLOSE) {
		EndDialog(hDlg, NULL);
	}
	else {
		return FALSE;
	}
	return TRUE;
}