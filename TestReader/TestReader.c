#include <stdio.h>
#include <Windows.h>

static PBYTE read_binary(PWCHAR input_file) {
	HANDLE file_handle;
	LARGE_INTEGER file_length;
	DWORD bytes_read;
	PVOID ret;
	PBYTE file = NULL;

	file_handle = CreateFile(input_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == file_handle) {
		fprintf(stderr, "Could not open input file: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	if (FALSE == GetFileSizeEx(file_handle, &file_length)) {
		fprintf(stderr, "Could not get input file size: 0x%08X\n", GetLastError());
		goto error_exit;
	}
	//file->buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, file->buff_size);
	file = malloc((size_t)file_length.QuadPart);
	if (NULL == file) {
		fprintf(stderr, "Could not allocate virtual memory for buffer: 0x%08X\n", GetLastError());
		goto error_exit;
	}
	memset(file, 0, (size_t)file_length.QuadPart);
	if (FALSE == ReadFile(file_handle, file, (size_t)file_length.QuadPart, &bytes_read, NULL)) {
		fprintf(stderr, "Could not read input file: 0x%08X\n", GetLastError());
		goto error_exit;
	}
	else if (bytes_read != file_length.QuadPart) {
		fprintf(stderr, "Could not read input file: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	ret = file;
	goto clean_exit;
error_exit:
	ret = NULL;
clean_exit:
	/*if (NULL != file->buffer) {
		HeapFree(GetProcessHeap(), 0, file->buffer);
	}
	*/
	if (INVALID_HANDLE_VALUE != file_handle) {
		CloseHandle(file_handle);
	}
	return ret;
}

static DWORD offset_from_rva(DWORD rva, PVOID section_start, PIMAGE_NT_HEADERS nt_header, PVOID file) {
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(((DWORD)file + (DWORD)section_start));
	if (0 == rva) {
		return rva;
	}
	for (DWORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
		if (rva >= section->VirtualAddress && rva <= section->VirtualAddress + section->Misc.VirtualSize) {
			break;
		}
		section++;
	}
	return (rva - section->VirtualAddress + section->PointerToRawData);
}

static VOID read_sections(PIMAGE_NT_HEADERS nt_headers, PVOID section_start, PBYTE file) {
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(((DWORD)file + (DWORD)section_start));
	printf("Dumping sections\n");
	for (DWORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		printf("Section %s at address 0x%08X, rva at 0x%08X\n", section->Name, (DWORD)section, section->VirtualAddress);
		section++;
	}
}

static VOID read_import_table(PIMAGE_NT_HEADERS nt_headers, PVOID section_start, PBYTE file) {
	//PVOID import_table = file + nt_headers->OptionalHeader.DataDirectory[2].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(file + offset_from_rva(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, section_start, nt_headers, file));
	LPSTR dll_name[256];
	DWORD i = 0;
	while ((PVOID)import_descriptor->Name != NULL) {
		dll_name[i] = (PVOID)(file + offset_from_rva(import_descriptor->Name, section_start, nt_headers, file));
		printf("dll name: %s\n", dll_name[i]);
		PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)(file + offset_from_rva(import_descriptor->OriginalFirstThunk, section_start, nt_headers, file));
		// TODO: handle ordinal import
		while (1) {
			if (NULL == thunk_data || 0 == thunk_data->u1.AddressOfData) {
				break;
			}
			PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(file + offset_from_rva(thunk_data->u1.AddressOfData, section_start, nt_headers, file));
			printf("\timport function name: %s, address 0x%08X\n", import_by_name->Name, thunk_data->u1.Function);
			thunk_data++;
		}
		import_descriptor++;
		i++;
	}
}

static VOID read_base_reloc(PIMAGE_NT_HEADERS nt_headers, PVOID section_start, PBYTE file) {
	PIMAGE_BASE_RELOCATION base_reloc_table = (PIMAGE_BASE_RELOCATION)(file + offset_from_rva(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, section_start, nt_headers, file));
	// http://research32.blogspot.com/2015/01/base-relocation-table.html
	// http://bytepointer.com/resources/pietrek_peering_inside_pe.htm
	while (1) {
		if (base_reloc_table->SizeOfBlock == 0 && base_reloc_table->VirtualAddress == 0) {
			break;
		}
		DWORD number_of_entries = (base_reloc_table->SizeOfBlock - sizeof(*base_reloc_table)) / sizeof(WORD);
		printf("number of address to fix in virtual address 0x%08X: 0x%08X. SizeOfBlock = 0x%08X\n", 
			base_reloc_table->VirtualAddress, 
			number_of_entries, 
			base_reloc_table->SizeOfBlock);

		PWORD rva_to_fix = (PWORD)((DWORD)base_reloc_table + sizeof(*base_reloc_table));
		for (DWORD i = 0; i < number_of_entries; ++i) {
			printf("\trva 0x%08X is 0x%08X, type is 0x%08X and offset is 0x%08X\n", i, *rva_to_fix, (*rva_to_fix>>12), *rva_to_fix & (1 << 12) - 1);
			rva_to_fix++;
		}
		
		(DWORD)base_reloc_table += (DWORD)base_reloc_table->SizeOfBlock;
	}
}

static VOID read_security_cookie(PIMAGE_NT_HEADERS nt_headers, PVOID section_start, PBYTE file) {
	PIMAGE_LOAD_CONFIG_DIRECTORY32 config_dir = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(file + offset_from_rva(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, section_start, nt_headers, file));
	//DWORD cookie = (DWORD)(file + offset_from_rva((config_dir->SecurityCookie - 0x400000), section_start, nt_headers, file));
	PDWORD cookie = (PDWORD)(file + offset_from_rva(config_dir->SecurityCookie - nt_headers->OptionalHeader.ImageBase, section_start, nt_headers, file));
	
	printf("Security cookie stored at 0x%08X, rva is 0x%08X, offset is 0x%08X, value is 0x%08X\n", 
		config_dir->SecurityCookie, 
		config_dir->SecurityCookie - nt_headers->OptionalHeader.ImageBase, 
		offset_from_rva(config_dir->SecurityCookie - nt_headers->OptionalHeader.ImageBase, section_start, nt_headers, file), 
		*cookie);
}

VOID read_pe(PBYTE file) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(file + dos_header->e_lfanew);
	PVOID section_start = (PVOID)(dos_header->e_lfanew + sizeof(nt_headers->Signature) + sizeof(nt_headers->FileHeader) + nt_headers->FileHeader.SizeOfOptionalHeader);

	PVOID base_address_asm;
	__asm {
		PUSHAD
		XOR ECX, ECX
		MOV EAX, FS: [ECX + 030H] // PEB
		MOV EAX, [EAX + 0CH]      // PEB_LDR_DATA
		MOV EAX, [EAX + 014H]     // InMemoryOrderList
		MOV EBX, [EAX + 010H]     // DllBase
		MOV base_address_asm, EBX
		POPAD
	}
	PVOID base_address_module = GetModuleHandle(0);
	printf("base_address asm: 0x%08X, module handle: 0x%08X, image_base: 0x%08X\n", (DWORD)base_address_asm, (DWORD)base_address_module, nt_headers->OptionalHeader.ImageBase);
	read_sections(nt_headers, section_start, file);
	read_import_table(nt_headers, section_start, file);
	read_security_cookie(nt_headers, section_start, file);
	read_base_reloc(nt_headers, section_start, file);
	
}

int main() {
	PBYTE file = read_binary(L".\\helloWorld.exe");

	read_pe(file);
}