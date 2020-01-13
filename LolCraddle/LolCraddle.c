#include "LolCraddle.h"

/// <summary>
/// Reads resources to load them in. Sets up the s_binary struct used troughout the "unpacking" process
/// </summary>
/// <param name="bin">An s_binary pointer</param>
/// <returns>A boolean value indicating the status of the operation</returns>
static BOOL load_binary(s_binary* bin) {
	BOOL ret = TRUE;
	HRSRC resource = NULL;
	HGLOBAL resource_handle = NULL;
	PVOID res = NULL;

	resource = FindResource(NULL, MAKEINTRESOURCE(IDD_PAYLOAD_DATA), RT_RCDATA);
	if (NULL == resource) {
		printf("Could not find resouirce %d\n", GetLastError());
		goto fail;
	}

	resource_handle = LoadResource(NULL, resource);
	if (NULL == resource_handle) {
		printf("Could not open resource payload: %d\n", GetLastError());
		goto fail;
	}

	bin->buff_size = SizeofResource(NULL, resource);
	if (0 == bin->buff_size) {
		printf("Could not get ressource size: %d\n", GetLastError());
		goto fail;
	}
	
	bin->buffer = VirtualAlloc(NULL, bin->buff_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == bin->buffer) {
		printf("Could not allocate memory for ressource: %d\n", GetLastError());
		goto fail;
	}
	CopyMemory(bin->buffer, LockResource(resource_handle), bin->buff_size);

	resource = FindResource(NULL, MAKEINTRESOURCE(IDD_PAYLOAD_KEY), RT_RCDATA);
	if (NULL == resource) {
		printf("Could not find resource: %d\n", GetLastError());
		goto fail;
	}

	resource_handle = LoadResource(NULL, resource);
	if (NULL == resource_handle) {
		printf("Could not open resource key: %d\n", GetLastError());
		goto fail;
	}
	bin->key = *(PBYTE)LockResource(resource_handle);

	for (size_t i = 0; i < bin->buff_size; ++i) {
		bin->buffer[i] ^= bin->key;
	}

	bin->dos_header = (PIMAGE_DOS_HEADER)bin->buffer;
	if (IMAGE_DOS_SIGNATURE != bin->dos_header->e_magic) {
		printf("Signature missmatch on dos header, aborting. Got 0x%04X\n", bin->dos_header->e_magic);
		goto fail;
	}
	bin->nt_headers = (PIMAGE_NT_HEADERS)(((DWORD)bin->buffer) + bin->dos_header->e_lfanew);
	if (IMAGE_NT_SIGNATURE != bin->nt_headers->Signature) {
		printf("Signature missmatch on nt header, aborting\n");
		goto fail;
	}
	goto exit;
fail:
	ret = FALSE;
	if (NULL != bin->buffer) {
		if (FALSE == VirtualFree(bin->buffer, 0, MEM_RELEASE)) {
			printf("Could ne release memory: %d\n", GetLastError());
		}
	}
exit:
	return ret;
}

/// <summary>
/// Allocates a new chunk of memory and maps the program inside s_binary in it.
/// </summary>
/// <param name="bin">An s_binary pointer</param>
/// <returns>A boolean value indicating the status of the operation</returns>
static BOOL map_binary(s_binary* bin) {
	BOOL ret = TRUE;
	PIMAGE_SECTION_HEADER section;

	// We don't care about where the newx base address is so we pass NULL as the first parameter
	bin->map_base = VirtualAlloc(NULL, bin->nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == bin->map_base) {
		printf("Could not allocate memory for new PE: %d\n", GetLastError());
		goto fail;
	}
	// Now we copy the program headers in memory, starting at the new base address
	CopyMemory(bin->map_base, bin->buffer, bin->nt_headers->OptionalHeader.SizeOfHeaders);
	// And we continue with sections
	section = IMAGE_FIRST_SECTION(bin->nt_headers);
	for (DWORD i = 0; i < bin->nt_headers->FileHeader.NumberOfSections; ++i) {
		CopyMemory((PVOID)((DWORD)bin->map_base + section->VirtualAddress), (PVOID)(bin->buffer + section->PointerToRawData), section->SizeOfRawData);
		section++;
	}
	
	ret = TRUE;
	goto exit;
fail:
	ret = FALSE;
exit:
	return ret;
}

/// <summary>
/// Reads in the Import descriptors to fill in the IAT
/// TODO: Import per ordinal
/// </summary>
/// <param name="bin">An s_binary pointer</param>
/// <returns>A boolean value indicating the status of the operation</returns>
static BOOL resolve_iat(s_binary* bin) {
	BOOL ret = TRUE;
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_headers = NULL;
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;
	PIMAGE_THUNK_DATA thunk_data_lookup = NULL, thunk_data_iat = NULL;
	PIMAGE_IMPORT_BY_NAME import_by_name = NULL;
	LPCSTR dll_name = NULL;
	HMODULE module_handle = NULL;

	dos_header = (PIMAGE_DOS_HEADER)bin->map_base;
	nt_headers = (PIMAGE_NT_HEADERS)(PIMAGE_NT_HEADERS)((PBYTE)bin->map_base + dos_header->e_lfanew);
	// Each dll will have its own import descriptor. The last import descriptor is NULL
	import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)bin->map_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while ((PVOID)import_descriptor->Name != NULL) {
		// Foreach import descriptor, we read the import lookup table and the import address table
		thunk_data_lookup = (PIMAGE_THUNK_DATA)((DWORD)bin->map_base + import_descriptor->OriginalFirstThunk);
		thunk_data_iat = (PIMAGE_THUNK_DATA)((DWORD)bin->map_base + import_descriptor->FirstThunk);
		dll_name = (PVOID)((DWORD)bin->map_base + import_descriptor->Name);
		module_handle = LoadLibraryA(dll_name);
		if (NULL == module_handle) {
			printf("Could not load library %s:%d\n", dll_name, GetLastError());
			goto fail;
		}
		while (thunk_data_lookup->u1.AddressOfData != 0) {
			// We get the import by name from the lookup table, resolve it's address and fill it in the IAT
			import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)bin->map_base + thunk_data_lookup->u1.AddressOfData);
			thunk_data_iat->u1.Function = (DWORD)GetProcAddress(module_handle, import_by_name->Name);
			if (0 == thunk_data_iat->u1.Function) {
				printf("Could not import function %s:%d\n", import_by_name->Name, GetLastError());
				goto fail;
			}
			thunk_data_lookup++;
			thunk_data_iat++;
		}
		import_descriptor++;
	}

	ret = TRUE;
	goto exit;
fail:
	ret = FALSE;
exit:
	return ret;
}

/// <summary>
/// Calculates the delta between the recommended base address and the actual base address.
/// Then the difference is applied to the addresses indicated in the reloc table
/// Usefull resources:
///     * http://research32.blogspot.com/2015/01/base-relocation-table.html
///     * http://bytepointer.com/resources/pietrek_peering_inside_pe.htm
///     * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
/// TODO: Import per ordinal
/// </summary>
/// <param name="bin">An s_binary pointer</param>
/// <returns>A boolean value indicating the status of the operation</returns>
static BOOL resolve_reloc(s_binary* bin) {
	BOOL ret = TRUE;
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_headers = NULL;
	PIMAGE_BASE_RELOCATION base_reloc_table = NULL;
	PWORD rva_to_fix = NULL;
	UINT reloc_delta = 0;
	DWORD number_of_entries = 0;

	dos_header = (PIMAGE_DOS_HEADER)bin->map_base;
	nt_headers = (PIMAGE_NT_HEADERS)(PIMAGE_NT_HEADERS)((PBYTE)bin->map_base + dos_header->e_lfanew);
	// The delta is computed by substracting the recommended base address (0x400000) to the actual base address
	reloc_delta = (DWORD)(bin->nt_headers->OptionalHeader.ImageBase) - (DWORD)(bin->map_base);
	base_reloc_table = (PIMAGE_BASE_RELOCATION)((DWORD)bin->map_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while (base_reloc_table->SizeOfBlock != 0 && base_reloc_table->VirtualAddress != 0) {
		number_of_entries = (base_reloc_table->SizeOfBlock - sizeof(*base_reloc_table)) / sizeof(WORD);
		rva_to_fix = (PWORD)((DWORD)base_reloc_table + sizeof(*base_reloc_table));
		for (DWORD i = 0; i < number_of_entries; ++i) {
			// Each entry is a byte holding the type of reloc in the 4 high bits and the offset to reloc in the lowest 12 bits.
			// In x86, type will always be IMAGE_REL_BASED_HIGHLOW. We just check the type in order to ignore the IMAGE_BASE_RELOCATION structure between
			// two blocks while we iterate.
			if (3 == (*rva_to_fix >> 12)) {
				*(PDWORD)((DWORD)bin->map_base + (DWORD)(base_reloc_table->VirtualAddress + (*rva_to_fix & (1 << 12) - 1))) -= reloc_delta;
			}
			rva_to_fix++;
		}
		(DWORD)base_reloc_table += (DWORD)base_reloc_table->SizeOfBlock;
	}
	return TRUE;
}

/// <summary>
/// Jumps to the entrypoint of the newly mapped program
/// </summary>
/// <param name="bin">An s_binary pointer</param>
/// <returns>A boolean value indicating the status of the operation</returns>
static BOOL execute_payload(s_binary* bin) {
	DWORD entry_point = 0, base_address = 0, map_base = 0;
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_headers = NULL;

	dos_header = (PIMAGE_DOS_HEADER)bin->map_base;
	nt_headers = (PIMAGE_NT_HEADERS)(PIMAGE_NT_HEADERS)((PBYTE)bin->map_base + dos_header->e_lfanew);
	entry_point = (DWORD)bin->map_base + bin->nt_headers->OptionalHeader.AddressOfEntryPoint;
	__asm {
		MOV EAX, entry_point
		JMP EAX
	}
	return TRUE;
}

static DWORD loader(VOID) {
	s_binary bin = { 0 };
	if (FALSE == load_binary(&bin)) {
		printf("Could not load binary\n");
		return -1;
	}
	if (FALSE == map_binary(&bin)) {
		printf("Could not map binary\n");
		return -1;
	}
	if (FALSE == resolve_iat(&bin)) {
		printf("Could not resolve IAT\n");
		return -1;
	}
	if (FALSE == resolve_reloc(&bin)) {
		printf("Could not resolve reloc");
		return -1;
	}
	if (FALSE == execute_payload(&bin)) {
		// never reached
		printf("Could not execute payload");
		return -1;
	}
	return 0;
}

int main()
{
	loader();
	return 0;
}