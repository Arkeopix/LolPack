#include <Windows.h>
#include <stdio.h>

#define IDD_PAYLOAD_DATA 1
#define IDD_PAYLOAD_KEY  2

typedef struct _binary {
	BYTE key;
	PBYTE buffer;
	size_t buff_size;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PVOID map_base;
} s_binary;