#pragma once

#include <Windows.h>

#define IDD_PAYLOAD_DATA 1
#define IDD_PAYLOAD_KEY  2

typedef struct _binary {
	PBYTE buffer;
	size_t buff_size;
	BYTE key;
} s_binary;