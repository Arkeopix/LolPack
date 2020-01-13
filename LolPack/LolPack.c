#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include "LolPack.h"
#include <stdlib.h>

/// <summary>
/// This function reads a file and populate the <c>s_binary</c> pointer. 
/// </summary>
/// <param name="file">An s_binary pointer</param>
/// <param name="input_file">The path of the file to be loaded in <c>s_binary</c></param>
/// <returns>
/// A boolean value indicating status of the operation.
/// </returns>
static BOOL read_binary(s_binary* file, PWCHAR input_file) {
	HANDLE file_handle;
	LARGE_INTEGER file_length;
	DWORD bytes_read;
	BOOL ret;

	file_handle = CreateFile(input_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == file_handle) {
		fprintf(stderr, "Could not open input file: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	if (FALSE == GetFileSizeEx(file_handle, &file_length)) {
		fprintf(stderr, "Could not get input file size: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	file->buff_size = (size_t)file_length.QuadPart;
	file->buffer = VirtualAlloc(NULL, file->buff_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == file->buffer) {
		fprintf(stderr, "Could not allocate virtual memory for buffer: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	if (FALSE == ReadFile(file_handle, file->buffer, file->buff_size, &bytes_read, NULL)) {
		fprintf(stderr, "Could not read input file: 0x%08X\n", GetLastError());
		goto error_exit;
	} else if (bytes_read != file_length.QuadPart) {
		fprintf(stderr, "Could not read input file: 0x%08X\n", GetLastError());
		goto error_exit;
	}

	ret = TRUE;
	goto clean_exit;
error_exit:
	ret = FALSE;
clean_exit:
	if (INVALID_HANDLE_VALUE != file_handle) {
		CloseHandle(file_handle);
	}
	return ret;
}

/// <summary> Plain and simple xor encryption. Generate a "random" key, which is a simple byte.</summary>
/// <param name=payload>An s_binary pointer. Must have been filled with a call to load_binary</param>
/// <returns>nothing</returns>
static VOID encrypt(s_binary *payload) {
	payload->key = rand() % 255;
	for (size_t i = 0; i < payload->buff_size; ++i) {
		payload->buffer[i] ^= payload->key;
	}
}

/// <summary>Reads in the stub, dump it to disk.
/// TODO: Instead of reading the file, find a way to include it as a resource in lolpack, maybe when compiling ?
/// </summary>
/// <param name="output_file">The path to the packed executable</param>
/// <returns>A boolean value indicating status of operation</returns>
static BOOL create_stub(PWCHAR output_file) {
	s_binary stub;
	DWORD bytes_written = 0;

	read_binary(&stub, L".\\LolCraddle.exe");
	HANDLE out_file = CreateFile(output_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == out_file) {
		printf("Could not create file: %d\n", GetLastError());
		return FALSE;
	}

	if (FALSE == WriteFile(out_file, stub.buffer, stub.buff_size, &bytes_written, NULL)) {
		printf("Could not write file: %d\n", GetLastError());
		return FALSE;
	}
	CloseHandle(out_file);
	return TRUE;
}

/// <summary>Updates the stub by adding the buffer and the key as resources</summary>
/// <param name="file">An s_bynary pointer</param>
/// <param name="output_file">The path of the packed executable</param>
/// <returns>A boolean value indicating status of operation</returns>
static BOOL update_stub(s_binary* file, PWCHAR output_file) {
	DWORD ret = 0;
	HANDLE out_pe = NULL;

	out_pe = BeginUpdateResource(output_file, TRUE);
	if (NULL == out_pe) {
		printf("Could not begin update resource: %d\n", GetLastError());
		return FALSE;
	}

	if (FALSE == UpdateResource(out_pe, RT_RCDATA, MAKEINTRESOURCE(IDD_PAYLOAD_DATA), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), file->buffer, file->buff_size)) {
		printf("Could not update resource: %d\n", GetLastError());
		return FALSE;
	}

	if (FALSE == UpdateResource(out_pe, RT_RCDATA, MAKEINTRESOURCE(IDD_PAYLOAD_KEY), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), &file->key, sizeof(BYTE))) {
		printf("Could not update resource: %d\n", GetLastError());
		return FALSE;
	}

	if (FALSE == EndUpdateResource(out_pe, FALSE)) {
		printf("Could not close resource handle: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

int wmain(DWORD argc, PWCHAR *argv) {
	PWCHAR input_file = NULL;
	PWCHAR output_file = NULL;
	s_binary payload = { 0 };
	if (2 > argc) {
		printf("Usage: %ls -f <unpacked PE name> -o <output packed PE name>\n", argv[0]);
		return 0;
	}

	for (DWORD i = 1; i < argc; i++) {
		if (0 == wcsncmp(argv[i], L"-f", 2)) {
			input_file = argv[i + 1];
			printf("input filename is %ls\n", input_file);
		}

		if (0 == wcsncmp(argv[i], L"-o", 2)) {
			output_file = argv[i + 1];
			printf("output filename is %ls\n", output_file);
		}
	}

	if (NULL == input_file || NULL == output_file) {
		printf("Usage: %ls -f <unpacked PE name> -o <output packed PE name>\n", argv[0]);
		return 0;
	}
	if (FALSE == read_binary(&payload, input_file)) {
		return -1;
	}
	encrypt(&payload);
	if (FALSE == create_stub(output_file)) {
		return -1;
	}
	if (FALSE == update_stub(&payload, output_file)) {
		return -1;
	}

	return 0;
}