#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include "Filter.h"

#pragma comment(lib, "fwpuclnt.lib")

#define EXIT_ON_ERROR(fnName) \
	if (result != ERROR_SUCCESS) \
   { \
   printf(#fnName " = 0x%08X\n", result); \
   goto CLEANUP; \
   }


// 5fb216a8-e2e8-4024-b853-391a4168641e
const GUID PROVIDER_KEY =
{
	0x5fb216a8,
	0xe2e8,
	0x4024,
	{ 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

const GUID SUBLAYER_KEY =
{
	0x5fb116a8,
	0xe1e8,
	0x1024,
	{ 0xb7, 0x33, 0x30, 0x2a, 0x11, 0x98, 0x74, 0x2e }
};

#define SESSION_NAME L"SDK Examples"

extern "C" __declspec(dllimport)
DWORD
Install(
		__in const GUID* providerKey,
		__in PCWSTR providerName,
		__in const GUID* subLayerKey,
		__in PCWSTR subLayerName,
		__out HANDLE* engine
		);

extern "C" __declspec(dllexport)

DWORD Uninstall(
				__in const GUID* providerKey,
				__in const GUID* subLayerKey
				);
