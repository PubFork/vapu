#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <conio.h>
#include "FilterUtil.h"


#define FIREWALL_SERVICE_NAMEW  L"MyVistaFirewall"


/******************************************************************************
PacketFilter::ParseIPAddrString - This is an utility method to convert
IP address in string format to byte array and
hex formats.
*******************************************************************************/
extern "C" __declspec(dllimport)
DWORD AddFilter(LPCSTR szIpAddrToBlock,
				HANDLE engine,				
				__in const GUID* subLayerKey,
				__out UINT64* u64VistaFilterId);

extern "C" __declspec(dllimport)
DWORD RemoveFilter(HANDLE engine, 
				  UINT64 u64VistaFilterId);