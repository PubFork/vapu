#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <strsafe.h>
#include <conio.h>


#define FIREWALL_SERVICE_NAMEW  L"MyVistaFirewall"

// Vista subnet mask
#define VISTA_SUBNET_MASK   0xffffffff

// Byte array IP address length
#define BYTE_IPADDR_ARRLEN    4

// Structure to store IP address filter.
typedef struct _IPFILTERINFO {
	BYTE bIpAddrToBlock[BYTE_IPADDR_ARRLEN];
	ULONG uHexAddrToBlock;
	UINT64 u64VistaFilterId;
} IPFILTERINFO, *PIPFILTERINFO;

//LamNV ADD END

/******************************************************************************
PacketFilter::ParseIPAddrString - This is an utility method to convert
IP address in string format to byte array and
hex formats.
*******************************************************************************/
bool ParseIPAddrString(LPCSTR szIpAddr, 
					   UINT nStrLen, 
					   BYTE* pbHostOrdr, 
					   UINT nByteLen, 
					   ULONG& uHexAddr )
{
	bool bRet = true;
	try
	{
		UINT i = 0;
		UINT j = 0;
		UINT nPack = 0;
		char szTemp[2];

		// Build byte array format from string format.
		for( ; ( i < nStrLen ) && ( j < nByteLen ); )
		{
			if( '.' != szIpAddr[i] ) 
			{
				::StringCchPrintf( szTemp, 2, "%c", szIpAddr[i] );
				nPack = (nPack*10) + ::atoi( szTemp );
			}
			else
			{
				pbHostOrdr[j] = nPack;
				nPack = 0;
				j++;
			}
			i++;
		}
		if( j < nByteLen )
		{
			pbHostOrdr[j] = nPack;

			// Build hex format from byte array format.
			for( j = 0; j < nByteLen; j++ )
			{
				uHexAddr = ( uHexAddr << 8 ) + pbHostOrdr[j];
			}
		}
	}
	catch(...)
	{
	}
	return bRet;
}


DWORD AddFilter(LPCSTR szIpAddrToBlock,
				HANDLE engine,				
				__in const GUID* subLayerKey)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	FWPM_FILTER0 Filter = {0};
	FWPM_FILTER_CONDITION0 Condition = {0};
	FWP_V4_ADDR_AND_MASK AddrMask = {0};

	// Prepare filter condition.
	Filter.subLayerKey = *subLayerKey;
	Filter.displayData.name = FIREWALL_SERVICE_NAMEW;	
	Filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
	Filter.action.type = FWP_ACTION_BLOCK;
	Filter.weight.type = FWP_EMPTY;
	Filter.filterCondition = &Condition;
	Filter.numFilterConditions = 1;

	// Remote IP address should match itFilters->uHexAddrToBlock.
	Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	Condition.matchType = FWP_MATCH_EQUAL;
	Condition.conditionValue.type = FWP_V4_ADDR_MASK;
	Condition.conditionValue.v4AddrMask = &AddrMask;

	// Add IP address to be blocked.
	IPFILTERINFO stIPFilter = {0};

	// Get byte array format and hex format IP address from string format.	
	ParseIPAddrString( szIpAddrToBlock,
		::lstrlen( szIpAddrToBlock ),
		stIPFilter.bIpAddrToBlock,
		BYTE_IPADDR_ARRLEN,
		stIPFilter.uHexAddrToBlock );

	AddrMask.addr = stIPFilter.uHexAddrToBlock;
	AddrMask.mask = VISTA_SUBNET_MASK;

	// Add filter condition to our interface. Save filter id in itFilters->u64VistaFilterId.
	dwFwAPiRetCode = ::FwpmFilterAdd0( engine,
		&Filter,
		NULL,
		&(stIPFilter.u64VistaFilterId));

	return dwFwAPiRetCode;
}


DWORD AddFilter(LPCSTR szIpAddrToBlock,
				HANDLE engine,				
				__in const GUID* subLayerKey)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	FWPM_FILTER0 Filter = {0};
	FWPM_FILTER_CONDITION0 Condition = {0};
	FWP_V4_ADDR_AND_MASK AddrMask = {0};

	// Prepare filter condition.
	Filter.subLayerKey = *subLayerKey;
	Filter.displayData.name = FIREWALL_SERVICE_NAMEW;	
	Filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
	Filter.action.type = FWP_ACTION_BLOCK;
	Filter.weight.type = FWP_EMPTY;
	Filter.filterCondition = &Condition;
	Filter.numFilterConditions = 1;

	// Remote IP address should match itFilters->uHexAddrToBlock.
	Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	Condition.matchType = FWP_MATCH_EQUAL;
	Condition.conditionValue.type = FWP_V4_ADDR_MASK;
	Condition.conditionValue.v4AddrMask = &AddrMask;

	// Add IP address to be blocked.
	IPFILTERINFO stIPFilter = {0};

	// Get byte array format and hex format IP address from string format.	
	ParseIPAddrString( szIpAddrToBlock,
		::lstrlen( szIpAddrToBlock ),
		stIPFilter.bIpAddrToBlock,
		BYTE_IPADDR_ARRLEN,
		stIPFilter.uHexAddrToBlock );

	AddrMask.addr = stIPFilter.uHexAddrToBlock;
	AddrMask.mask = VISTA_SUBNET_MASK;

	// Add filter condition to our interface. Save filter id in itFilters->u64VistaFilterId.
	dwFwAPiRetCode = ::FwpmFilterAdd0( engine,
		&Filter,
		NULL,
		&(stIPFilter.u64VistaFilterId));

	return dwFwAPiRetCode;
}