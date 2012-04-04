#include "stdafx.h"

#include "IntallFilter.h"

__declspec(dllexport) 
DWORD RemoveFilter(HANDLE engine, 
				  UINT64 u64VistaFilterId)
{
	return FwpmFilterDeleteById0(engine, u64VistaFilterId );
}

__declspec(dllexport) 
DWORD AddFilter(LPCSTR szIpAddrToBlock,
				HANDLE engine,				
				__in const GUID* subLayerKey,
				__out UINT64* u64VistaFilterId)
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
		u64VistaFilterId);

	return dwFwAPiRetCode;
}