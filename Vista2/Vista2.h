// Vista2.h
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <strsafe.h>
#include <conio.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma once

//#include "Provider.h"
//#include "Permitting.h"
//#include "Filter.h"


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

class VistaFilter
{
private:
	UINT64 u64VistaFilterId;
	HANDLE engine;
protected:
	DWORD Install(
		__in const GUID* providerKey,
		__in PCWSTR providerName,
		__in const GUID* subLayerKey,
		__in PCWSTR subLayerName
		)
	{
		DWORD result = ERROR_SUCCESS;	
		FWPM_SESSION0 session;
		FWPM_PROVIDER0 provider;
		FWPM_SUBLAYER0 subLayer;
		engine = NULL;

		memset(&session, 0, sizeof(session));
		// The session name isn't required but may be useful for diagnostics.
		session.displayData.name = SESSION_NAME;
		// Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
		// errors while waiting to acquire the transaction lock.
		session.txnWaitTimeoutInMSec = INFINITE;

		// The authentication service should always be RPC_C_AUTHN_DEFAULT.
		result = FwpmEngineOpen0(
			NULL,
			RPC_C_AUTHN_DEFAULT,
			NULL,
			&session,
			&engine
			);
		EXIT_ON_ERROR(FwpmEngineOpen0);

		// We add the provider and sublayer from within a single transaction to make
		// it easy to clean up partial results in error paths.
		result = FwpmTransactionBegin0(engine, 0);
		EXIT_ON_ERROR(FwpmTransactionBegin0);

		memset(&provider, 0, sizeof(provider));
		// The provider and sublayer keys are going to be used repeatedly when
		// adding filters and other objects. It's easiest to use well-known GUIDs
		// defined in a header somewhere, rather than having BFE generate the keys.
		provider.providerKey = *providerKey;
		// For MUI compatibility, object names should be indirect strings. See
		// SHLoadIndirectString for details.
		provider.displayData.name = (PWSTR)providerName;
		// Since we always want the provider and sublayer to be present, it's
		// easiest to add them as persistent objects during install.  Alternatively,
		// we could add non-persistent objects every time our service starts.
		provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

		result = FwpmProviderAdd0(engine, &provider, NULL);
		// Ignore FWP_E_ALREADY_EXISTS. This allows install to be re-run as needed
		// to repair a broken configuration.
		if (result != FWP_E_ALREADY_EXISTS)
		{
			EXIT_ON_ERROR(FwpmProviderAdd0);
		}

		memset(&subLayer, 0, sizeof(subLayer));
		subLayer.subLayerKey = *subLayerKey;
		subLayer.displayData.name = (PWSTR)subLayerName;
		subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
		// Link all our other objects to our provider. When multiple providers are
		// installed on a computer, this makes it easy to determine who added what.
		subLayer.providerKey = (GUID*)providerKey;
		// We don't care what our sublayer weight is, so we pick a weight in the
		// middle and let BFE assign the closest available.
		subLayer.weight = 0x8000;

		result = FwpmSubLayerAdd0(engine, &subLayer, NULL);
		if (result != FWP_E_ALREADY_EXISTS)
		{
			EXIT_ON_ERROR(FwpmSubLayerAdd0);
		}

		// Once all the adds have succeeded, we commit the transaction to persist
		// the new objects.
		result = FwpmTransactionCommit0(engine);
		EXIT_ON_ERROR(FwpmTransactionCommit0);
CLEANUP:
		// FwpmEngineClose0 accepts null engine handles, so we needn't precheck for
		// null. Also, when closing an engine handle, any transactions still in
		// progress are automatically aborted, so we needn't explicitly abort the
		// transaction in error paths.
		//FwpmEngineClose0(engine);
		return result;
	}


	DWORD Uninstall(
		__in const GUID* providerKey,
		__in const GUID* subLayerKey
		)
	{
		DWORD result = ERROR_SUCCESS;
		HANDLE engine = NULL;
		FWPM_SESSION0 session;

		memset(&session, 0, sizeof(session));
		// The session name isn't required but may be useful for diagnostics.
		session.displayData.name = SESSION_NAME;
		// Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
		// errors while waiting to acquire the transaction lock.
		session.txnWaitTimeoutInMSec = INFINITE;

		// The authentication service should always be RPC_C_AUTHN_DEFAULT.
		result = FwpmEngineOpen0(
			NULL,
			RPC_C_AUTHN_DEFAULT,
			NULL,
			&session,
			&engine
			);
		EXIT_ON_ERROR(FwpmEngineOpen0);

		// We delete the provider and sublayer from within a single transaction, so
		// that we always leave the system in a consistent state even in error
		// paths.
		result = FwpmTransactionBegin0(engine, 0);
		EXIT_ON_ERROR(FwpmTransactionBegin0);

		// We have to delete the sublayer first since it references the provider. If
		// we tried to delete the provider first, it would fail with FWP_E_IN_USE.
		result = FwpmSubLayerDeleteByKey0(engine, subLayerKey);
		if (result != FWP_E_SUBLAYER_NOT_FOUND)
		{
			// Ignore FWP_E_SUBLAYER_NOT_FOUND. This allows uninstall to succeed even
			// if the current configuration is broken.
			EXIT_ON_ERROR(FwpmSubLayerDeleteByKey0);
		}

		result = FwpmProviderDeleteByKey0(engine, providerKey);
		if (result != FWP_E_PROVIDER_NOT_FOUND)
		{
			EXIT_ON_ERROR(FwpmProviderDeleteByKey0);
		}

		// Once all the deletes have succeeded, we commit the transaction to
		// atomically delete all the objects.
		result = FwpmTransactionCommit0(engine);
		EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
		// FwpmEngineClose0 accepts null engine handles, so we needn't precheck for
		// null. Also, when closing an engine handle, any transactions still in
		// progress are automatically aborted, so we needn't explicitly abort the
		// transaction in error paths.
		FwpmEngineClose0(engine);
		return result;
	}

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
		//IPFILTERINFO stIPFilter = {0};
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

		u64VistaFilterId = stIPFilter.u64VistaFilterId;

		return dwFwAPiRetCode;
	}

public:
	DWORD StartFireWall(LPCSTR szIpAddrToBlock)
	{	
		DWORD dwResult = Install(&PROVIDER_KEY, L"Provider_name", &SUBLAYER_KEY, L"SubLayer_name");
		if (dwResult == NO_ERROR)
		{
			dwResult = AddFilter(szIpAddrToBlock, &SUBLAYER_KEY);
		}

		return dwResult;
	}

	DWORD StopFireWall()
	{
		FwpmFilterDeleteById0( engine, u64VistaFilterId );
		u64VistaFilterId = 0;

		return Uninstall(&PROVIDER_KEY, &SUBLAYER_KEY);
	}
};
