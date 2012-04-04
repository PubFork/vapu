// This is the main DLL file.

#include "stdafx.h"

#include "InstallEngine.h"

__declspec(dllexport)
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



__declspec(dllexport)
DWORD
Install(
		__in const GUID* providerKey,
		__in PCWSTR providerName,
		__in const GUID* subLayerKey,
		__in PCWSTR subLayerName,
		__out HANDLE* engine
		)
{
	DWORD result = ERROR_SUCCESS;
	//engine = NULL;
	FWPM_SESSION0 session;
	FWPM_PROVIDER0 provider;
	FWPM_SUBLAYER0 subLayer;

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
		engine
		);
	EXIT_ON_ERROR(FwpmEngineOpen0);

	// We add the provider and sublayer from within a single transaction to make
	// it easy to clean up partial results in error paths.
	result = FwpmTransactionBegin0(*engine, 0);
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

	result = FwpmProviderAdd0(*engine, &provider, NULL);
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

	result = FwpmSubLayerAdd0(*engine, &subLayer, NULL);
	if (result != FWP_E_ALREADY_EXISTS)
	{
		EXIT_ON_ERROR(FwpmSubLayerAdd0);
	}

	// Once all the adds have succeeded, we commit the transaction to persist
	// the new objects.
	result = FwpmTransactionCommit0(*engine);
	EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
	// FwpmEngineClose0 accepts null engine handles, so we needn't precheck for
	// null. Also, when closing an engine handle, any transactions still in
	// progress are automatically aborted, so we needn't explicitly abort the
	// transaction in error paths.
	//FwpmEngineClose0(engine);
	return result;
};