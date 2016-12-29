// WhitewoodEncryptionRandNumProvider.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "WhitewoodEncryptionRandNumProvider.h"


// This is an example of an exported variable
WHITEWOODENCRYPTIONRANDNUMPROVIDER_API int nWhitewoodEncryptionRandNumProvider=0;

// This is an example of an exported function.
WHITEWOODENCRYPTIONRANDNUMPROVIDER_API int fnWhitewoodEncryptionRandNumProvider(void)
{
    return 42;
}

// This is the constructor of a class that has been exported.
// see WhitewoodEncryptionRandNumProvider.h for the class definition
//CWhitewoodEncryptionRandNumProvider::CWhitewoodEncryptionRandNumProvider()
//{
//    return;
//}
// CNGProvider.cpp : Defines the exported functions for the DLL application.
//  Windows 8 : Beginning with Windows 8, the RNG algorithm supports FIPS 186 - 3. 
//  Keys less than or equal to 1024 bits adhere to FIPS 186 - 2 
//  and keys greater than 1024 to FIPS 186 - 3
//

#include "stdafx.h"
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <windows.h>
#include <strsafe.h>
#include <setupapi.h>
#include <spapidef.h>
#include <windows.h>
#include <bcrypt.h>
#include "../Include/bcrypt_provider.h"
#include <setupapi.h>
#include <tchar.h>

#include <stdio.h>
#include "WhitewoodEncryptionRandNumProvider.h"
//#include "NetRandomProvider.h"
#include <winternl.h>


#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include "..\include\dllhelper.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include <malloc.h>
#include <windows.h>

	//helper macros
#define MALLOC(X)   HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (X));

#define FREE(X)     { if(X) { HeapFree(GetProcessHeap(), 0, X); X = NULL ; } }

#include <bcrypt.h>
#include "..\include\bcrypt_provider.h"
}
//
#define WERNG_PROVIDER_NAME L"NetRand RNG Provider"

#include ".\..\Include\bcrypt_provider.h"
#include <sal.h>



#define WERNG_IMAGE_NAME L"WhitewoodRandom.dll"

PWSTR WERngAlgorithmNames[1] = {
	BCRYPT_RNG_ALGORITHM
};

CRYPT_INTERFACE_REG WERngInterface = {
	BCRYPT_RNG_INTERFACE, CRYPT_LOCAL, 1, WERngAlgorithmNames
};

PCRYPT_INTERFACE_REG WERngInterfaces[1] = {
	&WERngInterface
};

CRYPT_IMAGE_REG WERngImage = {
	WERNG_IMAGE_NAME, 1, WERngInterfaces
};

CRYPT_PROVIDER_REG WERngProvider = {
	0, NULL, &WERngImage, NULL
};

typedef ULONG(WINAPI* RtlNtStatusToDosErrorFunc)(IN NTSTATUS status);

static DWORD ToDosError(NTSTATUS status)
{
	DWORD error = NO_ERROR;
	HMODULE ntdll;
	RtlNtStatusToDosErrorFunc RtlNtStatusToDosError;

	ntdll = LoadLibrary(L"Ntdll.dll");
	if (ntdll != NULL)
	{
		RtlNtStatusToDosError = (RtlNtStatusToDosErrorFunc)
			GetProcAddress(ntdll, "RtlNtStatusToDosError");

		if (RtlNtStatusToDosError != NULL)
		{
			error = RtlNtStatusToDosError(status);
		}
		else
		{
			error = GetLastError();
			SetupWriteTextLogError(SetupGetThreadLogToken(),
				TXTLOG_INSTALLER,
				TXTLOG_ERROR,
				error,
				"RtlNtStatusToDosError function not found.");
		}
	}
	else
	{
		error = GetLastError();
		SetupWriteTextLogError(SetupGetThreadLogToken(),
			TXTLOG_INSTALLER,
			TXTLOG_ERROR,
			error,
			"Failed to load ntdll.dll.");
	}

	return error;
}

// This is an example of an exported variable
WHITEWOODENCRYPTIONRANDNUMPROVIDER_API int nCNGProvider = 0;
WHITEWOODENCRYPTIONRANDNUMPROVIDER_API NTSTATUS WINAPI GetInterface(
	_In_   LPCWSTR pszProviderName,
	_Out_  BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable,
	_In_   ULONG dwFlags
);

/* visual aid for dev
typedef struct _BCRYPT_RNG_FUNCTION_TABLE {
BCRYPT_INTERFACE_VERSION       Version;
BCryptOpenAlgorithmProviderFn  OpenAlgorithmProvider;
BCryptGetPropertyFn            GetProperty;
BCryptSetPropertyFn            SetProperty;
BCryptCloseAlgorithmProviderFn CloseAlgorithmProvider;
BCryptGenRandomFn              GenRandom;
} BCRYPT_RNG_FUNCTION_TABLE;
*/
BCRYPT_RNG_FUNCTION_TABLE RngFunctionTable;

typedef NTSTATUS(WINAPI *BCryptOpenAlgorithmProviderFn)(
	_Out_  BCRYPT_ALG_HANDLE *phAlgorithm,
	_In_   LPCWSTR pszAlgId,
	_In_   ULONG dwFlags
	);

typedef NTSTATUS(WINAPI *BCryptGetPropertyFn)(
	_In_   BCRYPT_HANDLE hObject,
	_In_   LPCWSTR pszProperty,
	_Out_  PUCHAR pbOutput,
	_In_   ULONG cbOutput,
	_Out_  ULONG *pcbResult,
	_In_   ULONG dwFlags
	);

typedef NTSTATUS(WINAPI *BCryptSetPropertyFn)(
	_Inout_  BCRYPT_HANDLE hObject,
	_In_     LPCWSTR pszProperty,
	_In_     PUCHAR pbInput,
	_In_     ULONG cbInput,
	_In_     ULONG dwFlags
	);

typedef NTSTATUS(WINAPI *BCryptGenRandomFn)(
	_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
	_Inout_  PUCHAR pbBuffer,
	_In_     ULONG cbBuffer,
	_In_     ULONG dwFlags
	);

typedef NTSTATUS(WINAPI *BCryptCloseAlgorithmProviderFn)(
	_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
	_In_     ULONG dwFlags
	);

/* This is an example of an exported function.
CNGPROVIDER_API int fnCNGProvider(void)
{
	return 42;
}
*/
// This is the constructor of a class that has been exported.
// see CNGProvider.h for the class definition
//CCNGProvider::CCNGProvider()
//{
//	return;
//}


NTSTATUS(WINAPI OpenProvider)(
	_Out_  BCRYPT_ALG_HANDLE *phAlgorithm,
	_In_   LPCWSTR pszAlgId,
	_In_   ULONG dwFlags
	)
{
	/*
	open up the network source and start the entropy fetch engine
	we will leave the entropy fetch status to fetch

	*/
	return STATUS_NOT_IMPLEMENTED;
}

_Must_inspect_result_ NTSTATUS(WINAPI  CloseProvider)(
	_Inout_ BCRYPT_ALG_HANDLE   hAlgorithm,
	_In_    ULONG   dwFlags)
{
	return STATUS_NOT_IMPLEMENTED;
}
NTSTATUS(WINAPI GetProperty)(
	_In_   BCRYPT_HANDLE hObject,
	_In_   LPCWSTR pszProperty,
	_Out_  PUCHAR pbOutput,
	_In_   ULONG cbOutput,
	_Out_  ULONG *pcbResult,
	_In_   ULONG dwFlags
	)
{
	return STATUS_NOT_IMPLEMENTED;
}
NTSTATUS(WINAPI SetProperty)(
	_Inout_  BCRYPT_HANDLE hObject,
	_In_     LPCWSTR pszProperty,
	_In_     PUCHAR pbInput,
	_In_     ULONG cbInput,
	_In_     ULONG dwFlags
	)
{
	return STATUS_NOT_IMPLEMENTED;
}
NTSTATUS(WINAPI GetRandom)(
	_Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
	_Inout_  PUCHAR pbBuffer,
	_In_     ULONG cbBuffer,
	_In_     ULONG dwFlags
	)
{
	return STATUS_NOT_IMPLEMENTED;
}

WHITEWOODENCRYPTIONRANDNUMPROVIDER_API NTSTATUS WINAPI GetInterface(LPCWSTR pszProviderName, BCRYPT_RNG_FUNCTION_TABLE ** ppFunctionTable, ULONG dwFlags)
{
	//	Let's initialize the function table
	RngFunctionTable.OpenAlgorithmProvider = OpenProvider;
	RngFunctionTable.GetProperty = GetProperty;
	RngFunctionTable.SetProperty = SetProperty;
	RngFunctionTable.GenRandom = GetRandom;
	RngFunctionTable.CloseAlgorithmProvider = CloseProvider;

	RngFunctionTable.Version = BCRYPT_RNG_INTERFACE_VERSION_1;
	return NTSTATUS();
}// provider.cpp : Defines the entry point for the DLL application.
 //

#include "stdafx.h"
//#include "NetRandomProvider.h"


#ifdef _MANAGED
#pragma managed(push, off)
#endif


 ///////////////////////////////////////////////////////////////////////////////
 //
 // Local definitions...
 //
 ///////////////////////////////////////////////////////////////////////////////
 //
 // These NTSTATUS items are not currently defined in BCRYPT.H. Unitl this is
 // corrected, the easiest way to make them available is to cut and paste them 
 // from NTSTATUS.H...
 //
#ifndef NTSTATUS
typedef LONG NTSTATUS, *PNSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_HMAC_NOT_SUPPORTED        ((NTSTATUS)0xC000A001L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#endif



//#define STRICT
#include <windows.h>
#include <bcrypt.h>
#include "..\include\bcrypt_provider.h"
#include <setupapi.h>
#include <tchar.h>

#include <stdio.h>






/*
PWSTR WERngAlgorithmNames[1] = {
BCRYPT_RNG_ALGORITHM
};

CRYPT_INTERFACE_REG WERngInterface = {
BCRYPT_RNG_INTERFACE, CRYPT_LOCAL, 1, WERngAlgorithmNames
};


PCRYPT_INTERFACE_REG WERngInterfaces[1] = {
&WERngInterface
};
*/
/*CRYPT_IMAGE_REG WERngImage = {
WERNG_IMAGE_NAME, 1, WERngInterfaces
};

CRYPT_PROVIDER_REG WERngProvider = {
0, NULL, &WERngImage, NULL
};

typedef DWORD(WINAPI* RtlNtStatusToDosErrorFunc)(IN NTSTATUS status);

static DWORD ToDosError(IN NTSTATUS status)
{
DWORD error = NO_ERROR;
HMODULE ntdll;
RtlNtStatusToDosErrorFunc RtlNtStatusToDosError;

ntdll = LoadLibrary(L"Ntdll.dll");
if (ntdll != NULL)
{
RtlNtStatusToDosError = (RtlNtStatusToDosErrorFunc)
GetProcAddress(ntdll, "RtlNtStatusToDosError");

if (RtlNtStatusToDosError != NULL)
{
error = RtlNtStatusToDosError(status);
}
else
{
error = GetLastError();
SetupWriteTextLogError(SetupGetThreadLogToken(),
TXTLOG_INSTALLER,
TXTLOG_ERROR,
error,
"RtlNtStatusToDosError function not found.");
}
}
else
{
error = GetLastError();
SetupWriteTextLogError(SetupGetThreadLogToken(),
TXTLOG_INSTALLER,
TXTLOG_ERROR,
error,
"Failed to load ntdll.dll.");
}

return error;
}
*/
NTSTATUS WINAPI RegisterProvider(BOOLEAN KernelMode)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(KernelMode);

	status = BCryptRegisterProvider(WERNG_PROVIDER_NAME, CRYPT_OVERWRITE,
		&WERngProvider);

	if (!NT_SUCCESS(status))
	{
		SetupWriteTextLogError(SetupGetThreadLogToken(),
			TXTLOG_INSTALLER,
			TXTLOG_ERROR,
			ToDosError(status),
			"Failed to register as a CNG provider.");
		return status;
	}

	status = BCryptAddContextFunctionProvider(CRYPT_LOCAL, NULL,
		BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, WERNG_PROVIDER_NAME,
		CRYPT_PRIORITY_BOTTOM);

	if (!NT_SUCCESS(status))
	{
		SetupWriteTextLogError(SetupGetThreadLogToken(),
			TXTLOG_INSTALLER,
			TXTLOG_ERROR,
			ToDosError(status),
			"Failed to add cryptographic function.");
	}

	return status;
}

NTSTATUS WINAPI UnregisterProvider()
{
	NTSTATUS status;

	status = BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, NULL,
		BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, WERNG_PROVIDER_NAME);

	if (!NT_SUCCESS(status))
	{
		SetupWriteTextLogError(SetupGetThreadLogToken(),
			TXTLOG_INSTALLER,
			TXTLOG_WARNING,
			ToDosError(status),
			"Failed to remove cryptographic function.");
	}

	status = BCryptUnregisterProvider(WERNG_PROVIDER_NAME);
	if (!NT_SUCCESS(status))
	{
		SetupWriteTextLogError(SetupGetThreadLogToken(),
			TXTLOG_INSTALLER,
			TXTLOG_WARNING,
			ToDosError(status),
			"Failed to unregister as a CNG provider.");
	}

	return STATUS_SUCCESS;
}

DWORD CALLBACK WERngCoInstaller(IN DI_FUNCTION InstallFunction,
	IN HDEVINFO DeviceInfoSet,
	IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL,
	IN OUT PCOINSTALLER_CONTEXT_DATA Context)
{
	NTSTATUS status;
	DWORD error = NO_ERROR;

	UNREFERENCED_PARAMETER(DeviceInfoSet);
	UNREFERENCED_PARAMETER(DeviceInfoData);
	UNREFERENCED_PARAMETER(Context);

	switch (InstallFunction)
	{
	case DIF_INSTALLDEVICE:
		status = RegisterProvider(FALSE);
		if (!NT_SUCCESS(status))
		{
			error = ToDosError(status);
		}
		break;

	case DIF_REMOVE:
		status = UnregisterProvider();
		if (!NT_SUCCESS(status))
		{
			error = ToDosError(status);
		}
		break;

	default:
		break;
	}

	return error;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

