
#ifndef _NETRANDPROV_H_
#define _NETRANDPROV_H_


#ifdef __cplusplus
extern "C"
{
#endif

#include <malloc.h>
#include <windows.h>

	//helper macros
#define MALLOC(X)   HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (X));

#define FREE(X)     { if(X) { HeapFree(GetProcessHeap(), 0, X); X = NULL ; } }
//#define WERNG_PROVIDER_NAME L"Whitewood Encryption RNG Provider"
#include <bcrypt.h>
#include "bcrypt_provider.h"
}

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

//
#endif //_NETRANDPROV_H_
