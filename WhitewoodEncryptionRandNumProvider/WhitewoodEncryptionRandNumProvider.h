// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the WHITEWOODENCRYPTIONRANDNUMPROVIDER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// WHITEWOODENCRYPTIONRANDNUMPROVIDER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef WHITEWOODENCRYPTIONRANDNUMPROVIDER_EXPORTS
#define WHITEWOODENCRYPTIONRANDNUMPROVIDER_API __declspec(dllexport)
#else
#define WHITEWOODENCRYPTIONRANDNUMPROVIDER_API __declspec(dllimport)
#endif

/* This class is exported from the WhitewoodEncryptionRandNumProvider.dll
class WHITEWOODENCRYPTIONRANDNUMPROVIDER_API CWhitewoodEncryptionRandNumProvider {
public:
	CWhitewoodEncryptionRandNumProvider(void);
	// TODO: add your methods here.
};
*/
extern WHITEWOODENCRYPTIONRANDNUMPROVIDER_API int nWhitewoodEncryptionRandNumProvider;

WHITEWOODENCRYPTIONRANDNUMPROVIDER_API int fnWhitewoodEncryptionRandNumProvider(void);
