#include <strsafe.h>

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
************
*******************************************************************/
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
