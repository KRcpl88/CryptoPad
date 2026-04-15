#pragma once

#include "../CryptoPad/framework.h"
#include "CAesCryptor.h"

const size_t k_cNonceSizeBytes = k_cAesBlockSizeBytes;

char ctoh(char c);
unsigned long atoh(__in_z const char* pszText);
void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin);
void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin);
bool GenNonce(__out_bcount(k_cNonceSizeBytes) BYTE* pNonce, __in_z_opt char* pszHashKey = nullptr);
bool ApplyNonce(__in_bcount(k_cNonceSizeBytes) BYTE* pNonce, __in_bcount(cKey) const unsigned char* pKey, __in size_t cKey, __inout CP_CIPHER* pCryptor);
void FbcProcessFile(__in HANDLE hFileIn, __in HANDLE hFileOut, __in ULONGLONG cbFileSize, __inout CP_CIPHER* pCryptor, __in EFileCryptProcess eFileCryptProcess);
void FbcEncryptFile(__in_z LPCWSTR pwszPlaintext, __in_z LPCWSTR pwszCiphertext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey);
void FbcDecryptFile(__in_z LPCWSTR pwszCiphertext, __in_z LPCWSTR pwszPlaintext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey);
void ParsePasswordW(__in_z LPCWSTR pwszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
void ParsePasswordA(__in_z LPCSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin);
