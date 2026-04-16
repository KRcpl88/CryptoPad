#include "../CryptoPad/framework.h"
#include "CryptoPadUtils.h"


char ctoh(char c)
{
    if (('0' <= c) && ('9' >= c))
    {
        return c - '0';
    }
    else if (('a' <= c) && ('z' >= c))
    {
        return 10 + c - 'a';
    }
    else if (('A' <= c) && ('Z' >= c))
    {
        return 10 + c - 'A';
    }

    return 0;
}

unsigned long atoh(__in_z const char* pszText)
{
    unsigned long dwResult = 0;
    while (*pszText >= '0')
    {
        dwResult = (dwResult << 4) + ctoh(*pszText);
        ++pszText;
    }

    return dwResult;
}

void HexToBin(__inout_z char* pszHex, __in size_t cchBin, __out_ecount(cchBin) unsigned char* pBin)
{
    char* pszTemp = nullptr;
    size_t i = cchBin - 1;

    // start at the end
    pszTemp = pszHex + strlen(pszHex) - 2;
    while ((pszTemp > pszHex) && (i < cchBin))
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszTemp));
        *pszTemp = 0;
        pszTemp -= 2;
        --i;
    }

    // convert the last char, this may be a partial value (one nybble instead of two)
    if (i < cchBin)
    {
        pBin[i] = static_cast<unsigned char>(atoh(pszHex));
        while ((--i) < cchBin)
        {
            pBin[i] = 0;
        }
    }
}

void HexToBin(__inout_z char* pszHex, __in size_t nAlign, __out size_t* pcchBin, __out unsigned char** ppBin)
{
    *pcchBin = strlen(pszHex) / 2;
    if ((((*pcchBin) / nAlign) * nAlign) < (*pcchBin))
    {
        *pcchBin = (1 + ((*pcchBin) / nAlign)) * nAlign;
    }

    *ppBin = new unsigned char[*pcchBin];

    HexToBin(pszHex, *pcchBin, *ppBin);
}

static bool ComputeHash(
    __in_z LPCWSTR pwszAlgorithm,
    __in_bcount(cbData1) const unsigned char* pData1,
    __in DWORD cbData1,
    __in_bcount_opt(cbData2) const unsigned char* pData2,
    __in DWORD cbData2,
    __out_bcount(cbHash) unsigned char* pHash,
    __in DWORD cbHash)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbResult = 0;
    unsigned char* pHashObject = nullptr;
    NTSTATUS status = 0;
    bool fSuccess = false;

    status = ::BCryptOpenAlgorithmProvider(&hAlg, pwszAlgorithm, NULL, 0);
    if (status < 0)
    {
        goto Error;
    }

    status = ::BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&cbHashObject),
        sizeof(cbHashObject),
        &cbResult,
        0);
    if ((status < 0) || (cbResult != sizeof(cbHashObject)))
    {
        goto Error;
    }

    pHashObject = new unsigned char[cbHashObject];
    ::memset(pHashObject, 0, cbHashObject);

    status = ::BCryptCreateHash(hAlg, &hHash, pHashObject, cbHashObject, NULL, 0, 0);
    if (status < 0)
    {
        goto Error;
    }

    status = ::BCryptHashData(hHash, const_cast<unsigned char*>(pData1), cbData1, 0);
    if (status < 0)
    {
        goto Error;
    }

    if ((pData2 != NULL) && (cbData2 > 0))
    {
        status = ::BCryptHashData(hHash, const_cast<unsigned char*>(pData2), cbData2, 0);
        if (status < 0)
        {
            goto Error;
        }
    }

    status = ::BCryptFinishHash(hHash, reinterpret_cast<PUCHAR>(pHash), cbHash, 0);
    if (status < 0)
    {
        goto Error;
    }

    fSuccess = true;

Error:
    if (hHash != NULL)
    {
        (void)::BCryptDestroyHash(hHash);
    }

    if (hAlg != NULL)
    {
        (void)::BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    delete[] pHashObject;
    return fSuccess;
}

bool GenNonce(__out_bcount(k_cNonceSizeBytes) BYTE* pNonce, __in_z_opt char* pszHashKey)
{
    char szDefaultHashKey[] = "3BCC8CBF2103DDC295E70BCC305C6BB232479DD2792204A2CA83CE3BEFF9EA43";
    BYTE rgSeed[32] = { 0 };
    BYTE rgDigest[32] = { 0 };
    unsigned char* pHashKey = nullptr;
    size_t cbHashKey = 0;
    bool fHashed = false;

    ASSERT(pNonce != NULL);
    if (pNonce == NULL)
    {
        return false;
    }

    if (::BCryptGenRandom(NULL, rgSeed, ARRAYSIZE(rgSeed), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        return false;
    }

    if (pszHashKey == nullptr)
    {
        ::HexToBin(szDefaultHashKey, 1, &cbHashKey, &pHashKey);
    }
    else
    {
        ::HexToBin(pszHashKey, 1, &cbHashKey, &pHashKey);
    }

    fHashed = ::ComputeHash(BCRYPT_SHA256_ALGORITHM, rgSeed, ARRAYSIZE(rgSeed), pHashKey, static_cast<DWORD>(cbHashKey), rgDigest, ARRAYSIZE(rgDigest));
    if (!fHashed)
    {
        delete[] pHashKey;
        return false;
    }

    ::memcpy(pNonce, rgDigest, k_cNonceSizeBytes);

    delete[] pHashKey;
    return true;
}

// Apply Nonce will set keys on pCryptor
bool ApplyNonce(__in_bcount(k_cNonceSizeBytes) BYTE* pNonce, __in_bcount(cKey) const unsigned char* pKey, __in size_t cKey, __inout CP_CIPHER* pCryptor)
{
    BYTE rgDerived[64] = { 0 };
    BYTE rgSessionKey[k_cAes256KeySizeBytes] = { 0 };
    BYTE rgIv[k_cAesBlockSizeBytes] = { 0 };

    ASSERT((pNonce != NULL) && (pKey != NULL) && (pCryptor != NULL));
    ASSERT(cKey == pCryptor->s_GetKeyWidth());

    if ((pNonce == NULL) || (pKey == NULL) || (pCryptor == NULL) || (cKey != pCryptor->s_GetKeyWidth()))
    {
        return false;
    }

    if (!::ComputeHash(BCRYPT_SHA512_ALGORITHM, pKey, static_cast<DWORD>(cKey), pNonce, k_cNonceSizeBytes, rgDerived, ARRAYSIZE(rgDerived)))
    {
        return false;
    }

    ::memcpy(rgSessionKey, rgDerived, ARRAYSIZE(rgSessionKey));
    ::memcpy(rgIv, rgDerived + ARRAYSIZE(rgSessionKey), ARRAYSIZE(rgIv));

    if (!pCryptor->SetKeys(rgSessionKey, ARRAYSIZE(rgSessionKey)))
    {
        return false;
    }

    if (!pCryptor->SetIv(rgIv, ARRAYSIZE(rgIv)))
    {
        return false;
    }

    return true;
}

void FbcProcessFile(__in HANDLE hFileIn, __in HANDLE hFileOut, __in ULONGLONG cbFileSize, __inout CP_CIPHER* pCryptor, __in EFileCryptProcess eFileCryptProcess)
{
    unsigned char rgBuf[0x20000] = { 0 };
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    DWORD cbBytesToWrite = 0;
    DWORD cbBlockAlignedBytesRead = 0;
    ULONGLONG ullTotalBytes = 0;

    C_ASSERT((sizeof(rgBuf) % k_cAesBlockSizeBytes) == 0);

    do
    {
        ::ReadFile(hFileIn, rgBuf, sizeof(rgBuf), &dwBytesRead, NULL);

        if (0 < dwBytesRead)
        {
            cbBlockAlignedBytesRead = (((dwBytesRead - 1) / k_cAesBlockSizeBytes) + 1) * k_cAesBlockSizeBytes;

            ASSERT(cbBlockAlignedBytesRead <= sizeof(rgBuf));

            switch (eFileCryptProcess)
            {
            case EFCP_Encrypt:
                pCryptor->Encrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = cbBlockAlignedBytesRead;
                break;
            case EFCP_Decrypt:
                pCryptor->Decrypt(rgBuf, cbBlockAlignedBytesRead);
                cbBytesToWrite = static_cast<DWORD>(min(static_cast<ULONGLONG>(dwBytesRead), cbFileSize - ullTotalBytes));
                break;
            }

            ::WriteFile(hFileOut, rgBuf, cbBytesToWrite, &dwBytesWritten, NULL);
            if (cbBytesToWrite != dwBytesWritten)
            {
                ::MessageBoxW(nullptr, L"Could not write file", L"Write Failed", MB_OK | MB_ICONERROR);
                return;
            }

            ullTotalBytes += dwBytesWritten;
        }
    } while (dwBytesRead == sizeof(rgBuf));
}

void FbcEncryptFile(__in_z LPCWSTR pwszPlaintext, __in_z LPCWSTR pwszCiphertext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey)
{
    CP_CIPHER* pCipher = new CP_CIPHER();
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    unsigned char* pNonce = NULL;
    DWORD dwBytes = 0;
    DWORD cbFileSize = 0;
    LARGE_INTEGER llFileSize = { 0 };

    // open input and output files
    hFileIn = ::CreateFileW(pwszPlaintext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    fOK = ::GetFileSizeEx(hFileIn, reinterpret_cast<LARGE_INTEGER*>(&llFileSize));
    if ((!fOK))
    {
        goto Error;
    }

    cbFileSize = llFileSize.LowPart;

    hFileOut = ::CreateFileW(pwszCiphertext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileOut)
    {
        goto Error;
    }

    pNonce = new unsigned char[k_cNonceSizeBytes];
    if (!::GenNonce(pNonce))
    {
        goto Error;
    }

    fOK = ::WriteFile(hFileOut, pNonce, static_cast<DWORD>(k_cNonceSizeBytes * sizeof(*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (k_cNonceSizeBytes * sizeof(*pNonce))))
    {
        goto Error;
    }

    fOK = ::WriteFile(hFileOut, &cbFileSize, static_cast<DWORD>(sizeof(cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof(cbFileSize)))
    {
        goto Error;
    }

    if (!::ApplyNonce(pNonce, pKey, cbKey, pCipher))
    {
        goto Error;
    }

    ::FbcProcessFile(hFileIn, hFileOut, cbFileSize, pCipher, EFCP_Encrypt);

    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not encrypt file", L"Encrypt Failed", MB_OK | MB_ICONERROR);

Done:
    delete pCipher;
    delete[] pNonce;
    ::CloseHandle(hFileIn);
    ::CloseHandle(hFileOut);
}

void FbcDecryptFile(__in_z LPCWSTR pwszCiphertext, __in_z LPCWSTR pwszPlaintext, __in_bcount(cbKey) const unsigned char* pKey, __in size_t cbKey)
{
    CP_CIPHER* pCipher = new CP_CIPHER();
    HANDLE hFileIn = NULL;
    HANDLE hFileOut = NULL;
    BOOL fOK = FALSE;
    unsigned char* pNonce = NULL;
    DWORD dwBytes = 0;
    DWORD cbFileSize = 0;

    // open input and output files
    hFileIn = ::CreateFileW(pwszCiphertext, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileIn)
    {
        goto Error;
    }

    hFileOut = ::CreateFileW(pwszPlaintext, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFileOut)
    {
        goto Error;
    }

    // read nonce from input file
    pNonce = new unsigned char[k_cNonceSizeBytes];

    fOK = ::ReadFile(hFileIn, pNonce, static_cast<DWORD>(k_cNonceSizeBytes * sizeof(*pNonce)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != (k_cNonceSizeBytes * sizeof(*pNonce))))
    {
        goto Error;
    }

    fOK = ::ReadFile(hFileIn, &cbFileSize, static_cast<DWORD>(sizeof(cbFileSize)), &dwBytes, NULL);
    if ((!fOK) || (dwBytes != sizeof(cbFileSize)))
    {
        goto Error;
    }

    if (!::ApplyNonce(pNonce, pKey, cbKey, pCipher))
    {
        goto Error;
    }

    ::FbcProcessFile(hFileIn, hFileOut, cbFileSize, pCipher, EFCP_Decrypt);
    goto Done;

Error:
    ::MessageBoxW(nullptr, L"Could not decrypt file", L"Decrypt Failed", MB_OK | MB_ICONERROR);

Done:
    delete pCipher;
    delete[] pNonce;
    ::CloseHandle(hFileIn);
    ::CloseHandle(hFileOut);
}

void ParsePasswordW(__in_z LPCWSTR pwszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    LPCWSTR pwszTemp = nullptr;

    *ppBin = new unsigned char[cbBin];
    ::memset(*ppBin, 0, cbBin);

    pwszTemp = pwszPassword;

    while (fFirstPass || ((*pwszTemp) && fPasswordIncomplete))
    {
        if ((*pwszTemp) == 0)
        {
            pwszTemp = pwszPassword;
        }

        *(reinterpret_cast<WCHAR*>(*ppBin + i)) += *pwszTemp;
        ++pwszTemp;

        if ((*pwszTemp) == 0)
        {
            fPasswordIncomplete = false;
        }

        i += sizeof(*pwszTemp);
        if (i >= cbBin)
        {
            fFirstPass = false;
            i = 0;
        }
    }
}

void ParsePasswordA(__in_z LPCSTR pszPassword, __in size_t cbBin, __out_bcount(cbBin) unsigned char** ppBin)
{
    size_t i = 0;
    bool fFirstPass = true;
    bool fPasswordIncomplete = true;
    LPCSTR pszTemp = nullptr;

    *ppBin = new unsigned char[cbBin];
    ::memset(*ppBin, 0, cbBin);

    pszTemp = pszPassword;

    while (fFirstPass || ((*pszTemp) && fPasswordIncomplete))
    {
        if ((*pszTemp) == 0)
        {
            pszTemp = pszPassword;
        }

        *(*ppBin + i) += static_cast<unsigned char>(*pszTemp);
        ++pszTemp;

        if ((*pszTemp) == 0)
        {
            fPasswordIncomplete = false;
        }

        i += sizeof(*pszTemp);
        if (i >= cbBin)
        {
            fFirstPass = false;
            i = 0;
        }
    }
}
