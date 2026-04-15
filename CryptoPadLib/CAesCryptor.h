#pragma once

#include "../CryptoPad/framework.h"
#include <bcrypt.h>

const size_t k_cAes256KeySizeBytes = 32;
const size_t k_cAesBlockSizeBytes = 16;

class CAes256Cryptor
{
private:
    BCRYPT_ALG_HANDLE m_hAesAlg;
    BCRYPT_KEY_HANDLE m_hAesKey;
    unsigned char* m_rgKeyObject;
    DWORD m_cbKeyObject;
    unsigned char m_rgIv[k_cAesBlockSizeBytes];

private:
    bool InitAesAlgorithm();

public:
    CAes256Cryptor();
    ~CAes256Cryptor();

    static size_t s_GetKeyWidth()
    {
        return k_cAes256KeySizeBytes;
    }

    static bool s_ValidKey(__in_bcount(cbKeyData) const unsigned char* pKeyData, __in size_t cbKeyData)
    {
        return (pKeyData != NULL) && (cbKeyData == s_GetKeyWidth());
    }

    bool SetKeys(__in_bcount(cbKeyData) const unsigned char* pKeyData, __in size_t cbKeyData);
    bool SetIv(__in_bcount(cbIv) const unsigned char* pIv, __in size_t cbIv);
    void Encrypt(__in_bcount(cbData) unsigned char* pData, __in size_t cbData);
    void Decrypt(__in_bcount(cbData) unsigned char* pData, __in size_t cbData);
};

typedef CAes256Cryptor CP_CIPHER;
