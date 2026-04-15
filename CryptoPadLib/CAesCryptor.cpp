#include "../CryptoPad/framework.h"
#include "CAesCryptor.h"

#pragma comment(lib, "bcrypt.lib")

static bool NtSuccess(__in NTSTATUS status)
{
    return status >= 0;
}

CAes256Cryptor::CAes256Cryptor() :
    m_hAesAlg(NULL),
    m_hAesKey(NULL),
    m_rgKeyObject(nullptr),
    m_cbKeyObject(0)
{
    ::memset(m_rgIv, 0, sizeof(m_rgIv));
}

CAes256Cryptor::~CAes256Cryptor()
{
    if (m_hAesKey != NULL)
    {
        (void)::BCryptDestroyKey(m_hAesKey);
        m_hAesKey = NULL;
    }

    if (m_hAesAlg != NULL)
    {
        (void)::BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
        m_hAesAlg = NULL;
    }

    delete[] m_rgKeyObject;
    m_rgKeyObject = nullptr;
    m_cbKeyObject = 0;
    ::SecureZeroMemory(m_rgIv, sizeof(m_rgIv));
}

bool CAes256Cryptor::InitAesAlgorithm()
{
    DWORD cbResult = 0;
    NTSTATUS status = 0;
    WCHAR rgChainMode[] = BCRYPT_CHAIN_MODE_CBC;

    if ((m_hAesAlg != NULL) && (m_rgKeyObject != nullptr) && (m_cbKeyObject != 0))
    {
        return true;
    }

    if (m_hAesAlg != NULL)
    {
        (void)::BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
        m_hAesAlg = NULL;
    }

    delete[] m_rgKeyObject;
    m_rgKeyObject = nullptr;
    m_cbKeyObject = 0;

    status = ::BCryptOpenAlgorithmProvider(&m_hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NtSuccess(status))
    {
        return false;
    }

    status = ::BCryptSetProperty(
        m_hAesAlg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(rgChainMode),
        static_cast<ULONG>(sizeof(rgChainMode)),
        0);
    if (!NtSuccess(status))
    {
        return false;
    }

    status = ::BCryptGetProperty(
        m_hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&m_cbKeyObject),
        sizeof(m_cbKeyObject),
        &cbResult,
        0);
    if (!NtSuccess(status) || (cbResult != sizeof(m_cbKeyObject)) || (m_cbKeyObject == 0))
    {
        return false;
    }

    m_rgKeyObject = new unsigned char[m_cbKeyObject]{ 0 };

    return true;
}

bool CAes256Cryptor::SetKeys(__in_bcount(cbKeyData) const unsigned char* pKeyData, __in size_t cbKeyData)
{
    NTSTATUS status = 0;

    ASSERT(s_ValidKey(pKeyData, cbKeyData));

    if (!InitAesAlgorithm())
    {
        ASSERT(false);
        return false;
    }

    if (m_hAesKey != NULL)
    {
        (void)::BCryptDestroyKey(m_hAesKey);
        m_hAesKey = NULL;
    }

    status = ::BCryptGenerateSymmetricKey(
        m_hAesAlg,
        &m_hAesKey,
        reinterpret_cast<PUCHAR>(m_rgKeyObject),
        m_cbKeyObject,
        const_cast<unsigned char*>(pKeyData),
        static_cast<ULONG>(cbKeyData),
        0);

    ASSERT(NtSuccess(status));
    return NtSuccess(status);
}

bool CAes256Cryptor::SetIv(__in_bcount(cbIv) const unsigned char* pIv, __in size_t cbIv)
{
    ASSERT((pIv != NULL) && (cbIv == k_cAesBlockSizeBytes));

    if ((pIv == NULL) || (cbIv != k_cAesBlockSizeBytes))
    {
        return false;
    }

    ::memcpy(m_rgIv, pIv, cbIv);
    return true;
}

void CAes256Cryptor::Encrypt(__in_bcount(cbData) unsigned char* pData, __in size_t cbData)
{
    DWORD cbOutput = 0;
    NTSTATUS status = 0;

    ASSERT((m_hAesKey != NULL) && (pData != NULL) && ((cbData % k_cAesBlockSizeBytes) == 0));
    if ((m_hAesKey == NULL) || (pData == NULL) || ((cbData % k_cAesBlockSizeBytes) != 0))
    {
        return;
    }

    status = ::BCryptEncrypt(
        m_hAesKey,
        reinterpret_cast<PUCHAR>(pData),
        static_cast<ULONG>(cbData),
        NULL,
        reinterpret_cast<PUCHAR>(m_rgIv),
        static_cast<ULONG>(sizeof(m_rgIv)),
        reinterpret_cast<PUCHAR>(pData),
        static_cast<ULONG>(cbData),
        &cbOutput,
        0);

    ASSERT(NtSuccess(status));
    ASSERT(cbOutput == cbData);
}

void CAes256Cryptor::Decrypt(__in_bcount(cbData) unsigned char* pData, __in size_t cbData)
{
    DWORD cbOutput = 0;
    NTSTATUS status = 0;

    ASSERT((m_hAesKey != NULL) && (pData != NULL) && ((cbData % k_cAesBlockSizeBytes) == 0));
    if ((m_hAesKey == NULL) || (pData == NULL) || ((cbData % k_cAesBlockSizeBytes) != 0))
    {
        return;
    }

    status = ::BCryptDecrypt(
        m_hAesKey,
        reinterpret_cast<PUCHAR>(pData),
        static_cast<ULONG>(cbData),
        NULL,
        reinterpret_cast<PUCHAR>(m_rgIv),
        static_cast<ULONG>(sizeof(m_rgIv)),
        reinterpret_cast<PUCHAR>(pData),
        static_cast<ULONG>(cbData),
        &cbOutput,
        0);

    ASSERT(NtSuccess(status));
    ASSERT(cbOutput == cbData);
}
