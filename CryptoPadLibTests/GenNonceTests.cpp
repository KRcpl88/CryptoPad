#include "CppUnitTest.h"
#include "../CryptoPadLib/CryptoPadUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPadLibTests
{
    extern const LPCSTR g_pszTestPassword = "P@s$w0rd!";

	TEST_CLASS(GenNonceTests)
	{
	public:
		
        TEST_METHOD(TestGenNonceOutputNotAllZeros)
        {
            BYTE rgNonce[k_cNonceSizeBytes] = { 0 };

            bool fOK = ::GenNonce(rgNonce);
            Assert::IsTrue(fOK, L"GenNonce should succeed");

            bool fAllZero = true;
            for (size_t i = 0; i < k_cNonceSizeBytes; i++)
            {
                if (rgNonce[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            Assert::IsFalse(fAllZero, L"GenNonce should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceTwoCallsProduceDifferentResults)
        {
            BYTE rgNonce1[k_cNonceSizeBytes] = { 0 };
            BYTE rgNonce2[k_cNonceSizeBytes] = { 0 };

            bool fOK1 = ::GenNonce(rgNonce1);
            bool fOK2 = ::GenNonce(rgNonce2);
            Assert::IsTrue(fOK1 && fOK2, L"GenNonce should succeed");

            bool fNoncesAreEqual = (::memcmp(rgNonce1, rgNonce2, k_cNonceSizeBytes) == 0);
            Assert::IsFalse(fNoncesAreEqual, L"Two consecutive calls to GenNonce should produce different results");
        }

        TEST_METHOD(TestGenNonceWithCustomHashKey)
        {
            BYTE rgNonce[k_cNonceSizeBytes] = { 0 };
            char rgCustomKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            bool fOK = ::GenNonce(rgNonce, rgCustomKey);
            Assert::IsTrue(fOK, L"GenNonce should succeed with custom hash key");

            bool fAllZero = true;
            for (size_t i = 0; i < k_cNonceSizeBytes; i++)
            {
                if (rgNonce[i] != 0)
                {
                    fAllZero = false;
                    break;
                }
            }
            Assert::IsFalse(fAllZero, L"GenNonce with custom hash key should produce non-zero output");
        }

        TEST_METHOD(TestGenNonceDefaultAndCustomHashKeyProduceDifferentResults)
        {
            BYTE rgNonce1[k_cNonceSizeBytes] = { 0 };
            BYTE rgNonce2[k_cNonceSizeBytes] = { 0 };
            char rgCustomKey[] = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";

            bool fOK1 = ::GenNonce(rgNonce1);
            bool fOK2 = ::GenNonce(rgNonce2, rgCustomKey);
            Assert::IsTrue(fOK1 && fOK2, L"GenNonce should succeed for default and custom hash keys");

            bool fNoncesAreEqual = (::memcmp(rgNonce1, rgNonce2, k_cNonceSizeBytes) == 0);
            Assert::IsFalse(fNoncesAreEqual, L"GenNonce with default and custom hash key should produce different results");
        }

	};
}
