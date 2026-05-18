/**
 * crypto/uav-openssl-ctx.cc
 */

#include "uav-openssl-ctx.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>

void OpenSSLInit::Bootstrap()
{
    static bool done = false;

    if (done)
    {
        return;
    }

    OSSL_PROVIDER* deflt =
        OSSL_PROVIDER_load(nullptr, "default");

    if (!deflt)
    {
        ERR_print_errors_fp(stderr);
    }

    done = true;
}

void OpenSSLInit::Cleanup()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
#endif
}