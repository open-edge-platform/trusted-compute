/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <openssl/x509.h>

static int GetEkCertificatePublicBytesRSA(const tpmCtx *ctx,
                                          TPM2B_AUTH *ownerAuth,
                                          uint32_t ekCertIndex,
                                          uint8_t **rsaPublicKeyBytes,
                                          int *rsaPublicKeyBytesLength)
{
    TSS2_RC rval = -1;
    uint8_t *nvBytes = NULL;
    int nvLength;
    X509 *ekCert = NULL;
    EVP_PKEY *ekPub = NULL;
    RSA *rsaPub = NULL;
    const BIGNUM *n;
    int len = 0;
    const unsigned char *tmp;

    DEBUG("Getting EK Certificate public key from nv index 0x%x", ekCertIndex)
    rval = NvRead(ctx, (uint8_t *)ownerAuth->buffer, ownerAuth->size, TPM2_RH_OWNER, ekCertIndex, &nvBytes, &nvLength);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Could not read EK Certificate at index 0x%x.  NvRead returned 0x%x", ekCertIndex, rval);
        rval = TPM_PROVIDER_ERROR_NO_EK_CERT; // using this error code will provide a more helpful error message in go
        goto error;
    }

    tmp = (const unsigned char *)nvBytes; // see "Warnings" at https://www.openssl.org/docs/man1.1.0/man3/d2i_X509.html
    ekCert = d2i_X509(NULL, &tmp, nvLength);
    if (ekCert == NULL)
    {
        ERROR("Could not parse the EK Certificate at index 0x%x", ekCertIndex)
        goto error;
    }

    ekPub = X509_get_pubkey(ekCert);
    if (!ekPub)
    {
        ERROR("Failed to retrieve the EK public key from the EK Certificate at index 0x%x", ekCertIndex)
        goto error;
    }

    rsaPub = EVP_PKEY_get1_RSA(ekPub);
    if (!rsaPub)
    {
        ERROR("Failed to retrieve the RSA public key from the EK Certificate at index 0x%x", ekCertIndex)
        goto error;
    }

    RSA_get0_key(rsaPub, &n, NULL, NULL);

    len = BN_num_bytes(n);
    if (len < 20 || len > 4096) // assume between SHA1 (20) and sha512 (4096) bytes
    {
        ERROR("Invalid public key length: 0x%x", len)
        goto error;
    }

    *rsaPublicKeyBytes = calloc(len, sizeof(uint8_t));
    if (*rsaPublicKeyBytes == NULL)
    {
        ERROR("Could not allocate RSA public key bytes")
        goto error;
    }

    BN_bn2bin(n, *rsaPublicKeyBytes);
    *rsaPublicKeyBytesLength = len;
    rval = TSS2_RC_SUCCESS;

error:
    if (nvBytes)
    {
        free(nvBytes);
    }

    if (ekCert)
    {
        X509_free(ekCert);
    }

    if (ekPub)
    {
        EVP_PKEY_free(ekPub);
    }

    if (rsaPub)
    {
        RSA_free(rsaPub);
    }

    return rval;
}

// Load the public data from the EK at 'handle'
// Load EK Certificate from nvram at 'ekCertificateIndex' (der blob)
// Parse the der and get the public key
// Compare the der's public key against the EK's public.unique
int IsValidEk(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLength,
              uint32_t handle,
              uint32_t ekCertificateIndex)
{
    TSS2_RC rval;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    uint8_t *ekCertPublicKeyBytes = NULL;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_AUTH ownerAuth = {0};
    int ekCertPublicKeyBytesLength;
    int len;

    DEBUG("Validating EK template at handle 0x%x against the EK Certificate at nv index 0x%x", handle, ekCertificateIndex);

    rval = InitializeTpmAuth(&ownerAuth, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        goto error;
    }

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, NULL, &public, &name, &qualifiedName, &sessionsData);
    if (rval != TSS2_RC_SUCCESS)
    {
        goto error;
    }

    rval = GetEkCertificatePublicBytesRSA(ctx, &ownerAuth, ekCertificateIndex, &ekCertPublicKeyBytes, &ekCertPublicKeyBytesLength);
    if (rval != TSS2_RC_SUCCESS)
    {
        goto error;
    }

    if (ekCertPublicKeyBytesLength != public.publicArea.unique.rsa.size)
    {
        ERROR("The size of the EK Certificate's public key (0x%x) does not match what was created (0x%x)", ekCertPublicKeyBytesLength, public.publicArea.unique.rsa.size);
        rval = TPM_PROVIDER_EK_PUBLIC_MISMATCH;
        goto error;
    }

    if (timingsafe_memcmp(ekCertPublicKeyBytes, public.publicArea.unique.rsa.buffer, ekCertPublicKeyBytesLength) != 0)
    {
        ERROR("The new EK's public key did not match the EK Certificate's");
        rval = TPM_PROVIDER_EK_PUBLIC_MISMATCH;
        goto error;
    }

    DEBUG("The generated EK's public key successfully matches the EK Certificate's")
    rval = TSS2_RC_SUCCESS;

error:
    if (ekCertPublicKeyBytes)
    {
        free(ekCertPublicKeyBytes);
    }

    return rval;
}
