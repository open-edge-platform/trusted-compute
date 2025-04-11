/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int Sign(const tpmCtx *ctx,
         const uint8_t *signingSecretKey,
         size_t signingSecretKeyLength,
         const uint8_t *publicKeyBytes,
         size_t publicKeyBytesLength,
         const uint8_t *privateKeyBytes,
         size_t privateKeyBytesLength,
         const uint8_t *hashBytes,
         size_t hashBytesLength,
         uint8_t **const signatureBytes,
         int *const signatureBytesLength)
{
    TPM2_RC rval;
    TPM2_HANDLE signingKeyHandle = 0;
    TPM2B_PRIVATE inPrivate = {0};
    TPM2B_PUBLIC inPublic = {0};
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND authCommand = {0};
    TPM2B_DIGEST hash = {0};
    TPMT_SIG_SCHEME scheme = {0};
    TPMT_SIGNATURE signature = {0};
    size_t offset = 0;
    TPM2B_NAME name = {0};

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
    };

    //---------------------------------------------------------------------------------------------
    // Check input parameters
    //---------------------------------------------------------------------------------------------
    if (signingSecretKey == NULL)
    {
        ERROR("The key secret must be provided");
        return -1;
    }

    if (signingSecretKeyLength == 0 || signingSecretKeyLength > BUFFER_SIZE(TPM2B_AUTH, buffer))
    {
        ERROR("Invalid key secret length: 0x%lx", signingSecretKeyLength);
        return -1;
    }

    if (publicKeyBytes == NULL)
    {
        ERROR("The public key bytes must be provided");
        return -1;
    }

    if (privateKeyBytes == NULL)
    {
        ERROR("The private key bytes must be provided");
        return -1;
    }

    if (hashBytes == NULL)
    {
        ERROR("The hash bytes must be provided");
        return -1;
    }

    if (hashBytesLength == 0 || hashBytesLength > ARRAY_SIZE(hash.buffer))
    {
        ERROR("Invalid hash bytes length: 0x%lx", hashBytesLength);
        return -1;
    }

    if (signatureBytes == NULL)
    {
        ERROR("The signature bytes must be provided");
        return -1;
    }

    if (signatureBytesLength == NULL)
    {
        ERROR("The signature bytes length cannot be null");
        return -1;
    }

    *signatureBytesLength = 0;

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_Load
    //---------------------------------------------------------------------------------------------
    offset = 0;
    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicKeyBytes, publicKeyBytesLength, &offset, &inPublic);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PUBLIC_Unmarshal returned error code: 0x%x", rval);
        return rval;
    }

    offset = 0;
    rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privateKeyBytes, privateKeyBytesLength, &offset, &inPrivate);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PRIVATE_Unmarshal returned error code: 0x%x", rval);
        return rval;
    }

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;

    name.size = sizeof(name) - 2;

    rval = Tss2_Sys_Load(ctx->sys,
                         TPM_HANDLE_PRIMARY,
                         &sessionData,
                         &inPrivate,
                         &inPublic,
                         &signingKeyHandle,
                         &name,
                         NULL);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Load returned error code: 0x%x", rval);
        return rval;
    }

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_Sign
    //---------------------------------------------------------------------------------------------
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    hash.size = TPM2_SHA256_DIGEST_SIZE;
    memcpy(hash.buffer, hashBytes, hashBytesLength);

    // key password
    authCommand.count = 1;
    authCommand.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&authCommand.auths[0].hmac, signingSecretKey, signingSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    rval = Tss2_Sys_Sign(ctx->sys,
                         signingKeyHandle,
                         &authCommand,
                         &hash,
                         &scheme,
                         &validation,
                         &signature,
                         NULL);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Sign returned error code: 0x%x", rval);
        return rval;
    }

    Tss2_Sys_FlushContext(ctx->sys, signingKeyHandle);

    //---------------------------------------------------------------------------------------------
    // Allocate and copy data for the out parameters (signatureBytes).  This will be free'd by go
    //---------------------------------------------------------------------------------------------
    if (signature.signature.rsassa.sig.size == 0 || signature.signature.rsassa.sig.size > ARRAY_SIZE(signature.signature.rsassa.sig.buffer))
    {
        ERROR("Invalid signature bytes size: 0x%x", signature.signature.rsassa.sig.size);
        return -1;
    }

    *signatureBytes = (uint8_t *)calloc(signature.signature.rsassa.sig.size, 1);
    if (!signatureBytes)
    {
        ERROR("Could not allocate signature buffer");
        return -1;
    }

    memcpy(*signatureBytes, signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size);
    *signatureBytesLength = signature.signature.rsassa.sig.size;

    return TSS2_RC_SUCCESS;
}
