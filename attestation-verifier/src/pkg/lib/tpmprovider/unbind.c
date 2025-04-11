/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int Unbind(const tpmCtx *ctx,
           const uint8_t *bindingSecretKey,
           size_t bindingSecretKeyLength,
           const uint8_t *publicKeyBytes,
           size_t publicKeyBytesLength,
           const uint8_t *privateKeyBytes,
           size_t privateKeyBytesLength,
           const uint8_t *encryptedBytes,
           size_t encryptedBytesLength,
           uint8_t **decryptedData,
           int *decryptedDataLength)
{
    TSS2_RC rval;
    TPM2_HANDLE bindingKeyHandle = 0;
    TPM2B_PRIVATE inPrivate = {0};
    TPM2B_PUBLIC inPublic = {0};
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};
    TPM2B_NAME name = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND authSession = {0};
    TPM2B_PUBLIC_KEY_RSA cipherText = {0};
    TPMT_RSA_DECRYPT scheme = {0};
    size_t offset = 0;

    TPM2B_DATA label = {
        .size = sizeof("TPM2"),
        .buffer = "TPM2",
    };

    TPM2B_PUBLIC_KEY_RSA message = {
        .size = sizeof(((TPM2B_PUBLIC_KEY_RSA *)0)->buffer)};

    //---------------------------------------------------------------------------------------------
    // Check input parameters
    //---------------------------------------------------------------------------------------------
    if (bindingSecretKey == NULL)
    {
        ERROR("Invalid key secret parameter");
        return -1;
    }

    if (bindingSecretKeyLength == 0 || bindingSecretKeyLength > BUFFER_SIZE(TPM2B_AUTH, buffer))
    {
        ERROR("Invalid key secret length: 0x%lx", bindingSecretKeyLength)
        return -1;
    }

    if (publicKeyBytes == NULL)
    {
        ERROR("Invalid public key bytes parameter");
        return -1;
    }

    if (privateKeyBytes == NULL)
    {
        ERROR("Invalid private key bytes parameter");
        return -1;
    }

    if (encryptedBytes == NULL)
    {
        ERROR("Invalid encrypted bytes parameter");
        return -1;
    }

    if (encryptedBytesLength == 0 || encryptedBytesLength > BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer))
    {
        ERROR("Invalid encrypted bytes length: 0x%lx", encryptedBytesLength);
        return -1;
    }

    if (decryptedData == NULL)
    {
        ERROR("Invalid decrypted data parameter");
        return -1;
    }

    if (decryptedDataLength == NULL)
    {
        ERROR("Invalid decrypted data length parameter");
        return -1;
    }

    *decryptedDataLength = 0;

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_Load
    //---------------------------------------------------------------------------------------------
    offset = 0;
    DEBUG("==> publicKeyBytesLength: 0x%x", publicKeyBytesLength);
    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicKeyBytes, publicKeyBytesLength, &offset, &inPublic);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PUBLIC_Unmarshal returned error code: 0x%x", rval);
        return rval;
    }

    offset = 0;
    DEBUG("==> privateKeyBytesLength: 0x%x", privateKeyBytesLength);
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
                         &bindingKeyHandle,
                         &name,
                         &sessionsDataOut);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Load returned error code: 0x%x", rval);
        return rval;
    }

    DEBUG("==> bindingKeyHandle: 0x%x", bindingKeyHandle)

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_RSA_Decrypt
    //---------------------------------------------------------------------------------------------

    // binding key password
    authSession.count = 1;
    authSession.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&authSession.auths[0].hmac, bindingSecretKey, bindingSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    // encrypted data
    DEBUG("==> encryptedBytesLength: 0x%x", encryptedBytesLength);
    cipherText.size = encryptedBytesLength;
    memcpy(cipherText.buffer, encryptedBytes, encryptedBytesLength);

    scheme.scheme = TPM2_ALG_OAEP;
    scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
    // scheme.scheme = TPM2_ALG_RSASSA;
    // scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    sessionsDataOut.count = 1;

    rval = Tss2_Sys_RSA_Decrypt(ctx->sys,
                                bindingKeyHandle,
                                &authSession,
                                &cipherText,
                                &scheme,
                                &label,
                                &message,
                                &sessionsDataOut);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_RSA_Decrypt returned error code: 0x%x", rval);
        return rval;
    }

    Tss2_Sys_FlushContext(ctx->sys, bindingKeyHandle);

    //---------------------------------------------------------------------------------------------
    // Allocate and copy data for the out parameters (decryptedData).  This will be free'd by go
    //---------------------------------------------------------------------------------------------
    if (message.size == 0 || message.size > BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer))
    {
        ERROR("Invalid message size: 0x%x", message.size)
        return -1;
    }

    *decryptedData = (uint8_t *)calloc(message.size, 1);
    if (!decryptedData)
    {
        ERROR("Could not allocate decrypted buffer");
        return -1;
    }

    memcpy(*decryptedData, message.buffer, message.size);
    *decryptedDataLength = message.size;

    return TSS2_RC_SUCCESS;
}
