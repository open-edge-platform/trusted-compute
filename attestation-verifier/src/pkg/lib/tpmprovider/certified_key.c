/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int CreateCertifiedKey(const tpmCtx *ctx,
                       CertifiedKey *keyOut,
                       TPM_CERTIFIED_KEY_USAGE keyUsage,
                       const uint8_t *ownerSecretKey,
                       size_t ownerSecretKeyLength)
{
    TSS2_RC rval;
    TPM2B_AUTH ownerAuth = {0};
    TPM2B_PUBLIC outPublic = {0};
    TPM2B_PRIVATE outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);
    TPMT_SIGNATURE signature = {0};
    TPM2_HANDLE loadedHandle = 0;
    TPM2B_NAME name = {0};
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};
    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION creationPcr = {0};
    TPM2B_CREATION_DATA creationData = {0};
    TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPMT_SIG_SCHEME inScheme = {0};
    TSS2L_SYS_AUTH_COMMAND authCommand = {0};
    size_t written = 0;

    TPM2B_DATA qualifyingData = {
        .size = 4,
        .buffer = {0x00, 0xff, 0x55, 0xaa}};

    TPM2B_ATTEST certifyInfo = {
        .size = sizeof(certifyInfo) - 2};

    //---------------------------------------------------------------------------------------------
    // Check parameters
    //---------------------------------------------------------------------------------------------
    if (!keyOut)
    {
        ERROR("The certified key was not provided");
        return -1;
    }

    if (ownerSecretKey == NULL)
    {
        ERROR("The owner secret key must be provided");
        return -1;
    }

    if (ownerSecretKeyLength == 0 || ownerSecretKeyLength > BUFFER_SIZE(TPM2B_AUTH, buffer))
    {
        ERROR("The owner secret key length is incorrect: 0x%lx", ownerSecretKeyLength);
        return -1;
    }

    //---------------------------------------------------------------------------------------------
    // Return an error if the public key at handle 0x81000000 (TPM_HANDLE_PRIMARY) has not been
    // made.  It should have been created by WLA setup before calling this function.
    //---------------------------------------------------------------------------------------------
    rval = PublicKeyExists(ctx, TPM_HANDLE_PRIMARY);
    if (rval == -1)
    {
        ERROR("The public key at 0x%x does not exists", TPM_HANDLE_PRIMARY);
        return -1;
    }

    //---------------------------------------------------------------------------------------------
    // Setup variables and call Tss2_Sys_Create
    //---------------------------------------------------------------------------------------------
    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;

    rval = InitializeTpmAuth(&inSensitive.sensitive.userAuth, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.objectAttributes = 0;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;

    if (keyUsage == TPM_CERTIFIED_KEY_USAGE_BINDING)
    {
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    }
    else if (keyUsage == TPM_CERTIFIED_KEY_USAGE_SIGNING)
    {
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    else
    {
        ERROR("Invalid key usage: %d", keyUsage);
        return -1;
    }

    rval = Tss2_Sys_Create(ctx->sys,
                           TPM_HANDLE_PRIMARY,
                           &sessionData,
                           &inSensitive,
                           &inPublic,
                           &outsideInfo,
                           &creationPcr,
                           &outPrivate,
                           &outPublic,
                           &creationData,
                           &creationHash,
                           &creationTicket,
                           &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Create returned error: 0x%x", rval);
        return rval;
    }

    //---------------------------------------------------------------------------------------------
    // Setup variables and call Tss2_Sys_Load
    //---------------------------------------------------------------------------------------------
    rval = Tss2_Sys_Load(ctx->sys,
                         TPM_HANDLE_PRIMARY,
                         &sessionData,
                         &outPrivate,
                         &outPublic,
                         &loadedHandle,
                         &name,
                         &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_Load returned error: 0x%x", rval);
        return rval;
    }

    //---------------------------------------------------------------------------------------------
    // Setup variables and call Tss2_Sys_Certify
    //---------------------------------------------------------------------------------------------
    authCommand.count = 2;
    authCommand.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&authCommand.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    // assume the aik password is empty as performed by trust-agent provisioning
    authCommand.auths[1].sessionHandle = TPM2_RS_PW;

    inScheme.scheme = TPM2_ALG_RSASSA;
    inScheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    rval = Tss2_Sys_Certify(ctx->sys,
                            loadedHandle,
                            TPM_HANDLE_AIK,
                            &authCommand,
                            &qualifyingData,
                            &inScheme,
                            &certifyInfo,
                            &signature,
                            &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Certify returned error: 0x%x", rval);
        return rval;
    }

    //---------------------------------------------------------------------------------------------
    // Allocate buffers for the CertifiedKey to return
    //---------------------------------------------------------------------------------------------
    keyOut->publicKey.buffer = (unsigned char *)calloc(sizeof(TPM2B_PUBLIC), 1);
    keyOut->privateBlob.buffer = (unsigned char *)calloc(sizeof(TPM2B_PRIVATE), 1);
    keyOut->keySignature.buffer = (unsigned char *)calloc(sizeof(TPMT_SIGNATURE), 1);
    keyOut->keyAttestation.buffer = (unsigned char *)calloc(sizeof(TPM2B_ATTEST), 1);
    keyOut->keyName.buffer = (unsigned char *)calloc(sizeof(TPM2B_NAME), 1);

    if (!keyOut->publicKey.buffer || !keyOut->privateBlob.buffer || !keyOut->keySignature.buffer ||
        !keyOut->keyAttestation.buffer)
    {
        ERROR("Could not allocate certified key buffers")
        goto error;
    }

    //---------------------------------------------------------------------------------------------
    // copy results to buffers
    //---------------------------------------------------------------------------------------------
    written = 0;
    Tss2_MU_TPM2B_PUBLIC_Marshal(&outPublic, keyOut->publicKey.buffer, sizeof(TPM2B_PUBLIC), &written);
    keyOut->publicKey.size = written;
    written = 0;

    Tss2_MU_TPM2B_PRIVATE_Marshal(&outPrivate, keyOut->privateBlob.buffer, sizeof(TPM2B_PRIVATE), &written);
    keyOut->privateBlob.size = written;
    written = 0;

    Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, keyOut->keySignature.buffer, sizeof(TPMT_SIGNATURE), &written);
    keyOut->keySignature.size = written;
    written = 0;

    Tss2_MU_TPM2B_ATTEST_Marshal(&certifyInfo, keyOut->keyAttestation.buffer, sizeof(TPM2B_ATTEST), &written);
    keyOut->keyAttestation.size = written;
    written = 0;

    Tss2_MU_TPM2B_NAME_Marshal(&name, keyOut->keyName.buffer, sizeof(TPM2B_NAME), &written);
    keyOut->keyName.size = written;

    rval = TSS2_RC_SUCCESS;
    goto exit;

error:

    if (keyOut->publicKey.buffer)
    {
        free(keyOut->publicKey.buffer);
    }

    if (keyOut->privateBlob.buffer)
    {
        free(keyOut->privateBlob.buffer);
    }

    if (keyOut->keySignature.buffer)
    {
        free(keyOut->keySignature.buffer);
    }

    if (keyOut->keyAttestation.buffer)
    {
        free(keyOut->keyAttestation.buffer);
    }

    rval = -1;

exit:

    Tss2_Sys_FlushContext(ctx->sys, loadedHandle);
    return rval;
}
