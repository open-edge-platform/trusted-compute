/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

// Based on https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_activatecredential.c
static int Tss2ActivateCredential(TSS2_SYS_CONTEXT *sys,
                                  TPMS_AUTH_COMMAND *endorsePassword,
                                  TPMS_AUTH_COMMAND *aikPassword,
                                  TPM2B_ID_OBJECT *credentialBlob,
                                  TPM2B_ENCRYPTED_SECRET *secret,
                                  TPM2B_DIGEST *certInfoData)
{
    TSS2_RC rval;
    TPMI_SH_POLICY sessionHandle = 0;
    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_password = {0};
    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_endorse = {0};
    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceNewer = TPM2B_EMPTY_INIT;
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER salt = {0};

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL};

    nonceNewer.size = TPM2_SHA1_DIGEST_SIZE;
    nonceCaller.size = TPM2_SHA1_DIGEST_SIZE;

    if (aikPassword == NULL)
    {
        ERROR("The aik password cannot be null");
        return -1;
    }

    cmd_auth_array_password.count = 2;
    memcpy(&cmd_auth_array_password.auths[0], aikPassword, sizeof(TPMS_AUTH_COMMAND));

    if (endorsePassword == NULL)
    {
        ERROR("The endorsement password cannot be null");
        return -1;
    }

    cmd_auth_array_endorse.count = 1;
    memcpy(&cmd_auth_array_endorse.auths[0], endorsePassword, sizeof(TPMS_AUTH_COMMAND));

    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &cmd_auth_array_endorse, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }

    cmd_auth_array_password.auths[1].sessionHandle = sessionHandle;
    cmd_auth_array_password.auths[1].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    cmd_auth_array_password.auths[1].hmac.size = 0;

    rval = Tss2_Sys_ActivateCredential(sys, TPM_HANDLE_AIK, TPM_HANDLE_EK, &cmd_auth_array_password, credentialBlob, secret, certInfoData, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_ActivateCredential failed. TPM Error:0x%x", rval);
        return rval;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }

    return TPM2_RC_SUCCESS;
}

int ActivateCredential(const tpmCtx *ctx,
                       const uint8_t *endorsementSecretKey,
                       size_t endorsementSecretKeyLength,
                       const uint8_t *credentialBytes,
                       size_t credentialBytesLength,
                       const uint8_t *secretBytes,
                       size_t secretBytesLength,
                       uint8_t **const decrypted,
                       int *const decryptedLength)
{
    TSS2_RC rval;
    TPMS_AUTH_COMMAND endorsePassword = {0};
    TPMS_AUTH_COMMAND aikPassword = {0};
    TPM2B_ID_OBJECT credentialBlob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);
    TPM2B_ENCRYPTED_SECRET secret = TPM2B_TYPE_INIT(TPM2B_ENCRYPTED_SECRET, secret);
    TPM2B_DIGEST certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    //
    // populate passwords
    //
    endorsePassword.sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&endorsePassword.hmac, endorsementSecretKey, endorsementSecretKeyLength);
    if (rval != 0)
    {
        ERROR("There was an error populating the endorsement secret");
        return -1;
    }

    // The aik password remains empty as it was provisioned with owner permissions
    // during setup (no password is needed).
    aikPassword.sessionHandle = TPM2_RS_PW;

    //
    // copy credentialBytes into the TPM2B_ID_OBJECT
    //
    if (credentialBytes == NULL || credentialBytesLength == 0 || credentialBytesLength > ARRAY_SIZE(credentialBlob.credential))
    {
        ERROR("Invalid size of credential bytes");
        return -1;
    }

    credentialBlob.size = credentialBytesLength;
    memcpy(credentialBlob.credential, credentialBytes, credentialBytesLength);

    //
    // copy secretBytes into the TPM2B_ENCRYPTED_SECRET
    //
    if (secretBytes == NULL || secretBytesLength == 0 || secretBytesLength > ARRAY_SIZE(secret.secret))
    {
        ERROR("Invalid secret bytes");
        return -1;
    }

    secret.size = secretBytesLength;
    memcpy(secret.secret, secretBytes, secretBytesLength);

    //
    // Now call activate credential
    //
    rval = Tss2ActivateCredential(ctx->sys, &endorsePassword, &aikPassword, &credentialBlob, &secret, &certInfoData);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (certInfoData.size == 0 || certInfoData.size > ARRAY_SIZE(certInfoData.buffer))
    {
        ERROR("Incorrect certificate info size");
        return -1;
    }

    // this will be freed by cgo in tpm20linux.go
    *decrypted = (uint8_t *)calloc(certInfoData.size, 1);
    if (!*decrypted)
    {
        ERROR("Could not allocated decrypted buffer");
        return -1;
    }

    memcpy(*decrypted, certInfoData.buffer, certInfoData.size);
    *decryptedLength = certInfoData.size;

    return 0;
}