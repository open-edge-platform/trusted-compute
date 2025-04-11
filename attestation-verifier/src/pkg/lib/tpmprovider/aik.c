/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

//-------------------------------------------------------------------------------------------------
// G E T   P U B   A K
// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_getpubak.c
//-------------------------------------------------------------------------------------------------
static int getpubak(TSS2_SYS_CONTEXT *sys,
                    TPM2B_AUTH *ownerSecretKey,
                    TPM2B_AUTH *endorsementSecretKey,
                    TPM2B_AUTH *aikSecretKey)
{
    TSS2_RC rval;
    TPML_PCR_SELECTION creation_pcr;
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
    TPM2B_NONCE nonce_caller = TPM2B_EMPTY_INIT;
    TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encrypted_salt = TPM2B_EMPTY_INIT;
    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);
    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMI_SH_POLICY sessionHandle = 0;

    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {{
                                                   .sessionHandle = TPM2_RS_PW,
                                                   .nonce = TPM2B_EMPTY_INIT,
                                                   .hmac = TPM2B_EMPTY_INIT,
                                                   .sessionAttributes = 0,
                                               }}};

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    creation_pcr.count = 0;

    if (ownerSecretKey == NULL)
    {
        ERROR("The owner secret key cannot be null");
        return -1;
    }

    if (endorsementSecretKey == NULL)
    {
        ERROR("The endorsement secret key cannot be null");
        return -1;
    }

    if (aikSecretKey == NULL)
    {
        ERROR("The aik secret key cannot be null");
        return -1;
    }

    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
    memcpy(&inSensitive.sensitive.userAuth, aikSecretKey, sizeof(TPM2B_AUTH));
    memcpy(&sessions_data.auths[0].hmac, endorsementSecretKey, sizeof(TPM2B_AUTH));

    { // from set_key_algorithm
        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.type = TPM2_ALG_RSA; // -g arg (0x01)
        inPublic.publicArea.objectAttributes = 0;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
        inPublic.publicArea.authPolicy.size = 0;
        inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.publicArea.unique.rsa.size = 0;
        inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;                 // -s argument (0x14)
        inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = TPM2_ALG_SHA256; // -D argument (0x0b)
    }

    //---------------------------------------------------------------------------------------------
    // Setup the first session
    // TODO: this code is duplicated in activate_credential and should be moved to a util function
    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceNewer = TPM2B_EMPTY_INIT;
    nonceNewer.size = TPM2_SHA1_DIGEST_SIZE; // ???
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    nonceCaller.size = TPM2_SHA1_DIGEST_SIZE; // ???
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER salt = {0};

    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }
    // ---------------------------------------------------------------------------------------------

    sessions_data.auths[0].sessionHandle = sessionHandle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    rval = Tss2_Sys_Create(sys, TPM_HANDLE_EK, &sessions_data,
                           &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
                           &out_public, &creation_data, &creation_hash, &creation_ticket,
                           &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Create Error. TPM Error:0x%x", rval);
        return rval;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;
    memcpy(&sessions_data.auths[0].hmac, endorsementSecretKey, sizeof(TPM2B_AUTH));

    // start a second session
    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = sessionHandle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    TPM2_HANDLE loaded_sha1_key_handle;
    rval = Tss2_Sys_Load(sys, TPM_HANDLE_EK, &sessions_data, &out_private, &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_Load Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    // use password for owner
    memcpy(&sessions_data.auths[0].hmac, ownerSecretKey, sizeof(TPM2B_AUTH));

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, loaded_sha1_key_handle, &sessions_data, TPM_HANDLE_AIK, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_FlushContext(sys, loaded_sha1_key_handle);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Flush transient AK error. TPM Error:0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

//-------------------------------------------------------------------------------------------------
//
// This function implements the following commands (see cicd/tpm2_commands.sh)
//
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName -g 0x1
//
//-------------------------------------------------------------------------------------------------
int CreateAik(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLength,
              const uint8_t *endorsementSecretKey,
              size_t endorsementSecretKeyLength)
{

    TSS2_RC rval;
    TPM2_HANDLE handle2048rsa = 0;
    TPM2B_AUTH ownerAuth = {0};
    TPM2B_AUTH endorsementAuth = {0};
    TPM2B_AUTH aikAuth = {0}; // provide empty aik secret so no password is needed

    rval = InitializeTpmAuth(&ownerAuth, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        ERROR("There was an error creating the tpm owner secret");
        return rval;
    }

    rval = InitializeTpmAuth(&endorsementAuth, endorsementSecretKey, endorsementSecretKeyLength);
    if (rval != 0)
    {
        ERROR("There was an error creating the tpm endorsement secret");
        return rval;
    }

    //
    // tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beeffeedbeeffeedbeeffeedbeeffeedbeeffeed -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName
    //
    if (PublicKeyExists(ctx, TPM_HANDLE_AIK) == 0)
    {
        DEBUG("The AIK handle at 0x%x already exists. Clearing the existing handle", TPM_HANDLE_AIK);

        // Clear the existing provisioned AIK
        rval = ClearKeyHandle(ctx->sys, &ownerAuth, TPM_HANDLE_AIK);
        if (rval != TPM2_RC_SUCCESS)
        {
            return rval;
        }
    }

    // Provision the newly minted AIK
    rval = getpubak(ctx->sys, &ownerAuth, &endorsementAuth, &aikAuth);
    if (rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }

    DEBUG("Successfully persisted AIK at handle 0x%x", TPM_HANDLE_AIK);
    return TSS2_RC_SUCCESS;
}

int GetAikName(const tpmCtx *ctx,
               uint8_t **aikName,
               int *aikNameLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &name, &qualifiedName, &sessionsData);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (name.size == 0 || name.size > ARRAY_SIZE(name.name))
    {
        ERROR("Invalid aik name length: 0x%x", name.size)
        return -1;
    }

    *aikName = calloc(name.size, 1);
    if (!*aikName)
    {
        ERROR("Could not allocate aik name buffer");
        return -1;
    }

    memcpy(*aikName, name.name, name.size);
    *aikNameLength = name.size;

    return 0;
}

int GetAikBytes(const tpmCtx *ctx,
                uint8_t **const aikBytes,
                int *const aikBytesLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME aikName = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &aikName, &qualifiedName, &sessionsData);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (aikPublic.publicArea.unique.rsa.size == 0 || aikPublic.publicArea.unique.rsa.size > ARRAY_SIZE(aikPublic.publicArea.unique.rsa.buffer))
    {
        ERROR("Incorrect aik buffer length 0x%x", aikPublic.publicArea.unique.rsa.size);
        return -1;
    }

    *aikBytes = calloc(aikPublic.publicArea.unique.rsa.size, 1);
    if (!*aikBytes)
    {
        ERROR("Could not allocate aik public buffer");
        return -1;
    }

    memcpy(*aikBytes, aikPublic.publicArea.unique.rsa.buffer, aikPublic.publicArea.unique.rsa.size);
    *aikBytesLength = aikPublic.publicArea.unique.rsa.size;

    return 0;
}