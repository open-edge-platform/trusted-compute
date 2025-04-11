/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

//-------------------------------------------------------------------------------------------------
// NewEk
// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_getpubek.c
//-------------------------------------------------------------------------------------------------
static int NewEk(const tpmCtx *ctx,
                 TPM2B_AUTH *ownerAuth,
                 TPM2B_AUTH *endorsementAuth,
                 TPMT_PUBLIC *ekTemplate,
                 uint32_t ekHandle)
{
    TSS2_RC rval;
    TPM2_HANDLE handle2048ek;
    TPML_PCR_SELECTION creationPCR;
    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2L_SYS_AUTH_COMMAND sessionsData = {1, {{
                                                  .sessionHandle = TPM2_RS_PW,
                                                  .nonce = TPM2B_EMPTY_INIT,
                                                  .hmac = TPM2B_EMPTY_INIT,
                                                  .sessionAttributes = 0,
                                              }}};

    if (ownerAuth == NULL)
    {
        ERROR("The owner secret key cannot be null");
        return -1;
    }

    if (endorsementAuth == NULL)
    {
        ERROR("The endorsement secret key cannot be null");
        return -1;
    }

    if (ekTemplate == NULL)
    {
        ERROR("The ek template cannot be null");
        return -1;
    }

    memcpy(&inPublic.publicArea, ekTemplate, sizeof(TPMT_PUBLIC));

    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;

    memcpy(&sessionsData.auths[0].hmac, endorsementAuth, sizeof(TPM2B_AUTH));

    creationPCR.count = 0;

    /* Create EK and get a handle to the key */
    rval = Tss2_Sys_CreatePrimary(ctx->sys, TPM2_RH_ENDORSEMENT,
                                  &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                                  &handle2048ek, &outPublic, &creationData, &creationHash,
                                  &creationTicket, &name, &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("TPM2_CreatePrimary Error. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("EK create success. Got handle: 0x%8.8x", handle2048ek);

    memcpy(&sessionsData.auths[0].hmac, ownerAuth, sizeof(TPM2B_AUTH));

    rval = Tss2_Sys_EvictControl(ctx->sys, TPM2_RH_OWNER, handle2048ek, &sessionsData, ekHandle, &sessionsDataOut);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("EvictControl failed. Could not make EK persistent. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("EvictControl EK persistent success.");

    rval = Tss2_Sys_FlushContext(ctx->sys, handle2048ek);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Flush transient EK failed. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("Successfully persisted EK at handle 0x%x", ekHandle);
    return rval;
}

int CreateEk(const tpmCtx *ctx,
             const uint8_t *ownerSecretKey,
             size_t ownerSecretKeyLength,
             const uint8_t *endorsementSecretKey,
             size_t endorsementSecretKeyLength,
             uint32_t ekHandle)
{
    TSS2_RC rval;
    TPM2B_AUTH ownerAuth = {0};
    TPM2B_AUTH endorsementAuth = {0};
    TPMT_PUBLIC ekTemplate = {0};

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
    // tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
    //
    if (PublicKeyExists(ctx, ekHandle) == 0)
    {
        DEBUG("The EK handle at %x already exists. Clearing the existing handle", ekHandle);

        rval = ClearKeyHandle(ctx->sys, &ownerAuth, ekHandle);
        if (rval != TPM2_RC_SUCCESS)
        {
            DEBUG("Failed to clear handle at 0x%x", ekHandle);
            return rval;
        }
    }

    rval = GetEkTemplate(ctx, &ownerAuth, &ekTemplate);
    if (rval != TPM2_RC_SUCCESS)
    {
        DEBUG("Failed to get Ek template");
        return rval;
    }

    rval = NewEk(ctx, &ownerAuth, &endorsementAuth, &ekTemplate, ekHandle);
    if (rval != TPM2_RC_SUCCESS)
    {
        DEBUG("Failed to create Ek at 0x%x", ekHandle);
        return rval;
    }

    return TPM2_RC_SUCCESS;
}