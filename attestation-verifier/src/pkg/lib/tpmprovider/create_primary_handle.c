/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int CreatePrimaryHandle(const tpmCtx *ctx,
                        uint32_t persistHandle,
                        const uint8_t *ownerSecretKey,
                        size_t ownerSecretKeyLength)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_COMMAND sessionsData = {0};
    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT;
    TPM2B_PUBLIC inPublic = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION creationPCR = {0};
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2_HANDLE handle2048rsa = 0;

    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionsData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }

    inSensitive.size = inSensitive.sensitive.userAuth.size + sizeof(inSensitive.size);

    inPublic.publicArea.type = TPM2_ALG_RSA;       // -G 0x0001
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256; // -g 0x000B
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(ctx->sys, TPM2_RH_OWNER, &sessionsData,
                                  &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                                  &handle2048rsa, &outPublic, &creationData, &creationHash,
                                  &creationTicket, &name, &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_CreatePrimary returned error code: 0x%0x\n", rval);
        return rval;
    }

    rval = Tss2_Sys_EvictControl(ctx->sys, TPM2_RH_OWNER, handle2048rsa, &sessionsData, persistHandle, &sessionsDataOut);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_EvictControl returned error code: 0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}