/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

// From https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_nv_util.h::tpm2_util_nv_max_buffer_size

#define NV_DEFAULT_BUFFER_SIZE 512

static int GetMaxNvBufferSize(TSS2_SYS_CONTEXT *sys, uint32_t *size)
{
    TSS2_RC rval = TSS2_BASE_RC_GENERAL_FAILURE;
    TPMS_CAPABILITY_DATA cap_data;
    TPMI_YES_NO more_data;

    if (!sys)
    {
        ERROR("TSS2_SYS_CONTEXT was not provided.");
        return TSS2_BASE_RC_BAD_REFERENCE;
    }

    if (!size)
    {
        ERROR("'size' was not provided.")
        return TSS2_BASE_RC_BAD_REFERENCE;
    }

    *size = 0;

    rval = Tss2_Sys_GetCapability(sys, NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, &more_data, &cap_data, NULL);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Failed to query max transmission size via Tss2_Sys_GetCapability. Error:0x%x", rval);
        return rval;
    }
    else
    {
        *size = cap_data.data.tpmProperties.tpmProperty[0].value;
    }

    if (*size > TPM2_MAX_NV_BUFFER_SIZE)
    {
        *size = TPM2_MAX_NV_BUFFER_SIZE;
    }
    else if (*size == 0)
    {
        *size = NV_DEFAULT_BUFFER_SIZE;
    }

    DEBUG("Max nv buffer size is 0x%x", *size);

    return TSS2_RC_SUCCESS;
}

int NvDefine(const tpmCtx *ctx,
             const uint8_t *ownerSecretKey,
             size_t ownerSecretKeyLength,
             const uint8_t *indexSecretKey,
             size_t indexSecretKeyLength,
             uint32_t nvIndex,
             uint16_t nvSize)
{
    TSS2_RC rval;
    TPM2B_NV_PUBLIC publicInfo = TPM2B_EMPTY_INIT;
    TPM2B_AUTH indexAuth = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    rval = InitializeTpmAuth(&indexAuth, indexSecretKey, indexSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    publicInfo.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH) + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.nvPublic.dataSize = nvSize;
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA256;
    publicInfo.nvPublic.attributes = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_OWNERREAD;

    rval = Tss2_Sys_NV_DefineSpace(ctx->sys, TPM2_RH_OWNER, &sessionData, &indexAuth, &publicInfo, &sessionDataOut);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_NV_DefineSpace returned error: 0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

int NvRelease(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLength,
              uint32_t nvIndex)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    rval = Tss2_Sys_NV_UndefineSpace(ctx->sys, TPM2_RH_OWNER, nvIndex, &sessionData, 0);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_NV_UndefineSpace returned error: 0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

//
// Returns 0 if true, -1 for false, all other values are error codes
//
int NvIndexExists(const tpmCtx *ctx, uint32_t nvIndex)
{
    TSS2_RC rval;
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nv_public, &nv_name, NULL);
    if (rval == 0x18B)
    {
        return -1;
    }

    return rval;
}

int NvRead(const tpmCtx *ctx,
           const uint8_t *indexSecretKey,
           size_t indexSecretKeyLength,
           uint32_t authHandle,
           uint32_t nvIndex,
           uint8_t **const nvBytes,
           int *const nvBytesLength)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NV_PUBLIC nvPublic = TPM2B_EMPTY_INIT;
    TPM2B_MAX_NV_BUFFER nvData = TPM2B_TYPE_INIT(TPM2B_MAX_NV_BUFFER, buffer);
    uint16_t nvBufferSize = 0; // total size of nv buffer
    uint16_t off = 0;          // offset to read from in nv buffer
    uint16_t len = 0;          // size of nv buffer to read

    *nvBytesLength = 0; // return zero in case of error conditions below

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, indexSecretKey, indexSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    // use the Tss2_Sys_NV_ReadPublic to find the total size of the index
    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nvPublic, &name, NULL);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_NV_ReadPublic returned: 0x%x", rval);
        return rval;
    }

    nvBufferSize = nvPublic.nvPublic.dataSize;
    if (nvBufferSize == 0 || nvBufferSize > TPM2_MAX_NV_BUFFER_SIZE)
    {
        ERROR("Invalid nv buffer size 0x%x", nvBufferSize);
        return -1;
    }

    *nvBytes = (uint8_t *)calloc(nvBufferSize, 1);
    if (!*nvBytes)
    {
        ERROR("Could not allocate nv buffer");
        return -1;
    }

    // loop for the length of nv buffer, reading "default size" chunks to avoid
    // errors encountered when reading more than 1024 bytes.
    while (off < nvBufferSize)
    {
        len = nvBufferSize > NV_DEFAULT_BUFFER_SIZE ? NV_DEFAULT_BUFFER_SIZE : nvBufferSize;
        if (off + len > nvBufferSize)
        {
            len = nvBufferSize - off;
        }

        rval = Tss2_Sys_NV_Read(ctx->sys, authHandle, nvIndex, &sessionData, len, off, &nvData, &sessionsDataOut);
        if (rval != TSS2_RC_SUCCESS)
        {
            ERROR("Tss2_Sys_NV_Read returned: 0x%x", rval);
            free(*nvBytes);
            return rval;
        }

        if (len != nvData.size)
        {
            ERROR("The nvdata size did not match the requested length [len:0x%x, size:0x%x]", len, nvData.size);
            free(*nvBytes);
            return rval;
        }

        memcpy(*nvBytes + off, nvData.buffer, len);
        off += len;
    }

    *nvBytesLength = off;
    DEBUG("Successfully read 0x%x bytes from index 0x%x", off, nvIndex)

    return TSS2_RC_SUCCESS;
}

int NvWrite(const tpmCtx *ctx,
            const uint8_t *indexSecretKey,
            size_t indexSecretKeyLength,
            uint32_t authHandle,
            uint32_t nvIndex,
            const uint8_t *nvBytes,
            size_t nvBytesLength)
{
    TSS2_RC rval;
    size_t pos = 0; // offset into nbBytes
    uint32_t maxNvBufferSize;
    TSS2L_SYS_AUTH_RESPONSE sessionDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionData = {0};
    TPM2B_MAX_NV_BUFFER nvWriteData;

    DEBUG("Attempting to save 0x%x bytes to nv index 0x%x", nvBytesLength, nvIndex)

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, indexSecretKey, indexSecretKeyLength);
    if (rval != 0)
    {
        return rval;
    }

    if (nvBytesLength == 0 || nvBytesLength > TPM2_MAX_NV_BUFFER_SIZE)
    {
        ERROR("Invalid nv write buffer size: 0x%lx", nvBytesLength);
        return -1;
    }

    while (pos < nvBytesLength)
    {
        memset(&nvWriteData, 0, sizeof(TPM2B_MAX_NV_BUFFER));
        nvWriteData.size = (nvBytesLength - pos) > NV_DEFAULT_BUFFER_SIZE ? NV_DEFAULT_BUFFER_SIZE : (nvBytesLength - pos);

        memcpy(nvWriteData.buffer, (nvBytes + pos), nvWriteData.size);

        rval = Tss2_Sys_NV_Write(ctx->sys, authHandle, nvIndex, &sessionData, &nvWriteData, (uint16_t)pos, &sessionDataOut);
        if (rval != TSS2_RC_SUCCESS)
        {
            ERROR("Tss2_Sys_NV_Write returned error:0x%x", rval);
            return rval;
        }

        pos += nvWriteData.size;
    }

    DEBUG("Saved 0x%x bytes to nv index 0x%x", pos, nvIndex)
    return TSS2_RC_SUCCESS;
}
