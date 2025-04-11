/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

tpmCtx *TpmCreate(unsigned int tctiType, const char *conf)
{
    tpmCtx *ctx = NULL;
    size_t size = 0;
    TSS2_RC rc = 0;
    TSS2_ABI_VERSION abiVersion = {0};
    const char *tss2Conf = conf;

    if (tctiType != TCTI_DEVICE && tctiType != TCTI_MSSIM)
    {
        ERROR("Incorrect tcti type: %d\n", tctiType);
        return NULL;
    }

    ctx = (tpmCtx *)calloc(1, sizeof(tpmCtx));
    if (ctx == NULL)
    {
        ERROR("Could not allocate tpm context\n");
        return NULL;
    }

    ctx->version = TPM_VERSION_20;

    if (tctiType == TCTI_DEVICE)
    {
        rc = Tss2_Tcti_Device_Init(NULL, &size, NULL);
    }
    else if (tctiType == TCTI_MSSIM)
    {
        Tss2_Tcti_Mssim_Init(NULL, &size, NULL);
    }

    if (rc != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Tcti_Device_Init return %d\n", rc);
        free(ctx);
        return NULL;
    }

    ctx->tcti = (TSS2_TCTI_CONTEXT *)calloc(1, size);

    if (tctiType == TCTI_DEVICE)
    {
        rc = Tss2_Tcti_Device_Init(ctx->tcti, &size, tss2Conf);
    }
    else if (tctiType == TCTI_MSSIM)
    {
        Tss2_Tcti_Mssim_Init(ctx->tcti, &size, tss2Conf);
    }

    if (rc != TPM2_RC_SUCCESS)
    {
        ERROR("Tcti_Init returned %d\n", rc);
        free(ctx);
        return NULL;
    }

    abiVersion.tssCreator = 1;
    abiVersion.tssFamily = 2;
    abiVersion.tssLevel = 1;
    abiVersion.tssVersion = 108;

    size = Tss2_Sys_GetContextSize(0);
    ctx->sys = (TSS2_SYS_CONTEXT *)calloc(1, size);
    if (ctx == NULL)
    {
        ERROR("Could not allocate TSS2_SYS_CONTEXT\n");
        free(ctx);
        return NULL;
    }

    rc = Tss2_Sys_Initialize(ctx->sys, size, ctx->tcti, &abiVersion);
    if (rc != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Initialize returned %d\n", rc);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void TpmDelete(tpmCtx *ctx)
{
    if (ctx != NULL)
    {
        if (ctx->sys)
        {
            Tss2_Sys_Finalize(ctx->sys);
            free(ctx->sys);
        }

        if (ctx->tcti)
        {
            Tss2_Tcti_Finalize(ctx->tcti);
            free(ctx->tcti);
        }

        free(ctx);
    }
}

TPM_VERSION Version(tpmCtx *ctx)
{
    return ctx->version;
}
