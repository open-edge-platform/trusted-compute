/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

// This file contains all of the tss2 specific functions, defines, etc. to
// support tpm20linux.go

#ifndef __TPM_20_LINUX__
#define __TPM_20_LINUX__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_mssim.h>

#include "tpm.h"

#define TRUE 1
#define FALSE 0

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_util.h
#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field)      \
    {                                     \
        .size = BUFFER_SIZE(type, field), \
    }
#define TPM2B_INIT(xsize) \
    {                     \
        .size = xsize,    \
    }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPMT_TK_CREATION_EMPTY_INIT \
    {                               \
        .tag = 0,                   \
        .hierarchy = 0,             \
        .digest = TPM2B_EMPTY_INIT  \
    }

#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT \
    {                                     \
        .sensitive = {                    \
            .data.size = 0,               \
            .userAuth.size = 0,           \
        },                                \
    }

#define TPMS_AUTH_COMMAND_INIT(session_handle) \
    {                                          \
        .sessionHandle = session_handle,       \
        .nonce = TPM2B_EMPTY_INIT,             \
        .sessionAttributes = 0,                \
        .hmac = TPM2B_EMPTY_INIT               \
    }

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT                                                                                                                                \
    {                                                                                                                                                                       \
        .publicArea = {                                                                                                                                                     \
            .type = TPM2_ALG_RSA,                                                                                                                                           \
            .objectAttributes =                                                                                                                                             \
                TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH, \
        },                                                                                                                                                                  \
    }

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

#define LOG(fmt, ...) fprintf(stdout, "[LOG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#define ERROR(fmt, ...) fprintf(stderr, "[ERR:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);

#define ENABLE_DEBUG_LOGGING 0
#if ENABLE_DEBUG_LOGGING
#define DEBUG(fmt, ...) fprintf(stdout, "[DBG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#else
#define DEBUG(fmt, ...)
#endif

struct tpmCtx
{
    TPM_VERSION version;
    TSS2_TCTI_CONTEXT *tcti;
    TSS2_SYS_CONTEXT *sys;
};

//-------------------------------------------------------------------------------------------------
// Internal utility functions
//-------------------------------------------------------------------------------------------------

//
//  Memcmp function which is constant time safe
//
int timingsafe_memcmp(const void *a, const void *b, size_t len);

//
//  Converts a string into TPM2B_AUTH and performs simple validation.
//
int InitializeTpmAuth(TPM2B_AUTH *auth, const char *secretKey, size_t secretKeyLength);

//
// Removes the persistent handle at 'keyHandle' from the TPM.
//
int ClearKeyHandle(TSS2_SYS_CONTEXT *sys, TPM2B_AUTH *ownerAuth, TPM_HANDLE keyHandle);

//
// This function  implements the procedure documented in sections 2.2.1.6 and  2.2.1.9 in 'TCG EK
// Credential Profile' version 2.1.  However, it will return an error if the TPM does not use RSA
// EKs/certificate since HVS does not currently support ECC or other ('high range') algorithms.
//
int GetEkTemplate(const tpmCtx *ctx, TPM2B_AUTH *ownerAuth, TPMT_PUBLIC *outPublic);

#endif
