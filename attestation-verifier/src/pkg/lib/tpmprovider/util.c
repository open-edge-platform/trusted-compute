
/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tpm20linux.h"

#include <ctype.h>
#include <limits.h>


void explicit_memzero(void *v, size_t n) {
    if (v != NULL)  {
        volatile unsigned char *p = (volatile unsigned char *)v;

        while (n--) {
            *p++ = (unsigned char)0x00;
        }
    }
}

//
// A constant time safe memcmp function
//
int timingsafe_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *uptr1 = a;
    const unsigned char *uptr2 = b;
    unsigned int valLT = 0u;
    unsigned int valGT = 0u;
    volatile unsigned int mask = (1u << CHAR_BIT);

    for (; 0 != len; --len, ++uptr1, ++uptr2) {
        // calculates the difference between the corresponding bytes
        valLT |= mask & ((unsigned int)*uptr1 - (unsigned int)*uptr2);
        valGT |= mask & ((unsigned int)*uptr2 - (unsigned int)*uptr1);

        // ensure that once a difference is found, subsequent bytes
        // do not affect the result
        mask &= ~(valLT | valGT);
    }

    return (int)(valGT >> CHAR_BIT) - (int)(valLT >> CHAR_BIT);
}

int InitializeTpmAuth(TPM2B_AUTH *auth, const char *secretKey, size_t secretKeyLength)
{
    if (!auth)
    {
        ERROR("Auth not provided");
        return -1;
    }

    if (!secretKey)
    {
        ERROR("Null secret key provided");
        return -1;
    }

    if (secretKeyLength > ARRAY_SIZE(auth->buffer))
    {
        ERROR("Invalid secret key length: %ld", secretKeyLength);
        return -1;
    }

    memcpy(auth->buffer, secretKey, secretKeyLength);
    auth->size = secretKeyLength;

    return 0;
}

//
// Returns an integer value indicating the status of the public key at handle 'handle'.
// Zero:     Public key exists at 'handle'
// Negative: Public key does not exist at 'handle'
// Positive: Error code from Tss2_Sys_ReadPublic
//
int PublicKeyExists(const tpmCtx *ctx, uint32_t handle)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_PUBLIC inPublic = TPM2B_EMPTY_INIT;
    ;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
    //    DEBUG("Tss2_Sys_ReadPublic of handle 0x%x returned 0x%0x", handle, rval);
    if (rval == 0x18b)
    {
        rval = -1;
    }

    return rval;
}

//
// ClearKeyHandle clears a key from the TPM. Returns an integer value indicating whether the key was cleared:
// Zero:     Key at handle cleared
// Non-zero: Key clearing failed. Error code from Tss2_Sys_EvictControl.
//
int ClearKeyHandle(TSS2_SYS_CONTEXT *sys, TPM2B_AUTH *ownerAuth, TPM_HANDLE keyHandle)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {{
                                                   .sessionHandle = TPM2_RS_PW,
                                                   .nonce = TPM2B_EMPTY_INIT,
                                                   .hmac = TPM2B_EMPTY_INIT,
                                                   .sessionAttributes = 0,
                                               }}};

    if (ownerAuth == NULL)
    {
        ERROR("The owner auth must be provided");
        return -1;
    }

    memcpy(&sessions_data.auths[0].hmac, ownerAuth, sizeof(TPM2B_AUTH));

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, keyHandle, &sessions_data, keyHandle, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Key clearing failed. TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    return rval;
}

int ReadPublic(const tpmCtx *ctx,
               TPM_HANDLE handle,
               uint8_t **const modulusBytes,
               int *const modulusBytesLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, NULL, &public, &name, &qualifiedName, &sessionsData);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (public.publicArea.unique.rsa.size == 0 || public.publicArea.unique.rsa.size > ARRAY_SIZE(public.publicArea.unique.rsa.buffer))
    {
        ERROR("Incorrect buffer length 0x%x", public.publicArea.unique.rsa.size);
        return -1;
    }

    *modulusBytes = calloc(public.publicArea.unique.rsa.size, 1);
    if (!*modulusBytes)
    {
        ERROR("Could not allocate modulus buffer");
        return -1;
    }

    memcpy(*modulusBytes, public.publicArea.unique.rsa.buffer, public.publicArea.unique.rsa.size);
    *modulusBytesLength = public.publicArea.unique.rsa.size;

    return TSS2_RC_SUCCESS;
}
