/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

#define NV_INDEX_RSA_NONCE 0x1c00003
#define NV_INDEX_RSA_TEMPLATE 0x1c00004
#define NV_INDEX_ECC_NONCE 0x1c0000b
#define NV_INDEX_ECC_TEMPLATE 0x1c0000c

#define NV_INDEX_ABSENT 0
#define NV_INDEX_PRESENT 1

// The 'TCG EK Credential Profile' recommends looking for NV indexes using
// TPM2_GetCapabilties.  For now, restrict the range to RSA indices.
#define CAPABILITY_HANDLE_START 0x01C00000
#define CAPABILITY_HANDLE_END 0x01C00005

typedef union NvIndexStatus
{
    struct
    {
        unsigned int RsaEkCertificate : 1;
        unsigned int RsaEkNonce : 1;
        unsigned int RsaEkTemplate : 1;
        unsigned int EccEkCertificate : 1;
        unsigned int EccEkNonce : 1;
        unsigned int EccEkTemplate : 1;
    };
    unsigned int raw;
} NvIndexStatus;

static int GetNVIndices(TSS2_SYS_CONTEXT *sys, TPMS_CAPABILITY_DATA *capability_data)
{
    TSS2_RC rval;
    TPM2_CAP capability = TPM2_CAP_HANDLES;
    TPMI_YES_NO more_data = 0;

    rval = Tss2_Sys_GetCapability(sys,
                                  NULL,
                                  capability,
                                  CAPABILITY_HANDLE_START,
                                  (CAPABILITY_HANDLE_END - CAPABILITY_HANDLE_START),
                                  &more_data,
                                  capability_data,
                                  NULL);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_GetCapability returned 0x%x", rval);
    }

    return rval;
}

static NvIndexStatus GetNvIndexStatus(TPMS_CAPABILITY_DATA *capability_data)
{
    NvIndexStatus results = {0};

    for (int i = 0; i < capability_data->data.handles.count; i++)
    {
        DEBUG("NV index 0x%x is present", capability_data->data.handles.handle[i]);

        switch (capability_data->data.handles.handle[i])
        {
        case NV_IDX_RSA_ENDORSEMENT_CERTIFICATE:
            DEBUG("RSA EK Certificate is present at nv index 0x%x", NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
            results.RsaEkCertificate = NV_INDEX_PRESENT;
            break;
        case NV_INDEX_RSA_NONCE:
            DEBUG("RSA nonce is present at nv index 0x%x", NV_INDEX_RSA_NONCE)
            results.RsaEkNonce = NV_INDEX_PRESENT;
            break;
        case NV_INDEX_RSA_TEMPLATE:
            DEBUG("RSA template is present at nv index 0x%x", NV_INDEX_RSA_TEMPLATE)
            results.RsaEkTemplate = NV_INDEX_PRESENT;
            break;
        case NV_IDX_ECC_ENDORSEMENT_CERTIFICATE:
            DEBUG("ECC EK Certificate is present at nv index 0x%x", NV_IDX_ECC_ENDORSEMENT_CERTIFICATE)
            results.EccEkCertificate = NV_INDEX_PRESENT;
            break;
        case NV_INDEX_ECC_NONCE:
            DEBUG("ECC nonce is present at nv index 0x%x", NV_INDEX_ECC_NONCE)
            results.EccEkNonce = NV_INDEX_PRESENT;
            break;
        case NV_INDEX_ECC_TEMPLATE:
            DEBUG("ECC template is present at nv index 0x%x", NV_INDEX_ECC_TEMPLATE)
            results.EccEkTemplate = NV_INDEX_PRESENT;
            break;
        default:
            DEBUG("Unhandled nv index 0x%x", capability_data->data.handles.handle[i])
            break;
        }
    }

    return results;
}

static int UnmarshalEkTemplate(const tpmCtx *ctx, TPM2B_AUTH *ownerAuth, uint32_t nvIndex, TPMT_PUBLIC *outPublic)
{
    TSS2_RC rval = -1;
    uint8_t *nvBytes;
    int nvLength;

    DEBUG("Collecting EK template from nv index 0x%x", NV_INDEX_RSA_TEMPLATE);

    rval = NvRead(ctx, (uint8_t *)ownerAuth->buffer, ownerAuth->size, TPM2_RH_OWNER, nvIndex, &nvBytes, &nvLength);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Could not read EK template at index 0x%x.  NvRead returned 0x%x", nvIndex, rval);
        goto error;
    }

    rval = Tss2_MU_TPMT_PUBLIC_Unmarshal(nvBytes, nvLength, 0, outPublic);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Could not unmarshal EK template.  Tss2_MU_TPMT_PUBLIC_Unmarshal returned 0x%x", rval);
        goto error;
    }

    rval = TSS2_RC_SUCCESS;

error:
    if (nvBytes)
    {
        free(nvBytes);
    }

    return rval;
}

static int SetEkNonce(const tpmCtx *ctx, TPM2B_AUTH *ownerAuth, uint32_t nvIndex, TPMT_PUBLIC *outPublic)
{
    TSS2_RC rval = -1;
    uint8_t *nvBytes = NULL;
    int nvLength = 0;

    rval = NvRead(ctx, (uint8_t *)ownerAuth->buffer, ownerAuth->size, TPM2_RH_OWNER, nvIndex, &nvBytes, &nvLength);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Could not read EK nonce at index 0x%x.  NvRead returned 0x%x", nvIndex, rval);
        goto error;
    }

    if (nvBytes == NULL || nvLength == 0 || nvLength > ARRAY_SIZE(outPublic->unique.rsa.buffer))
    {
        ERROR("Invalid nvByte buffer ptr or buffer size: 0x%x", nvLength);
        goto error;
    }

    if (outPublic == NULL)
    {
        ERROR("outPublic cannot be null");
        goto error;
    }

    memset(&outPublic->unique, 0, sizeof(TPMU_PUBLIC_ID));
    memcpy(outPublic->unique.rsa.buffer, nvBytes, nvLength);

    outPublic->unique.rsa.size = 256;

    rval = TSS2_RC_SUCCESS;

error:
    if (nvBytes)
    {
        free(nvBytes);
    }

    return rval;
}

// see section 'B.3.3 Template L-1: RSA 2048 (Storage)' in the 'TCG EK Credential Profile' specs
static int SetDefaultRsaTemplate(TPMT_PUBLIC *outPublic)
{

    DEBUG("Using default TCG RSA EK template");

    if (outPublic == NULL) {
        ERROR("The public structure cannot be null");
        return -1;
    }

    memset(outPublic, 0, sizeof(TPMT_PUBLIC));

    outPublic->type = TPM2_ALG_RSA;
    outPublic->nameAlg = TPM2_ALG_SHA256;

    outPublic->objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    outPublic->objectAttributes &= ~TPMA_OBJECT_STCLEAR;
    outPublic->objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    outPublic->objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    outPublic->objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
    outPublic->objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
    outPublic->objectAttributes &= ~TPMA_OBJECT_NODA;
    outPublic->objectAttributes &= ~TPMA_OBJECT_ENCRYPTEDDUPLICATION;
    outPublic->objectAttributes |= TPMA_OBJECT_RESTRICTED;
    outPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
    outPublic->objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;

    static BYTE auth_policy[] = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
        0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
        0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA};

    outPublic->authPolicy.size = ARRAY_SIZE(auth_policy);
    memcpy(outPublic->authPolicy.buffer, auth_policy, ARRAY_SIZE(auth_policy));

    outPublic->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    outPublic->parameters.rsaDetail.symmetric.keyBits.aes = 128;
    outPublic->parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    outPublic->parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    outPublic->parameters.rsaDetail.keyBits = 2048;
    outPublic->parameters.rsaDetail.exponent = 0;

    outPublic->unique.rsa.size = 256;

    return TSS2_RC_SUCCESS;
}

int GetEkTemplate(const tpmCtx *ctx, TPM2B_AUTH *ownerAuth, TPMT_PUBLIC *outPublic)
{
    TSS2_RC rval;
    TPMS_CAPABILITY_DATA capability_data = {0};
    NvIndexStatus nvIndexStatus;

    if (!ctx)
    {
        ERROR("The TPM context cannot be null");
        return -1;
    }

    if (!outPublic)
    {
        ERROR("The public structure cannot be null");
        return -1;
    }

    rval = GetNVIndices(ctx->sys, &capability_data);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    nvIndexStatus = GetNvIndexStatus(&capability_data);

    if (nvIndexStatus.RsaEkTemplate == NV_INDEX_PRESENT)
    {
        LOG("Applying RSA EK template from nv index 0x%x", NV_INDEX_RSA_TEMPLATE);
        rval = UnmarshalEkTemplate(ctx, ownerAuth, NV_INDEX_RSA_TEMPLATE, outPublic);
    }
    else
    {
        rval = SetDefaultRsaTemplate(outPublic);
    }

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Failure in applying the RSA EK Template");
        return rval;
    }

    // Populate nonce if present and also check for 'unspecified' scenario...
    if (nvIndexStatus.RsaEkNonce == NV_INDEX_PRESENT && nvIndexStatus.RsaEkTemplate == NV_INDEX_PRESENT)
    {
        LOG("Applying RSA EK nonce from nv index 0x%x", NV_INDEX_RSA_NONCE);
        rval = SetEkNonce(ctx, ownerAuth, NV_INDEX_RSA_NONCE, outPublic);
    }
    else if (nvIndexStatus.RsaEkNonce == NV_INDEX_PRESENT && nvIndexStatus.RsaEkTemplate == NV_INDEX_ABSENT)
    {
        ERROR("The case of an EK Template Absent and an EK Nonce Populated is unspecified");
        return -1;
    }
    else
    {
        DEBUG("The EK Nonce will not be applied")
    }

    DEBUG("Template Type:        0x%x", outPublic->type);
    DEBUG("Template Alg:         0x%x", outPublic->nameAlg);
    DEBUG("Template Attributes:  0x%x", outPublic->objectAttributes);
    DEBUG("Template Auth Size:   0x%x", outPublic->authPolicy.size);
    DEBUG("Template Sym Algo:    0x%x", outPublic->parameters.rsaDetail.symmetric.algorithm);
    DEBUG("Template Sym Keybits: 0x%x", outPublic->parameters.rsaDetail.symmetric.keyBits);
    DEBUG("Template Sym Mode:    0x%x", outPublic->parameters.rsaDetail.symmetric.mode);
    DEBUG("Template Scheme:      0x%x", outPublic->parameters.rsaDetail.scheme.scheme);
    DEBUG("Template Keybits:     0x%x", outPublic->parameters.rsaDetail.keyBits);
    DEBUG("Template Exponent:    0x%x", outPublic->parameters.rsaDetail.exponent);
    DEBUG("Template Unique Size: 0x%x", outPublic->unique.rsa.size);

    return TSS2_RC_SUCCESS;
}
