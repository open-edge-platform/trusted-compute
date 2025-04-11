/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TPM_H__
#define __TPM_H__

#include <stdint.h> // size_t, etc.
#include <stdlib.h> // C.free

typedef enum TPM_VERSION
{
    TPM_VERSION_UNKNOWN,
    TPM_VERSION_10,
    TPM_VERSION_20
} TPM_VERSION;

typedef enum TCTI_TYPE
{
    TCTI_DEVICE,
    TCTI_MSSIM,
} TCTI_TYPE;

typedef enum NV_IDX
{
    NV_IDX_RSA_ENDORSEMENT_CERTIFICATE = 0x1c00002,
    NV_IDX_ECC_ENDORSEMENT_CERTIFICATE = 0x1c0000a,
    NV_IDX_X509_P384_EK_CERTCHAIN = 0x01c00100,
    NV_IDX_ASSET_TAG = 0x1c10110
} NV_IDX;

typedef enum TPM_HANDLE
{
    TPM_HANDLE_PRIMARY = 0x81000000,
    TPM_HANDLE_EK = 0x81010000,
    TPM_HANDLE_AIK = 0x81018000,
} TPM_HANDLE;

typedef enum TPM_CERTIFIED_KEY_USAGE
{
    TPM_CERTIFIED_KEY_USAGE_BINDING = 0,
    TPM_CERTIFIED_KEY_USAGE_SIGNING,
} TPM_CERTIFIED_KEY_USAGE;

typedef enum TPM_PROVIDER_ERROR
{
    TPM_PROVIDER_ERROR_NO_EK_CERT = 0x100000,
    TPM_PROVIDER_EK_PUBLIC_MISMATCH,
    TPM_PROVIDER_INVALID_PCRSELECTION,
    TPM_PROVIDER_INVALID_PCRCOUNT,
} TPM_PROVIDER_ERROR;

typedef struct CertifiedKey
{
    struct
    {
        int size;
        unsigned char *buffer;
    } publicKey;
    struct
    {
        int size;
        unsigned char *buffer;
    } privateBlob;
    struct
    {
        int size;
        unsigned char *buffer;
    } keySignature;
    struct
    {
        int size;
        unsigned char *buffer;
    } keyAttestation;
    struct
    {
        int size;
        unsigned char *buffer;
    } keyName;
} CertifiedKey;

typedef struct tpmCtx tpmCtx;

//
//  To be use in cgo code to free memory allocated by TPM provider
//
void explicit_memzero(void *v, size_t n);

tpmCtx *TpmCreate(unsigned int tctiType, const char *conf);

void TpmDelete(tpmCtx *ctx);

TPM_VERSION Version(tpmCtx *ctx);

int TakeOwnership(const tpmCtx *ctx,
                  const uint8_t *ownerSecretKey,
                  size_t ownerSecretKeyLength,
                  const uint8_t *endorsementSecretKey,
                  size_t endorsementSecretKeyLength);

int IsOwnedWithAuth(const tpmCtx *ctx,
                    const uint8_t *ownerSecretKey,
                    size_t ownerSecretKeyLength);

int CreateAik(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLength,
              const uint8_t *endorsementSecretKey,
              size_t endorsementSecretKeyLength);

int GetAikBytes(const tpmCtx *ctx,
                uint8_t **const aikBytes,
                int *const aikBytesLength);

int GetAikName(const tpmCtx *ctx,
               uint8_t **const aikName,
               int *const aikNameLength);

int GetTpmQuote(const tpmCtx *ctx,
                const uint8_t *pcrSelectionBytes,
                size_t pcrSelectionBytesLength,
                const uint8_t *qualifyingDataString,
                size_t qualifyingDataStringLength,
                uint8_t **const quoteBytes,
                int *const quouteBytesLength);

int ActivateCredential(const tpmCtx *ctx,
                       const uint8_t *endorsementSecretKey,
                       size_t endorsementSecretKeyLength,
                       const uint8_t *credentialBytes,
                       size_t credentialBytesLength,
                       const uint8_t *secretBytes,
                       size_t secretBytesLength,
                       uint8_t **const decrypted,
                       int *const decryptedLength);

int CreatePrimaryHandle(const tpmCtx *ctx,
                        uint32_t persistHandle,
                        const uint8_t *ownerSecretKey,
                        size_t ownerSecretKeyLength);

int CreateEk(const tpmCtx *ctx,
             const uint8_t *ownerSecretKey,
             size_t ownerSecretKeyLength,
             const uint8_t *endorsementSecretKey,
             size_t endorsementSecretKeyLength,
             uint32_t ekHandle);

int NvIndexExists(const tpmCtx *ctx, uint32_t nvIndex);

int NvDefine(const tpmCtx *ctx,
             const uint8_t *ownerSecretKey,
             size_t ownerSecretKeyLength,
             const uint8_t *indexSecretKey,
             size_t indexSecretKeyLength,
             uint32_t nvIndex,
             uint16_t nvSize);

int NvRead(const tpmCtx *ctx,
           const uint8_t *indexSecretKey,
           size_t indexSecretKeyLength,
           uint32_t authHandle,
           uint32_t nvIndex,
           uint8_t **const nvBytes,
           int *const nvBytesLength);

int NvWrite(const tpmCtx *ctx,
            const uint8_t *indexSecretKey,
            size_t indexSecretKeyLength,
            uint32_t authHandle,
            uint32_t nvIndex,
            const uint8_t *nvBytes,
            size_t nvBytesLength);

int NvRelease(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLenth,
              uint32_t nvIndex);

int CreateCertifiedKey(const tpmCtx *ctx,
                       CertifiedKey *keyOut,
                       TPM_CERTIFIED_KEY_USAGE usage,
                       const uint8_t *keySecret,
                       size_t keySecretLength);

int Unbind(const tpmCtx *ctx,
           const uint8_t *bindingSecretKey,
           size_t bindingSecretKeyLength,
           const uint8_t *publicKeyBytes,
           size_t publicKeyBytesLength,
           const uint8_t *privateKeyBytes,
           size_t privateKeyBytesLength,
           const uint8_t *encryptedBytes,
           size_t encryptedBytesLength,
           uint8_t **const decryptedData,
           int *const decryptedDataLength);

int Sign(const tpmCtx *ctx,
         const uint8_t *signingSecretKey,
         size_t signingSecretKeyLength,
         const uint8_t *publicKeyBytes,
         size_t publicKeyBytesLength,
         const uint8_t *privateKeyBytes,
         size_t privateKeyBytesLength,
         const uint8_t *hashBytes,
         size_t hashBytesLength,
         uint8_t **const signatureBytes,
         int *const signatureBytesLength);

int PublicKeyExists(const tpmCtx *ctx,
                    uint32_t handle);

int ReadPublic(const tpmCtx *ctx,
               uint32_t handle,
               uint8_t **const publicBytes,
               int *const publicBytesLength);

int IsValidEk(const tpmCtx *ctx,
              const uint8_t *ownerSecretKey,
              size_t ownerSecretKeyLength,
              uint32_t handle,
              uint32_t ekCertificateIndex);

int IsPcrBankActive(const tpmCtx *ctx,
                    const uint8_t *pcrSelectionBytes,
                    size_t pcrSelectionBytesLength);

#endif