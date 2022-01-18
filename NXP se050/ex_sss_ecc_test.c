/*
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <time.h>
#include <string.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_BIT_LEN 256
#define EC_KEY_BIT_LEN2 384
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* clang-format off */
const uint8_t keyPairData[] = { 0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x78, 0xE5, 0x20, 0x6A,
    0x08, 0xED, 0xD2, 0x52, 0x36, 0x33, 0x8A, 0x24,
    0x84, 0xE4, 0x2F, 0x1F, 0x7D, 0x1F, 0x6D, 0x94,
    0x37, 0xA9, 0x95, 0x86, 0xDA, 0xFC, 0xD2, 0x23,
    0x6F, 0xA2, 0x87, 0x35, 0xA1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9, 0x20,
    0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7, 0x20,
    0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86, 0xD2,
    0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A, 0x15,
    0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78, 0x63,
    0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D, 0x87,
    0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76, 0x63,
    0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31, 0x8E,
    0x68, 0x7C };

const uint8_t extPubKeyData[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9,
    0x20, 0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7,
    0x20, 0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86,
    0xD2, 0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A,
    0x15, 0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78,
    0x63, 0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D,
    0x87, 0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76,
    0x63, 0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31,
    0x8E, 0x68, 0x7C
};

/* clang-format on */

static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_status_t status2 = kStatus_SSS_Success;
    uint8_t message[2048] = "temperature=6\ntestvariable=false\nserial=234j-f399-34jl-pp34\nanother_variable=0x3442d\ntime=16:40\nmessage_received=true";
    uint8_t digest[32]  = "Hello World";

    // tai voi olla myös 64
    uint8_t digest_256[32] = {0};
    uint8_t digest_384[48] = {0};
    size_t digestLen;
    size_t messageLen;
    size_t digest_256Len;
    size_t digest_384Len;
    uint8_t signature_2[256] = {0};
    uint8_t signature_3[384]= {0};
    size_t signatureLen;
    size_t signatureLen3;
    size_t signatureLen1;
    sss_object_t keyPair;
    sss_object_t keyPair2;
    sss_object_t key_pub;
    sss_asymmetric_t ctx_asymm  = {0};
    sss_asymmetric_t ctx_verify = {0};
    sss_digest_t digest_ctx = {0};

    sss_algorithm_t digest256_algorithm = kAlgorithm_SSS_SHA256;
    sss_algorithm_t digest384_algorithm = kAlgorithm_SSS_SHA384;

    // RSA:n muuttujat
    sss_object_t key;
    sss_asymmetric_t ctx_asym = {0};
    uint32_t keyId = MAKE_TEST_ID(__LINE__);
    uint8_t digest_1024[32] = {0};
    uint8_t digest_1024Len;
    uint8_t signature_1024[128] = {0};

    uint8_t digest_2048[32] = {0};
    uint8_t digest_2048Len;
    uint8_t signature_2048[256] = {0};

    // LOG_I kommentoitu pois
    // LOG_I("Running Elliptic Curve Cryptography Example ex_sss_ecc_test.c");

    digestLen = sizeof(digest);
    messageLen = sizeof(message);

    /* doc:start ex_sss_asymmetric-allocate-key */
    /* Pre-requisite for Signing Part*/
    
    //status = sss_key_object_init(&keyPair, &pCtx->ks);
    //ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

// nistp-256 avaimen generointi ja sillä messagen signature


for (int i = 0; i < 11; i++) {

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);


    status = sss_key_object_allocate_handle(&keyPair,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        //sizeof(keyPairData),
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    //oma: vanhan avaimen poisto, uuden avaimen generointi ja ajan otto
    // aika avaimen generoinnnista
    time_t t;
    t = clock();
    status = sss_key_store_erase_key(&pCtx->ks, &keyPair);
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, EC_KEY_BIT_LEN, 0);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // aika avaimen asettamisesta muistiin
    //printf("keypair: %f", keyPair.keyStore->extension.data);

    //LOG_MAU8_I("avain: ", keyPair.keyStore->extension.data, 256);

    //time_t ts;
    //ts = clock();
    // ????
    // status = sss_key_store_set_key(&pCtx->ks, &keyPair, keyPairData, sizeof(keyPairData), EC_KEY_BIT_LEN, NULL, 0);
    //ts = clock() - ts;
    t = clock() - t;
    double gen_time = ((double)t)/CLOCKS_PER_SEC;

    //double set_time = ((double)ts)/CLOCKS_PER_SEC;
    //ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    //double gen_plus_set = gen_time + set_time;

    printf("vanhan avaimen poisto ja uuden generointi: %f\n", gen_time);

    /* doc:end ex_sss_asymmetric-allocate-key */

    /* doc:start ex_sss_asymmetric-asym-sign */

    // vaihdettu SHA256 -> ECDSA_SHA256

    // AJAN OTTO SIGNATURELLE ALKAA
    time_t signt;
    signt = clock();


    // Digestin tuotto
    memset(signature_2, 0, 256);
    //signature_2 = {0};


    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest256_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status = kStatus_SSS_Success);

    digest_256Len = sizeof(digest_256);
    status = sss_digest_one_go(&digest_ctx, message, messageLen, digest_256, &digest_256Len);

    // Digestin tuotto loppuu

    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);



    // OTETAAN MUKAAN MYÖS SIGNATURE
    // Kommentoitu pois tässä turhia logiviestejä
    signatureLen = sizeof(signature_2);
    /* Do Signing */
    // LOG_I("Do Signing");
    // LOG_MAU8_I("digest", digest, digestLen);

    // vaihdettu digest ja digestLen -> message, messageLen
    status = sss_asymmetric_sign_digest(&ctx_asymm, digest_256, digest_256Len, signature_2, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    signt = clock() - signt;
    double sign_time = ((double)signt)/CLOCKS_PER_SEC;
    // AJAN OTTO SIGNATURELLE LOPPUU

    printf("256 avaimen signature viestille: %f\n", sign_time);

    


    // LOG_MAU8_I("signature", signature, signatureLen);
    // LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);
    /* doc:end ex_sss_asymmetric-asym-sign */

}



// 384 -bittisen nistp generointi ja signature
for (int i = 0; i < 11; i++) {

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        EC_KEY_BIT_LEN2,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    time_t t;
    t = clock();

    status = sss_key_store_erase_key(&pCtx->ks, &keyPair);
    //ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 384, 0);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    t = clock() - t;
    double gen_time = ((double)t)/CLOCKS_PER_SEC;
    //clock_t ts = clock();
    //status2 = sss_key_store_set_key(&pCtx->ks, &keyPair, keyPairData, sizeof(keyPairData), 384, NULL, 0);
    //ts = clock() - ts;
    
    //double set_time = ((double)ts)/CLOCKS_PER_SEC;
    //ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    //double gen_plus_set = gen_time + set_time;
    printf("384-bittisen avaimen generointi ja asettaminen key storeen: %f\n", gen_time);



    // AJAN OTTO SIGNATURELLE ALKAA
    time_t signt;
    signt = clock();

    // Digestin tuotto
    memset(signature_3, 0, 384);

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest384_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status = kStatus_SSS_Success);

    digest_384Len = sizeof(digest_384);

    //double vltulos = sizeof(digest_384);
    //printf("väli: %f", vltulos);
    status = sss_digest_one_go(&digest_ctx, message, messageLen, digest_384, &digest_384Len);

    // Digestin tuotto loppuu



    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA384, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status2 == kStatus_SSS_Success);

    signatureLen3 = sizeof(signature_3);
    // Do Signing 
    // LOG_I("Do Signing");
    // LOG_MAU8_I("digest", digest, digestLen);

    // vaihdettu digest ja digestLen -> message, messageLen
    status = sss_asymmetric_sign_digest(&ctx_asymm, digest_384, digest_384Len, signature_3, &signatureLen3);
    
    signt = clock() - signt;
    double sign_time = ((double)signt)/CLOCKS_PER_SEC;
    // AJAN OTTO SIGNATURELLE LOPPUU

    printf("384 avaimen signature viestille: %f\n", sign_time);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    


    // LOG_MAU8_I("signature", signature, signatureLen);
    // LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);

}


// RSA-avaimen generointi (1024)

for(int i = 0; i<11; i++){

    status = sss_key_object_init(&key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    time_t t;
    t = clock();

    status = sss_key_store_erase_key(&pCtx->ks, &keyPair);

    sss_algorithm_t algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;

    status = sss_key_object_allocate_handle(&keyPair, 
        keyId, 
        kSSS_KeyPart_Pair, 
        kSSS_CipherType_RSA, 
        (1024 / 8), 
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 1024, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    t = clock() - t;
    double rsa_time = ((double)t)/CLOCKS_PER_SEC;

    time_t ts;
    ts = clock();
    // Digestin tuotto
    memset(signature_1024, 0, 128);

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status = kStatus_SSS_Success);

    digest_1024Len = sizeof(digest_1024);

    //double vltulos = sizeof(digest_384);
    //printf("väli: %f", vltulos);
    status = sss_digest_one_go(&digest_ctx, message, messageLen, digest_1024, &digest_1024Len);

    // Digestin tuotto loppuu

    signatureLen = sizeof(signature_1024);



    status = sss_asymmetric_context_init(&ctx_asym, &pCtx->session, &keyPair, algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&ctx_asym, digest_1024, digest_1024Len, signature_1024, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ts = clock() - ts;
    double rsa_sign = ((double)ts)/CLOCKS_PER_SEC;

    printf("RSA 1024:n genaika: %f\n", rsa_time);
    printf("RSA 1024:n sign aika: %f\n", rsa_sign);
}


// RSA 2048 generointi
for(int i = 0; i<11; i++){

    status = sss_key_object_init(&key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    time_t t;
    t = clock();

    status = sss_key_store_erase_key(&pCtx->ks, &keyPair);

    sss_algorithm_t algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;

    status = sss_key_object_allocate_handle(&keyPair, 
        keyId, 
        kSSS_KeyPart_Pair, 
        kSSS_CipherType_RSA, 
        (2048 / 8), 
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, 2048, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    t = clock() - t;
    double rsa_time = ((double)t)/CLOCKS_PER_SEC;

    time_t ts;
    ts = clock();
    // Digestin tuotto
    memset(signature_1024, 0, 128);

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status = kStatus_SSS_Success);

    digest_2048Len = sizeof(digest_2048);

    //double vltulos = sizeof(digest_384);
    //printf("väli: %f", vltulos);
    status = sss_digest_one_go(&digest_ctx, message, messageLen, digest_2048, &digest_2048Len);

    // Digestin tuotto loppuu

    signatureLen = sizeof(signature_2048);



    status = sss_asymmetric_context_init(&ctx_asym, &pCtx->session, &keyPair, algorithm, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&ctx_asym, digest_2048, digest_2048Len, signature_2048, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ts = clock() - ts;
    double rsa_sign = ((double)ts)/CLOCKS_PER_SEC;

    printf("RSA 2048:n genaika: %f\n", rsa_time);
    printf("RSA 2048:n sign aika: %f\n", rsa_sign);
}


    /* Pre requiste for Verifying Part*/
    status = sss_key_object_init(&key_pub, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&key_pub,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        sizeof(extPubKeyData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    //status = sss_key_store_set_key(&pCtx->ks, &key_pub, extPubKeyData, sizeof(extPubKeyData), EC_KEY_BIT_LEN, NULL, 0);
    //ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* doc:start ex_sss_asymmetric-asym-verify */
    status =
        sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &key_pub, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Logit kommentoitu pois LOG_I ja LOG_MAU8

    // LOG_I("Do Verify");
    // LOG_MAU8_I("digest", digest, digestLen);
    // LOG_MAU8_I("signature", signature, signatureLen);
    status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature_2, signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    // LOG_I("Verification Successful !!!");
    /* doc:end ex_sss_asymmetric-asym-verify */

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecc_test Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecc_test Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL)
        sss_asymmetric_context_free(&ctx_asymm);
    if (ctx_verify.session != NULL)
        sss_asymmetric_context_free(&ctx_verify);
    return status;
}
