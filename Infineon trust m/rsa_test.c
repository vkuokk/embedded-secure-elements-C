#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>


// Esimerkkinä käytetty trustm_rsa_keygen.c
int main (void){

    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;

    uint8_t rsaheader2048[] = {0x30,0x82,0x01,0x22, // SEQUENCE
                                0x30,0x0d,          // SEQUENCE
                                0x06,0x09,          // OID : 1.2.840.113549.1.1.1
                                0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
                                0x05,0x00};         // NULL

    uint8_t rsaheader1024[] = {0x30,0x81,0x9F,      // SEQUENCE
                                0x30,0x0D,          // SEQUENCE
                                0x06,0x09,          // OID : 1.2.840.113549.1.1.1
                                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,
                                0x05,0x00};         // NULL

    uint8_t pubKey[300];
    uint16_t i;

    uint16_t pubKeyLen = sizeof(pubKey)+1000;
    uint8_t keyType=0x01;// default Auth
    uint8_t keySize=0x41; // default 1024
    //uint8_t keySize=0x42;// 2048?

    // (yksi) default RSA -avaimen id:stä
    optiga_key_id =0xE0FC;
    uint8_t signature [300];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);
    // 256 digest len = 32, 384 Len = 48
    uint8_t digest[32];
    //uint8_t digest[48];
    uint16_t digestLen = 0;
    uint8_t message[2048] = "temperature=6\ntestvariable=false\nserial=234j-f399-34jl-pp34\nanother_variable=0x3442d\ntime=16:40\nmessage_received=true";
    size_t messageLen;
    messageLen = sizeof(message);



    return_status = trustm_Open();

    for (i=0; i < sizeof(rsaheader1024);i++)
    {
        pubKey[i] = rsaheader1024[i];
    }

    for(size_t j = 0; j<10; j++){
        optiga_lib_status = OPTIGA_LIB_BUSY;
        clock_t t = clock();
        return_status = optiga_crypt_rsa_generate_keypair(me_crypt,
                                                        keySize,
                                                        keyType,
                                                                FALSE,
                                                        &optiga_key_id,
                                                        (pubKey+i),
                                                        &pubKeyLen);


        trustm_WaitForCompletion(MAX_RSA_KEY_GEN_TIME);

        t = clock() -t;
        double gen_time = ((double)t)/CLOCKS_PER_SEC;
        return_status = optiga_lib_status;
        printf("gen_time: %f\r\n", gen_time);
        if(OPTIGA_LIB_SUCCESS != return_status)
        {
            printf("virhe generoinnissa\r\n");
            exit(1);
        }
    }
        // Sign aika alkaa
    //HASH 256/384
    for (size_t k = 0; k < 10; k++)
    {
        memset(digest, 0, sizeof(digest));
        digestLen = 0;
        signature_length = sizeof(signature);
        clock_t t = clock();
        SHA256_CTX sha256;
        //SHA512_CTX sha384;

        SHA256_Init(&sha256);
        //SHA384_Init(&sha384);

        SHA256_Update(&sha256, message, messageLen);
        //SHA384_Update(&sha384, message, messageLen);

        SHA256_Final(digest, &sha256);
        //SHA384_Final(digest, &sha384);

        digestLen = sizeof(digest);
         //printf("Hash onnistui: \n");
        //trustmHexDump(digest, digestLen);

        //printf("ennen signausta sign_len: %x\r\n", signature_length);
        //printf("digest_len: %x\r\n", digestLen);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_rsa_sign(me_crypt,
                                                OPTIGA_RSASSA_PKCS1_V15_SHA256, 
                                                digest, 
                                                digestLen, 
                                                optiga_key_id, 
                                                signature, 
                                                &signature_length,
                                                0x0000);

        trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        return_status = optiga_lib_status;

        if (return_status == OPTIGA_LIB_SUCCESS)
        {
            //printf("signature: \n");
            //trustmHexDump(signature, signature_length);
            //memset(signature, 0, sizeof(signature));
            //printf("signature_length: %f\n", signature_length);
            
        }
        t = clock() - t;
        double sign_time = ((double)t) / CLOCKS_PER_SEC;
        printf("sign_time: %f\r\n", sign_time);
    }


    

    trustm_Close();
    trustm_hibernate_flag = 0;
    return 0;

}