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


typedef struct _OPTFLAG {
        uint16_t        read            : 1;
        uint16_t        type            : 1;
        uint16_t        output          : 1;
        uint16_t        keysize         : 1;
        uint16_t        savepubkey      : 1;
        uint16_t        bypass          : 1;
        uint16_t        dummy6          : 1;
        uint16_t        dummy7          : 1;
        uint16_t        dummy8          : 1;
        uint16_t        dummy9          : 1;
        uint16_t        dummy10         : 1;
        uint16_t        dummy11         : 1;
        uint16_t        dummy12         : 1;
        uint16_t        dummy13         : 1;
        uint16_t        dummy14         : 1;
        uint16_t        dummy15         : 1;
}OPTFLAG;

union _uOptFlag {
        OPTFLAG flags;
        uint16_t        all;
} uOptFlag;

int main (void)
{
    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;
    uint8_t eccheader256[] = {0x30,0x59, // SEQUENCE
                                0x30,0x13, // SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x08, // OID:1.2.840.10045.3.1.7
                                0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};

    uint8_t eccheader384[] = {0x30,0x76, // SEQUENCE
                                0x30,0x10, //SEQUENCE
                                0x06,0x07, // OID:1.2.840.10045.2.1
                                0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x05, // OID:1.3.132.0.34
                                0x2B,0x81,0x04,0x00,0x22};
    uint8_t pubKey[200];
    uint16_t i;

    uint16_t pubKeyLen = sizeof(pubKey)+1000;
    uint8_t keyType=0x01;// default Auth
    //default:
    //uint8_t keySize=0x03;// default 256
    uint8_t keySize=0x04; // 384?
    char *outFile = "ecc_testi.pem";
    uint8_t signature [300];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);
    // 256 digest len = 32, 384 Len = 48
    //uint8_t digest[32];
    uint8_t digest[48];
    uint16_t digestLen = 0;
    uint8_t message[2048] = "temperature=6\ntestvariable=false\nserial=234j-f399-34jl-pp34\nanother_variable=0x3442d\ntime=16:40\nmessage_received=true";
    size_t messageLen;
    messageLen = sizeof(message);



    int option = 0;                    // Command line option.

    uOptFlag.all = 0;

    //ecc_keygen -kopioitu
    optiga_key_id = 0xE0F2;

    if(uOptFlag.flags.bypass != 1)
    #ifdef HIBERNATE_ENABLE
        trustm_hibernate_flag = 1; // Enable hibernate Context Save
    #else
        trustm_hibernate_flag = 0; // disable hibernate Context Save
    #endif 
    else
        trustm_hibernate_flag = 0; // disable hibernate Context Save




    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS){
        printf("alustusvirhe\r\n");
        exit(1);
    }

    // ECC header 256 tai 384
    for (i=0; i < sizeof(eccheader384);i++)
    {
        pubKey[i] = eccheader384[i];
    }


    if(uOptFlag.flags.bypass != 1)
        {
            // OPTIGA Comms Shielded connection settings to enable the protection
            OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
            OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
        }

    for(size_t j = 0;j<10; j++){
        optiga_lib_status = OPTIGA_LIB_BUSY;
        clock_t t = clock();
        return_status = optiga_crypt_ecc_generate_keypair(me_crypt, keySize, keyType, FALSE, &optiga_key_id, (pubKey+i), &pubKeyLen);
        trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        //return_status = optiga_util_write_data(me_util, (optiga_key_id+0x10E0), OPTIGA_UTIL_ERASE_AND_WRITE, 0, (pubKey), pubKeyLen+i);
        //trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
        t = clock()- t;
        double gen_time = ((double)t)/CLOCKS_PER_SEC;
        printf("gen_time: %f\r\n", gen_time);
        
        if(OPTIGA_LIB_SUCCESS != return_status){
            printf("virhe generoinnissa\r\n");
            exit(1);
        }
        //trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
    }
    
    // Sign aika alkaa
    //HASH 256/384
    for (size_t k = 0; k < 10; k++)
    {
        memset(digest, 0, sizeof(digest));
        digestLen = 0;
        signature_length = sizeof(signature);
        clock_t t = clock();
        //SHA256_CTX sha256;
        SHA512_CTX sha384;

        //SHA256_Init(&sha256);
        SHA384_Init(&sha384);

        //SHA256_Update(&sha256, message, messageLen);
        SHA384_Update(&sha384, message, messageLen);

        //SHA256_Final(digest, &sha256);
        SHA384_Final(digest, &sha384);

        digestLen = sizeof(digest);
         //printf("Hash onnistui: \n");
        //trustmHexDump(digest, digestLen);

        //printf("ennen signausta sign_len: %x\r\n", signature_length);
        //printf("digest_len: %x\r\n", digestLen);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecdsa_sign(me_crypt, 
                                                digest, 
                                                digestLen, 
                                                optiga_key_id, 
                                                signature, 
                                                &signature_length);

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

    return_status = optiga_lib_status;
    if (return_status != OPTIGA_LIB_SUCCESS){
        printf("virhe: %x\r\n", return_status);
    }
    else
    {
        printf("Pubkey :\n");
        trustmHexDump(pubKey, (uint32_t) pubKeyLen+i);

        return_status = trustmWritePEM(pubKey, pubKeyLen+i,
                                                                                    outFile,"PUBLIC KEY");
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
                    printf("Error when saving file!!!\n");
        }
    } 

    trustm_Close();
    trustm_hibernate_flag = 0;
    return 0;
}