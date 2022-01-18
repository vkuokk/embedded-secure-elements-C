//#include <asf.h>
#include "cryptoauthlib.h"
#include <stdio.h>
#include <assert.h>
#include <time.h>
//#include "atca_iface.h"

//"Esimerkistä Cryptoauthlib -hello world"

extern ATCA_STATUS status = ATCA_SUCCESS;
/*
static ATCA_STATUS cryptoauthlib_init(void)
{
    

    ATCAIfaceCfg cfg_ateccx08a_i2c_default2 = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC608A,
    .atcai2c.slave_address  = 0x6A,
    .atcai2c.bus            = 1,
    .atcai2c.baud           = 400000,
    //.atcai2c.baud = 100000,
    .wake_delay             = 1500,
    .rx_retries             = 20
    };
    //#elif (CRYPTOAUTH_DEVICE == DEVICE_ATECC508A)
    //status = atcab_init(&cfg_ateccx08a_i2c_default);
    //#elif (CRYPTOAUTH_DEVICE == DEVICE_ATECC608A)
    //cfg_ateccx08a_i2c_default.atcai2c.slave_address = ECC608A_ADDRESS;
    cfg_ateccx08a_i2c_default2.devtype = ATECC608A;
    status = atcab_init(&cfg_ateccx08a_i2c_default2);
    

    return status;
}
*/

/*
ATCAIfaceCfg cfg = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC608A,
    .atcai2c.address        = 0x6A,
    .atcai2c.bus            = 1,
    .atcai2c.baud           = 100000,
    //.atcai2c.baud = 100000,
    .wake_delay             = 1500,
    .rx_retries             = 20
    };
*/


int main(void)
{
    uint8_t message[2048] = "temperature=6\ntestvariable=false\nserial=234j-f399-34jl-pp34\nanother_variable=0x3442d\ntime=16:40\nmessage_received=true";
    size_t messageLen = sizeof(message);
    uint8_t digest[32] = {0};
    uint8_t public_key[64];
    uint16_t private_key_id;
    uint8_t slot = 3;
    uint8_t random_number[32];
    uint8_t revision[4];
    uint8_t info[4];

    uint8_t signature[32] = {0};
    bool device = false;
    bool locked = true;
    memset(revision, 0, 4*sizeof(uint8_t));

    //memset(revision, 0, 4);
    //system_init();
    //SysTick_Config(system_gclk_gen_get_hz(GCLK_GENERATOR_0));
    //status = cryptoauthlib_init();

    
    
    ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
    cfg.atcai2c.baud = 100000;
    cfg.atcai2c.bus = 1;
    cfg.atcai2c.address = 0x6A;

    //assert(status = atcab_init(&cfg) == ATCA_SUCCESS);
    status = atcab_init(&cfg);

    //assert(status == ATCA_SUCCESS);

    printf("statuskoodi: %04X\r\n", status);
    device = atcab_is_ca_device(ATECC608B);
    printf("%i\n",device);
    device = atcab_is_ca_device(ATECC608A);
    printf("%i\n",device);
    device = atcab_is_ca_device(ATECC608);
    printf("%i\n",device);
    device = atcab_is_ca_device(ATCA_DEV_UNKNOWN);
    printf("%i\n",device);

    status = atcab_is_config_locked(&locked);
    printf("statuskoodilocked: %04X\r\n", status);
    printf("locked: %i\r\n", locked);
    
    //cfg_ateccx08a_i2c_default.devtype = ATECC608A;
    //status = atcab_init(&cfg_ateccx08a_i2c_default);
    printf("revision: %i\n", revision);
    status = atcab_info(&revision);
    printf("statuskoodi: %04X\r\n", status);
    //printf("revision: %u\n", revision);
    // toisenlainen printtaus
    printf("%i", revision[0]);
    printf("%i", revision[1]);
    printf("%i", revision[2]);
    printf("%i\r\n", revision[3]);

    //printf("random: %f", random_number);
    status = atcab_random(&random_number);
    printf("statuskoodi: %04X\r\n", status);
    status = atcab_get_pubkey(0,&public_key);
    printf("statuskoodi: %04X\r\n", status);
    printf("random: %32x\n", &random_number);
    //printf("ennen gen public: %f ja private %f\n", public_key, private_key_id);
    printf("public key: ");
    for (size_t i=0; i<sizeof public_key; i++){
        printf("%x",public_key[i]);
    }

    printf("\r\n");

    // private key slotista 1:
    //private_key_id = 1;
    //status = atca_test_config_get_id(3, &private_key_id);
    private_key_id = 0x02;
    printf("\r\n");

    

    status = atcab_genkey(slot, &public_key);
    
    
    printf("statuskoodi gen: %04X\r\n", status);
    //status = atcab_genkey(ATCA_TEMPKEY_KEYID, &public_key);
    //printf("statuskoodi gen: %04X\r\n", status);


    for (size_t i = 0; i<10; i++){

        clock_t t = clock();
        status = atcab_genkey(slot, &public_key);

        t = clock() - t;
        double gen_time = ((double)t)/CLOCKS_PER_SEC;
        printf("gen time: %f\r\n", gen_time);
    }


    printf("statuskoodi gen: %04X\r\n", status);
    //printf("jälkeen gen public: %64X\n", public_key);

    status = atcab_hw_sha2_256(&message, messageLen, &digest);
    printf("statuskoodi hash: %04X\r\n", status);

    //digestin tarkistus (olemassaolo)
    for(size_t i=0; i<sizeof digest; i++){
        printf("%x", digest[i]);
    }
    
    printf("\r\n");
    //signature
    for(size_t i = 0; i<10; i++){
        clock_t t = clock();
        status = atcab_sign(slot, &digest, &signature);
        t = clock() - t;
        double sign_time = ((double)t)/CLOCKS_PER_SEC;
        printf("sign time: %f\r\n", sign_time);
    }
    

    printf("statuskoodi sign: %04X\r\n", status);

    printf("\r\n");
    printf("signature\r\n");
    for (size_t i=0;i<sizeof signature; i++){
        printf("%x",signature[i]);
    }

    printf("\r\n");
    printf("public key: ");
    for (size_t i=0; i<sizeof public_key; i++){
        printf("%x",public_key[i]);
    }
    printf("\r\n");
    printf("private key id: %x\r\n ", private_key_id);
    //printf("random number: %f", random_number);
}