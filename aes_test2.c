#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

int
Base64Encode ( const unsigned char* buffer, size_t length, char** b64text )
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);//ignore new line - writee everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return (0); // success
}

size_t
calcDecodeLength ( const char* b64input ) //Calculate the length of a decoded string
{
    size_t len = strlen(b64input),
        padding = 0;

    if ( b64input[len-1] == '=' && b64input[len-2] == '=' )
        padding = 2;
    else if ( b64input[len-1] == '=' )
        padding = 1;

    return (len * 3) / 4 - padding;
}

int
Base64Decode ( char* b64message, unsigned char** buffer, size_t* length ) //Decodes a base64 encoded string
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*) malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);//Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen);
    BIO_free_all(bio);

    return (0);
}

static void
hex_print ( const void* pv, size_t len )
{
    const unsigned char * p = (const unsigned char*)pv;
    if ( NULL == pv )
        printf("NULL");
    else {
        size_t i = 0;
        for (; i<len; ++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}

int
main ( int argc, char **argv )
{
    int keylength = 128;

    unsigned char aes_key[keylength/8];
    memset(aes_key, 0, keylength/8);

    aes_key[0] = 'o';
    aes_key[1] = 'p';
    aes_key[2] = 'b';
    aes_key[3] = 'a';
    aes_key[4] = 't';
    aes_key[5] = 'c';
    aes_key[6] = 'h';
    aes_key[7] = '1';
    aes_key[8] = '2';
    aes_key[9] = '3';
    aes_key[10] = '4';
    aes_key[11] = '5';
    aes_key[12] = '6';
    aes_key[13] = '7';
    aes_key[14] = '8';
    aes_key[15] = '9';

    printf("aes_key : %s\n", aes_key);

    size_t inputslength = 4;

    unsigned char aes_input[inputslength];
    memset(aes_input, 0, inputslength);

    aes_input[0] = 'H';
    aes_input[1] = 'K';
    aes_input[2] = 'O';
    aes_input[3] = 'O';

    printf("aes_input : %s\n", aes_input);

    unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
    iv_enc[0] = 0x9d;
    iv_enc[1] = 0x30;
    iv_enc[2] = 0x5c;
    iv_enc[3] = 0x8a;
    iv_enc[4] = 0x86;
    iv_enc[5] = 0x3c;
    iv_enc[6] = 0x10;
    iv_enc[7] = 0x90;
    iv_enc[8] = 0x94;
    iv_enc[9] = 0xd4;
    iv_enc[10] = 0xb5;
    iv_enc[11] = 0x77;
    iv_enc[12] = 0xa1;
    iv_enc[13] = 0x57;
    iv_enc[14] = 0xb0;
    iv_enc[15] = 0x02;

    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);

    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
    printf("enc_out : ", enc_out);
    hex_print(enc_out, sizeof(enc_out));

    char* base64EncodeOutput;
    Base64Encode(enc_out, strlen(enc_out), &base64EncodeOutput);
    printf("Output (base64): %s\n", base64EncodeOutput);

    unsigned char * base64DecodeOutput;
    size_t test;
    Base64Decode(base64EncodeOutput, &base64DecodeOutput, &test);
    printf("Output : %s, %d\n", base64DecodeOutput, test);

    AES_set_decrypt_key(aes_key, 128, &dec_key);
    AES_cbc_encrypt(base64DecodeOutput, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

    printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));
    printf("==> %s\n", aes_input);

    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));
    printf("==> %s\n", enc_out);

    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));
    printf("==> %s\n", dec_out);

    return 0;
}
