#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
// #include <openssl/evperr.h>

int encrypt(const unsigned char *key, const unsigned char *iv,
            const unsigned char *msg, size_t msg_len, unsigned char *out);

int main() {

	// uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	// char input[] = "1";

	// char test[100] = {0};
	// sizeof(test);
	// sizeof(input);

	// SHA256(input, strlen(input), hash);

	// // printf("Hash: a582e8c28249fe7d7990bfa0afebd2da9185a9f831d4215b4efec74f355b301a\n");

	// 	printf("inpu: ");
	// for(int i = 0; i < strlen(input); i++) {
	// 	printf("%02x", input[i]);
	// }
	// printf("\n");

	// printf("Hash: ");
	// for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
	// 	printf("%02x", hash[i]);
	// }
	// printf("\n");

	// printf("Version: %s", OPENSSL_VERSION_STR);


	// const uint8_t key[] = "test";
	// const uint8_t iv[]  = "123";
	// const uint8_t msg[] = "Hallo Welt!";
	// uint8_t out[200] = {0};

	// encrypt(key, iv, msg, strlen(msg), out);

	// printf("ENCR:\n");
	// for(int i = 0; i < 200; i++) {
	// 	printf("%02x", out[i]);
	// }
	// printf("\n");

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	const EVP_CIPHER* cipher = EVP_aes_256_ecb();
	const uint8_t* key = "testkey";
	const uint8_t* iv = "testkey";
	const uint8_t* msg = "Hallo Welt!12345";
	int size = 1000;
	uint8_t buffer[1000] = {0};
	uint8_t out[1000] = {0};
	int c = 0;

	int ret = EVP_EncryptInit(ctx, cipher, key, NULL);
	if (!ret) {
		EVP_CIPHER_free(cipher);
		EVP_CIPHER_CTX_free(ctx);
		printf("Init Error!");
		return 1;
	}

	// OSSL_PARAM* param = {"padding"};

	// printf("Padding: %d", EVP_CIPHER_CTX_get_params(ctx, OSSL_CIPHER_PARAM_PADDING));

	ret = EVP_EncryptUpdate(ctx, buffer, &size, msg, strlen(msg));
		if (!ret) {
		EVP_CIPHER_free(cipher);
		EVP_CIPHER_CTX_free(ctx);
		printf("Update Error!");
		return 1;
	}

	for(int i = 0; i < size; i++) {
		// printf("%02x", buffer[i]);
		out[c++] = buffer[i];
	}
	printf("\n");

	ret = EVP_EncryptFinal(ctx, buffer, &size);
	if (!ret) {
		EVP_CIPHER_free(cipher);
		EVP_CIPHER_CTX_free(ctx);
		printf("Final Error!");
		return 1;
	}

	for(int i = 0; i < size; i++) {
		out[c++] = buffer[i];
	}

	printf("ENCR:\n");
	for(int i = 0; i < c; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");


	EVP_CIPHER_free(cipher);
	EVP_CIPHER_CTX_free(ctx);
	return 0;

}

int encrypt(const unsigned char *key, const unsigned char *iv,
            const unsigned char *msg, size_t msg_len, unsigned char *out)
{
   /*
    * This assumes that key size is 32 bytes and the iv is 16 bytes.
    * For ciphertext stealing mode the length of the ciphertext "out" will be
    * the same size as the plaintext size "msg_len".
    * The "msg_len" can be any size >= 16.
    */
    int ret = 0, encrypt = 1, outlen, len;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);
    if (ctx == NULL || cipher == NULL)
        goto err;

    /*
     * The default is "CS1" so this is not really needed,
     * but would be needed to set either "CS2" or "CS3".
     */
    params[0] = OSSL_PARAM_construct_utf8_string("cts_mode",
                                                 "CS1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, params))
        goto err;

    /* NOTE: CTS mode does not support multiple calls to EVP_CipherUpdate() */
    if (!EVP_CipherUpdate(ctx, out, &outlen, msg, msg_len))
        goto err;
     if (!EVP_CipherFinal_ex(ctx, out + outlen, &len))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}