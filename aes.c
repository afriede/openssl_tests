#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define DECRYPT 0
#define ENCRYPT 1

size_t do_crypt(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len, const unsigned char* key, const unsigned char* iv, int do_encrypt);
int do_cryptFile(FILE *in, FILE *out, int do_encrypt);

int main() {
	// FILE* infile  = fopen("testfile copy.txt", "rb");
	// FILE* outfile = fopen("testfile.txt.enc", "wb");

	// do_cryptFile(infile, outfile, ENCRYPT);
	// // do_crypt(outfile, infile, DECRYPT);

	// fclose(infile);
	// fclose(outfile);

	const char* msg = "Dies ist ein kleiner Test um zu schauen, ob das alles geklappt hat!";
	const unsigned char key[32] = {0x67, 0xCA, 0xB7, 0x5F, 0xDE, 0xAB, 0x2D, 0x72, 0xBD, 0x8D, 0xDA, 0xCD, 0xD5, 0x48, 0x0A, 0x1C, 0xD0, 0x37, 0x76, 0x45, 0x8F, 0xA2, 0x92, 0xAC, 0x87, 0x4D, 0xD3, 0xB1, 0x23, 0x43, 0xFC, 0x18};
	const unsigned char iv[16]  = {0x84, 0xA4, 0x36, 0x84, 0xE0, 0xD5, 0xFE, 0xBD, 0x34, 0x79, 0x16, 0x28, 0x09, 0xD4, 0xA1, 0xDC};

	unsigned char out[1000] = {0};

	size_t enc_data_len = do_crypt(msg, strlen(msg), out, sizeof(out), key, iv, ENCRYPT);
	if(enc_data_len < 0) {
		printf("Error!\n");
		return EXIT_FAILURE;
	}

	printf("ENC:\n");
	for(int i = 0; i < enc_data_len; i++) {
		printf("%02x", out[i]);
	}
	printf("\n");
	return EXIT_SUCCESS;
}

size_t do_crypt(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len, const unsigned char* key, const unsigned char* iv, int do_encrypt) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, enc_len;
    EVP_CIPHER_CTX *ctx;

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit_ex2(ctx, EVP_aes_256_cbc(), NULL, NULL,
                            do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
		printf("Error: EVP_CipherInit_ex2");
        return -1;
    }
    OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 32);
    OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
		printf("Error: EVP_CipherInit_ex2 + key&iv");
        return -1;
    }

	if (!EVP_CipherUpdate(ctx, outbuf, &outlen, in, in_len)) {
		/* Error */
		EVP_CIPHER_CTX_free(ctx);
		printf("Error: EVP_CipherUpdate");
		return -1;
	}

	// fwrite(outbuf, 1, outlen, out);
	for(int i = 0; i < outlen; i++) {
		out[enc_len++] = outbuf[i];
	}
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
		printf("Error: EVP_CipherFinal");
        return -1;
    }
    // fwrite(outbuf, 1, outlen, out);
	for(int i = 0; i < outlen; i++) {
		out[enc_len++] = outbuf[i];
	}

    EVP_CIPHER_CTX_free(ctx);
    return enc_len;
}

int do_cryptFile(FILE *in, FILE *out, int do_encrypt) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdeF0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit_ex2(ctx, EVP_aes_256_cbc(), NULL, NULL,
                            do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 32);
    OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    for (;;) {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}