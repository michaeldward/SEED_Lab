#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	int read;
	printf("hi");
	fp = fopen("dictionary.txt", "r");
	if (fp == NULL) printf("failure");
	while ((read = getline(&line, &len, fp)) != -1) {
		unsigned char* key[16];
		unsigned char* output[1024];
		int outlen, tmplen;
		char intext = "This is a top secret.";
		size_t i;
		for (i = 0; i < read; ++i) {
			key[i] = &line[i];
		}
		while (read < 16) {
			char blah = ' ';
			key[read] = &blah;
			++read;
		}
		for (i = 0; i < 16; ++i) {
			printf("%c\n", *key[i]);
		}
		printf("%s", *key);
		EVP_CIPHER_CTX *ctx;
		ctx = EVP_CIPHER_CTX_new();
		unsigned char iv[] = "0000000000000000";
		//OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
		//OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
		EVP_CipherInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv, 1);
		EVP_EncryptUpdate(ctx, &output, &outlen, &intext, 21);
		EVP_EncryptFinal_ex(ctx, output + outlen, &tmplen);
		EVP_CIPHER_CTX_free(ctx);
	}
	fclose(fp);
	//EVP_CIPHER_CTX *ctx;
	//unsigned char iv[] = "0000000000000000";
	//EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
	//OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	//OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
	//EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);
	//return 0;
}
