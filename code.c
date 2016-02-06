#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	int read;
	fp = fopen("dictionary.txt", "r");
	if (fp == NULL) printf("failure");
	while ((read = getline(&line, &len, fp)) != -1) {
		unsigned char* key[16];
		unsigned char* output[1024];
		int outlen, tmplen;
		char * intext = NULL;
		size_t inputLen = 0;
		char * ciphertext = NULL;
		size_t cipherlen = 0;
		FILE * input;
		input = fopen("plaintext.txt", "r");
		getline(&intext, &inputLen, input);
		fclose(input);
		FILE * cipher;
		cipher = fopen("ciphertxt", "r");
		getline(&ciphertext, &cipherlen, cipher);
		fclose(cipher);
		size_t i;
		for (i = 0; i < read; ++i) {
			key[i] = &line[i];
		}
		while (read < 16) {
			char blah = ' ';
			key[read] = &blah;
			++read;
		}
		//for (i = 0; i < 16; ++i) {
		//	printf("%c\n", *key[i]);
		//}
		//printf("%s", *key);
		EVP_CIPHER_CTX *ctx;
		ctx = EVP_CIPHER_CTX_new();
		unsigned char iv[] = "0000000000000000";
		EVP_CipherInit_ex(ctx, EVP_idea_cbc(), NULL, *key, iv, 1);
		if (strlen(intext) == 21) {
			EVP_EncryptUpdate(ctx, *output, &outlen, intext, strlen(intext));
		}
		EVP_EncryptFinal_ex(ctx, *output + outlen, &tmplen);
		if (output == ciphertext) {
			printf("%s", *key); //correct key found
		}
		EVP_CIPHER_CTX_free(ctx);
		
	}
	fclose(fp);
}
