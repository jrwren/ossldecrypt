#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

// #include "test.h"

// SESSIONIDHEX    = "BF6E711FD0E90D32FA321A60D6F3EE6054FDA65FFCBA09A08E51F2F812877346"
// 	MASTERKEYHEX    = "F98126522F5D22D7A67AD18032F15D9E6188DB95356445BF09C6B4045C95E9D2921778FEBC882ECED55E50D89758FF3A"
// 	SESSIONID       []byte
// 	MASTERKEY       []byte
// 	clientrandomhex = `fc42562e190b657a3670e9db1254da1ace91b93297e862a9e53212a5c745e743`
// 	clientrandom    []byte
// 	serverrandomhex = `18db3022a966ecea221160d6d94435116ed54d56dc1215d9ec294768592a2b18`
// 	serverrandom    []byte

unsigned char* input;
long input_len;

void test_direct_decrypt() {
    unsigned char buf[512];
    int howmany, res;
    long keylen, nonce_len, aead_len;
    unsigned char *key = OPENSSL_hexstr2buf("362ff749c2fdc2050a02f5ca6f1cd1de68db2987f4f18a0298e951eea424b8d7", &keylen);
    unsigned char *nonce = OPENSSL_hexstr2buf("032ac5870000000000000001", &nonce_len);
    unsigned char *aead = OPENSSL_hexstr2buf("00000000000000011703030164", &aead_len);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("test_direct_decrypt: EVP_CIPHER_CTX_new failed\n");
        return;
    }
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("test_direct_decrypt: EVP_DecryptInit error: %d\n",res);
    }
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL)) {
        printf("test_direct_decrypt: EVP_CIPHER_CTX_ctrl error: %d setting IVLEN %ld\n",res, nonce_len);
    }
    res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    if (!res) {
        printf("test_direct_decrypt: EVP_DecryptInit error: %d\n",res);
    }
    // ?? EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, ref_TAG); ?
    res = EVP_DecryptUpdate (ctx, NULL, &howmany, aead, aead_len);
    if (!res) {
        printf("test_direct_decrypt: EVP_DecryptInit error: %d\n",res);
    }
	// input = input[recordHeaderLen+8:]
    input = input + 8 + 5; //skip the nonce/seq
    res = EVP_DecryptUpdate (ctx, buf, &howmany, input, input_len);
    if (!res) {
        printf("test_direct_decrypt: EVP_DecryptInit 2 error: %d\n",res);
    }
    res = EVP_DecryptFinal_ex(ctx, buf+howmany, &howmany);
    if (res<=0) {
        printf("test_direct_decrypt: EVP_DecryptFinal_ex error: %d read %d\n", res, howmany);
    }
    char *expect = "GET /ipcheck.html HTTP/1.1";
    res = strncmp(expect, (char*)buf, strlen(expect));
    if (0!=res) {
        printf("test_direct_decrypt: FAIL, expect: %s, got %s\n", expect, buf);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    printf("got %s\n", buf);

    EVP_CIPHER_CTX_free(ctx);
}

void test_decrypt() {
    /*
    plaintext, err := Decrypt(VersionTLS12, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		true, MASTERKEY, clientrandom, serverrandom, input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(plaintext), `GET /ipcheck.html HTTP/1.1`) {
		t.Fatal("unexpected plaintext result", plaintext)
	}*/
}

void init() {
    // var err error
	// SESSIONID, err = hex.DecodeString(SESSIONIDHEX)
	// if err != nil {
	// 	panic(err)
	// }
	// MASTERKEY, err = hex.DecodeString(MASTERKEYHEX)
	// if err != nil {
	// 	panic(err)
	// }
    input = OPENSSL_hexstr2buf("170303017c00000000000000016aa6c1a007b04221ffe774fd4a3d666c49b34114951218e6700e6cd2608c956d53a60cb3183d62a0ef1a781986b83f39597a10b8dcfc5b24466a34705bb6889399512f4d87e39a8c29a51a6e3359b385290bcde3abba6c9af4d6ed7b9a8021e26d769e91e4b6960d836aaa60c5042dd7886a4bcb0890e5b499788a8128118e587313b21e94436c49ffcd976533c32b33d7dc6d6ab7be998fb7fdff90ac719d866b8e724dff68608191cf52392c278d3895f18422cfad423fa6bb6acd95481ef6da4e410da0a2a1b01d62489ad4cbd9cf1a4ceefe4e1922d5811d703b5621225195e68970e7e9b473864bcc4fb810e04ab3b877c146487b971ec77430a60864467eb7f47be5e8a509a7c80305272392b93085a33159dcfc5b505876288f926d494e5339b37c5ca90381f6d01ec79110c547bd2ed5b573606d87fc44d1ccc4e95c1b734c8da5d915129602e1acd137dfbde06ee2be48fd7c05480d67672027f4e03e81809e18734be5f9ba0d953cf16b44459a8e27",
        &input_len);
	// clientrandom, err = hex.DecodeString(clientrandomhex)
	// if err != nil {
	// 	panic(err)
	// }
	// serverrandom, err = hex.DecodeString(serverrandomhex)
	// if err != nil {
	// 	panic(err)
	// }
}

int main() {
    init();
    test_direct_decrypt();
    test_decrypt();
}
