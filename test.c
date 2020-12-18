
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "decrypt.h"

unsigned char *sessionid;
long sessionid_len;
unsigned char *masterkey;
long masterkey_len;
unsigned char *clientrandom;
long clientrandom_len;
unsigned char *serverrandom;
long serverrandom_len;
unsigned char *input;
long input_len;
int DEBUG = 0;

void test_direct_decrypt() {
  unsigned char buf[512];
  int howmany, res;
  long keylen, nonce_len, aead_len;
  unsigned char *key = OPENSSL_hexstr2buf(
      "362ff749c2fdc2050a02f5ca6f1cd1de68db2987f4f18a0298e951eea424b8d7",
      &keylen);
  unsigned char *nonce =
      OPENSSL_hexstr2buf("032ac5870000000000000001", &nonce_len);
  unsigned char *aead =
      OPENSSL_hexstr2buf("00000000000000011703030164", &aead_len);
  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    printf("test_direct_decrypt: EVP_CIPHER_CTX_new failed\n");
    return;
  }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    printf("test_direct_decrypt: EVP_DecryptInit error: %d\n", res);
  }
  //   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL)) {
  //     printf("test_direct_decrypt: EVP_CIPHER_CTX_ctrl error: %d setting
  //     IVLEN "
  //            "%ld\n",
  //            res, nonce_len);
  //   }
  res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
  if (!res) {
    printf("test_direct_decrypt: EVP_DecryptInit error: %d\n", res);
  }
  // ?? EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, ref_TAG); ?
  res = EVP_DecryptUpdate(ctx, NULL, &howmany, aead, aead_len);
  if (!res) {
    printf("test_direct_decrypt: EVP_DecryptInit error: %d\n", res);
  }
  // input = input[recordHeaderLen+8:]
  input = input + 8 + 5; // skip the nonce/seq
  res = EVP_DecryptUpdate(ctx, buf, &howmany, input, input_len);
  if (!res) {
    printf("test_direct_decrypt: EVP_DecryptInit 2 error: %d\n", res);
  }
  res = EVP_DecryptFinal_ex(ctx, buf + howmany, &howmany);
  if (res <= 0) {
    printf("test_direct_decrypt: EVP_DecryptFinal_ex error: %d read %d\n", res,
           howmany);
  }
  char *expect = "GET /ipcheck.html HTTP/1.1";
  res = strncmp(expect, (char *)buf, strlen(expect));
  if (0 != res) {
    printf("test_direct_decrypt: FAIL, expect: %s, got %s\n", expect, buf);
    EVP_CIPHER_CTX_free(ctx);
    return;
  }
  if (DEBUG > 0)
    printf("test_direct_decrypt: got %s\n", buf);

  EVP_CIPHER_CTX_free(ctx);
}

void test_decrypt() {
  int out_len;
  char *out;
  int res = decrypt(TLS1_2_VERSION, TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    1, masterkey, masterkey_len, clientrandom, serverrandom,
                    input, input_len, out, &out_len);
  if (res) {
    printf("test_decrypt: FAIL: %d\n", res);
    return;
  }
  char *expect = "GET /ipcheck.html HTTP/1.1";
  res = strncmp(expect, (char *)out, strlen(expect));
  if (0 != res) {
    printf("test_decrypt: FAIL, expect: %s, got %s\n", expect, out);
    return;
  }
  /*
plaintext, err := Decrypt(VersionTLS12,
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, MASTERKEY, clientrandom,
serverrandom, input) if err != nil { t.Fatal(err)
}
if !strings.HasPrefix(string(plaintext), `GET /ipcheck.html HTTP/1.1`) {
        t.Fatal("unexpected plaintext result", plaintext)
}*/
}

void init() {
  const char *debug = getenv("DEBUG");
  if (debug != NULL && strlen(debug) > 0)
    DEBUG = atoi(debug);

  sessionid = OPENSSL_hexstr2buf(
      "BF6E711FD0E90D32FA321A60D6F3EE6054FDA65FFCBA09A08E51F2F812877346",
      &sessionid_len);
  masterkey =
      OPENSSL_hexstr2buf("F98126522F5D22D7A67AD18032F15D9E6188DB95356445BF09C6B"
                         "4045C95E9D2921778FEBC882ECED55E50D89758FF3A",
                         &masterkey_len);
  clientrandom = OPENSSL_hexstr2buf(
      "fc42562e190b657a3670e9db1254da1ace91b93297e862a9e53212a5c745e743",
      &clientrandom_len);
  if (SSL3_RANDOM_SIZE != strlen(clientrandom)) {
    fprintf(stderr, "client random unexpected size\n");
  }
  serverrandom = OPENSSL_hexstr2buf(
      "18db3022a966ecea221160d6d94435116ed54d56dc1215d9ec294768592a2b18",
      &serverrandom_len);
  if (SSL3_RANDOM_SIZE != strlen(serverrandom)) {
    fprintf(stderr, "server random unexpected size\n");
  }
  input = OPENSSL_hexstr2buf(
      "170303017c00000000000000016aa6c1a007b04221ffe774fd4a3d666c49b34114951218"
      "e6700e6cd2608c956d53a60cb3183d62a0ef1a781986b83f39597a10b8dcfc5b24466a34"
      "705bb6889399512f4d87e39a8c29a51a6e3359b385290bcde3abba6c9af4d6ed7b9a8021"
      "e26d769e91e4b6960d836aaa60c5042dd7886a4bcb0890e5b499788a8128118e587313b2"
      "1e94436c49ffcd976533c32b33d7dc6d6ab7be998fb7fdff90ac719d866b8e724dff6860"
      "8191cf52392c278d3895f18422cfad423fa6bb6acd95481ef6da4e410da0a2a1b01d6248"
      "9ad4cbd9cf1a4ceefe4e1922d5811d703b5621225195e68970e7e9b473864bcc4fb810e0"
      "4ab3b877c146487b971ec77430a60864467eb7f47be5e8a509a7c80305272392b93085a3"
      "3159dcfc5b505876288f926d494e5339b37c5ca90381f6d01ec79110c547bd2ed5b57360"
      "6d87fc44d1ccc4e95c1b734c8da5d915129602e1acd137dfbde06ee2be48fd7c05480d67"
      "672027f4e03e81809e18734be5f9ba0d953cf16b44459a8e27",
      &input_len);
}

int main() {
  init();
  if (DEBUG) {
    printf("test_direct_decrypt\n");
  }
  test_direct_decrypt();

  if (DEBUG) {
    printf("test_decrypt\n");
  }
  test_decrypt();
  // TODO: an example using EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS
  // and EVP_CTRL_SET_PIPELINE_INPUT_BUFS
}
