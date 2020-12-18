
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

static int keymatexportlen = 20;

static int tls1_PRF_EVP(const EVP_MD *md, const char *seed1, size_t seed1_len,
                        const char *seed2, size_t seed2_len, const char *seed3,
                        size_t seed3_len, const char *seed4, size_t seed4_len,
                        const char *seed5, size_t seed5_len,
                        const unsigned char *sec, size_t slen,
                        unsigned char *out, size_t olen) {
  EVP_PKEY_CTX *pctx = NULL;
  int ret = 0;

  if (md == NULL) {
    return -1;
  }
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
  if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0 ||
      EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0 ||
      EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0 ||
      EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0 ||
      EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0 ||
      EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0 ||
      EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0 ||
      EVP_PKEY_derive(pctx, out, &olen) <= 0) {
    ret = -2;
    goto err;
  }

  ret = 1;

err:
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

int tls1_export_keying_material(const EVP_MD *md,
                                const unsigned char *client_random,
                                const unsigned char *server_random,
                                const unsigned char *master_key,
                                int master_key_length, unsigned char *out,
                                size_t olen, const char *label, size_t llen,
                                const unsigned char *context, size_t contextlen,
                                int use_context) {
  unsigned char *val = NULL;
  size_t vallen = 0, currentvalpos;
  int rv;

  /*
   * construct PRF arguments we construct the PRF argument ourself rather
   * than passing separate values into the TLS PRF to ensure that the
   * concatenation of values does not create a prohibited label.
   */
  vallen = llen + SSL3_RANDOM_SIZE * 2;
  if (use_context) {
    vallen += 2 + contextlen;
  }

  val = OPENSSL_malloc(vallen);
  if (val == NULL)
    goto err2;
  currentvalpos = 0;
  memcpy(val + currentvalpos, (unsigned char *)label, llen);
  currentvalpos += llen;
  memcpy(val + currentvalpos, client_random, SSL3_RANDOM_SIZE);
  currentvalpos += SSL3_RANDOM_SIZE;
  memcpy(val + currentvalpos, server_random, SSL3_RANDOM_SIZE);
  currentvalpos += SSL3_RANDOM_SIZE;

  if (use_context) {
    val[currentvalpos] = (contextlen >> 8) & 0xff;
    currentvalpos++;
    val[currentvalpos] = contextlen & 0xff;
    currentvalpos++;
    if ((contextlen > 0) || (context != NULL)) {
      memcpy(val + currentvalpos, context, contextlen);
    }
  }

  /*
   * disallow prohibited labels note that SSL3_RANDOM_SIZE > max(prohibited
   * label len) = 15, so size of val > max(prohibited label len) = 15 and
   * the comparisons won't have buffer overflow
   */
  if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
             TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0)
    goto err1;
  if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
             TLS_MD_SERVER_FINISH_CONST_SIZE) == 0)
    goto err1;
  if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
             TLS_MD_MASTER_SECRET_CONST_SIZE) == 0)
    goto err1;
  if (memcmp(val, TLS_MD_EXTENDED_MASTER_SECRET_CONST,
             TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE) == 0)
    goto err1;
  if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
             TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0)
    goto err1;

  rv = tls1_PRF_EVP(md, val, vallen, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                    master_key, master_key_length, out, olen);

  goto ret;
err1:
  SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL, SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
  rv = 0;
  goto ret;
err2:
  SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL, ERR_R_MALLOC_FAILURE);
  rv = 0;
ret:
  OPENSSL_clear_free(val, vallen);
  return rv;
}

int keys_from_master_secret(int tls_ver, int ciphersuite,
                            const char *master_secret, int master_secret_len,
                            char *client_random, char *server_random, int ivLen,
                            char *client_mac, char *server_mac, int *mac_len,
                            char *client_key, char *server_key, char *client_iv,
                            char *server_iv, int *iv_len) {
  int res = 0;
  // TODO: prf based on tls_ver
  // TODO: md based on ciphersuite
  // TODO: mac & iv based on ciphersuite
  *iv_len = 12;
  int keylen = 8;
  *mac_len = 0;
  const EVP_MD *md = EVP_sha384(); // TLS1_PRF_SHA384 ?
  unsigned char *exportedkeymat = malloc(keymatexportlen);
  //  tls1_export_keying_material
  if (!tls1_export_keying_material(
          md, client_random, server_random, master_secret, master_secret_len,
          exportedkeymat, keymatexportlen, NULL, 0, NULL, 0, 0)) {
    return -1;
  }
  // IS KM now the same as expected keyMasterial?

  printf("expected: ");
  for (int i = 0; i < keymatexportlen; i++) {
    printf("%x", exportedkeymat[i]);
  }
  printf(" %d", keymatexportlen);
  printf("\n");
  // clientMAC = keyMaterial[:macLen]
  // keyMaterial = keyMaterial[macLen:]
  client_mac = exportedkeymat;
  exportedkeymat += *mac_len;
  // serverMAC = keyMaterial[:macLen]
  // keyMaterial = keyMaterial[macLen:]
  server_mac = exportedkeymat;
  exportedkeymat += *mac_len;
  // clientKey = keyMaterial[:keyLen]
  // keyMaterial = keyMaterial[keyLen:]
  client_key = exportedkeymat;
  exportedkeymat += keylen;
  // serverKey = keyMaterial[:keyLen]
  // keyMaterial = keyMaterial[keyLen:]
  server_key = exportedkeymat + keylen;
  exportedkeymat += keylen;
  // clientIV = keyMaterial[:ivLen]
  // keyMaterial = keyMaterial[ivLen:]
  client_iv = exportedkeymat;
  exportedkeymat += *iv_len;
  // serverIV = keyMaterial[:ivLen]
  server_iv = exportedkeymat;
  return 0;
}

int decrypt(int tls_ver, int ciphersuite, int isclient,
            const char *master_secret, long mastersecret_len,
            const char *clientrandom, const char *serverrandom,
            unsigned const char *input, long input_len, unsigned char *out,
            int *out_len) {
  int res;
  unsigned char *key, *aead, *client_key, *server_key, *client_iv, *server_iv,
      *client_mac, *server_mac, *iv;
  int aead_len, iv_len, howmany;
  int mac_len = 0;
  unsigned char buf[4096]; // malloc an input length?
  out = buf;
  // TODO check serverrandom_len == SSL3_RANDOM_SIZE and clientrandom_len ==
  // SSL3_RANDOM_SIZE
  int ivLen = 12;
  res = keys_from_master_secret(
      tls_ver, ciphersuite, master_secret, mastersecret_len, clientrandom,
      serverrandom, ivLen, client_mac, server_mac, &mac_len, client_key,
      server_key, client_iv, server_iv, &iv_len);
  if (res < 0) {
    return -10;
  }
  printf("client_key: ");
  for (int i = 0; i < 8; i++) {
    printf("%x", client_key[i]);
  }
  printf(" server_key: ");
  for (int i = 0; i < 8; i++) {
    printf("%x", server_key[i]);
  }
  printf("\n");
  if (isclient) {
    key = client_key;
    iv = client_iv;
  } else {
    key = server_key;
    iv = server_iv;
  }
  // TODO: lookup the cipher based on ciphersuite.
  const EVP_CIPHER *cipher = EVP_aes_256_gcm();

  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return -1;
  }
  if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
    return -2;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
    return -3;
  }
  res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
  if (!res) {
    return -4;
  }
  // ?? EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, ref_TAG); ?
  res = EVP_DecryptUpdate(ctx, NULL, &howmany, aead, aead_len);
  if (!res) {
    return -5;
  }
  // input = input[recordHeaderLen+8:]
  input = input + 8 + 5; // skip the nonce/seq
  res = EVP_DecryptUpdate(ctx, out, &howmany, input, input_len);
  if (!res) {
    return -6;
  }
  res = EVP_DecryptFinal_ex(ctx, out + howmany, &howmany);
  if (res <= 0) {
    return -7;
  }
  return 0;
}