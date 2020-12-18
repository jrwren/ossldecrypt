
char *decrypt(int tlsver, int ciphersuite, int isclient, const char *masterkey,
              long masterkey_len, const char *clientrandom,
              long clientrandom_len, const char *serverrandom,
              long serverrandom_len, const char *input, long input_len);