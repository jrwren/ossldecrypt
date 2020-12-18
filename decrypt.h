
int decrypt(int tlsver, int ciphersuite, int isclient,
            const unsigned char *masterkey, long masterkey_len,
            const unsigned char *clientrandom,
            const unsigned char *serverrandom,
            const unsigned char *input, long input_len, unsigned char *out, int *outlen);