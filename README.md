examples of decrypting a TLS block using openssl

To run on my mac:
export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CFLAGS="-I/usr/local/opt/openssl@1.1/include"
export LDLIBS=-lcrypto
make test && ./test
