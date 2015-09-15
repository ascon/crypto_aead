#include <string.h>
#include <stdio.h>
#include "api.h"
#include "crypto_aead.h"

void print(unsigned char* name, unsigned char* var, unsigned long long len) {
  int i;
  printf("%s[%llu]=", name, len);
  for (i = 0; i < len; ++i)
    printf("%02x", var[i]);
}

int main() {
  unsigned long long alen = 0;
  unsigned long long mlen = 0;
  unsigned long long clen = CRYPTO_ABYTES;
  unsigned char a[] = "ASCON";
  unsigned char m[] = "ascon";
  unsigned char c[strlen(m) + CRYPTO_ABYTES];
  unsigned char nsec[CRYPTO_NSECBYTES];
  unsigned char npub[CRYPTO_NPUBBYTES] = { 0 };
  unsigned char k[CRYPTO_KEYBYTES] = { 0 };
  int r;
  alen = strlen(a);
  mlen = strlen(m);
  print("k", k, CRYPTO_KEYBYTES);
  printf(" ");
  print("n", npub, CRYPTO_NPUBBYTES);
  printf("\n");
  print("a", a, alen);
  printf(" ");
  print("m", m, mlen);
  printf(" -> ");
  crypto_aead_encrypt(c, &clen, m, mlen, a, alen, nsec, npub, k);
  print("c", c, clen - CRYPTO_ABYTES);
  printf(" ");
  print("t", c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
  printf(" -> ");
  r = crypto_aead_decrypt(m, &mlen, nsec, c, clen, a, alen, npub, k);
  print("a", a, alen);
  printf(" ");
  print("m", m, mlen);
  printf("\n");
  return r;
}
