#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//hexlify from https://stackoverflow.com/a/50629682/756104
int a2v(char c)
{
    if ((c >= '0') && (c <= '9'))
    {
        return c - '0';
    }
    if ((c >= 'a') && (c <= 'f'))
    {
        return c - 'a' + 10;
    }
    else return 0;
}

char v2a(int c)
{
    const char hex[] = "0123456789abcdef";
    return hex[c];
}

char *unhexlify(char *hstr)
{
    char *bstr = malloc((strlen(hstr) / 2) + 1);
    char *pbstr = bstr;
    for (int i = 0; i < strlen(hstr); i += 2)
    {
        char c = (a2v(hstr[i]) << 4) + a2v(hstr[i + 1]);
        if (c == 0) {
            *pbstr++ = -128;
        } else {
            *pbstr++ = c;
        }
    }
    *pbstr++ = '\0';
    return bstr;
}

char *hexlify(char *bstr, size_t n)
{
    char *hstr = malloc((n * 2) + 1);
    char *phstr = hstr;
    for (size_t i = 0; i < n; i++)
    {
      *phstr++ = v2a((bstr[i] >> 4) & 0x0F);
      *phstr++ = v2a((bstr[i]) & 0x0F);
    }
    *phstr++ = '\0';
    return hstr;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

int main(int argc, char *argv[]) {
  uint32_t key[4] = {0x31, 0, 0, 0};

  for (uint32_t fst = 0; fst < 0x100; ++fst) {
    for (uint32_t snd = 0; snd < 0x100; ++snd) {
      for (uint32_t thrd = 0; thrd < 0x100; ++thrd) {
        key[1] = fst;
        key[2] = snd;
        key[3] = thrd;
        uint8_t ciphertext[8] = {0x24, 0x8e, 0xb0, 0x50, 0xe8, 0xb2, 0x68, 0x6f};
        decipher(0x20, (uint32_t *)ciphertext, key);
        if (memcmp(ciphertext, "GIF8", 4) == 0
            && (ciphertext[4] == '7' || ciphertext[4] == '9')
            && ciphertext[5] == 'a') {
          char kc[4] = {(char)key[0], (char)key[1], (char)key[2], (char)key[3]};
          char *kstr = hexlify(kc, 4);
          printf("Potential match: %s\n", kstr);
          free(kstr);
        }
      }
    }
  }

  return 0;
}
