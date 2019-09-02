#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*cipher_fun)(unsigned int, uint32_t[2], const uint32_t[4]);

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
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
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <1 (encrypt) | 0 (decrypt)> <input file> <output file>\n", argv[0]);
    return 1;
  }

  int arg1 = atoi(argv[1]);
  if (arg1 != 0 && arg1 != 1) {
    fprintf(stderr, "First argument must be 0 or 1\n");
    return 1;
  }

  FILE *f = fopen(argv[2], "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *pbuf = malloc(fsize);
  fread(pbuf, 1, fsize, f);
  fclose(f);

  const uint32_t key[4] = {0, 0, 0, 0};

  cipher_fun cipher = arg1 == 0 ? decipher : encipher;

  for (int i = 0; i < fsize/8; ++i) {
    cipher(0x20, (uint32_t *)(pbuf + (i*8)), key);
  }

  f = fopen(argv[3], "wb");
  fwrite(pbuf, 1, fsize, f);
  fclose(f);

  return 0;
}
