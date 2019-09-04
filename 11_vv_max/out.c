#include <immintrin.h>

const char R0_INIT0[32] = {0x46, 0x4c, 0x41, 0x52, 0x45, 0x32, 0x30, 0x31, 0x39, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
const char R1_INIT0[32] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
const char R3_INIT0[32] = {0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1b, 0x1b, 0x1b, 0x1a, 0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1b, 0x1b, 0x1b, 0x1a};
const char R4_INIT0[32] = {0x10, 0x10, 0x1, 0x2, 0x4, 0x8, 0x4, 0x8, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1, 0x2, 0x4, 0x8, 0x4, 0x8, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10};
const char R5_INIT0[32] = {0x0, 0x10, 0x13, 0x4, 0xbf, 0xbf, 0xb9, 0xb9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x13, 0x4, 0xbf, 0xbf, 0xb9, 0xb9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
const char R6_INIT0[32] = {0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f};
const char R10_INIT0[32] = {0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1, 0x40, 0x1};
const char R11_INIT0[32] = {0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0, 0x0, 0x10, 0x1, 0x0};
const char R12_INIT0[32] = {0x2, 0x1, 0x0, 0x6, 0x5, 0x4, 0xa, 0x9, 0x8, 0xe, 0xd, 0xc, 0xff, 0xff, 0xff, 0xff, 0x2, 0x1, 0x0, 0x6, 0x5, 0x4, 0xa, 0x9, 0x8, 0xe, 0xd, 0xc, 0xff, 0xff, 0xff, 0xff};
const char R13_INIT0[32] = {0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const char R16_INIT0[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const char R17_INIT0[32] = {0x19, 0xcd, 0xe0, 0x5b, 0xab, 0xd9, 0x83, 0x1f, 0x8c, 0x68, 0x5, 0x9b, 0x7f, 0x52, 0xe, 0x51, 0x3a, 0xf5, 0x4f, 0xa5, 0x72, 0xf3, 0x6e, 0x3c, 0x85, 0xae, 0x67, 0xbb, 0x67, 0xe6, 0x9, 0x6a};
const char R18_INIT0[32] = {0xd5, 0x5e, 0x1c, 0xab, 0xa4, 0x82, 0x3f, 0x92, 0xf1, 0x11, 0xf1, 0x59, 0x5b, 0xc2, 0x56, 0x39, 0xa5, 0xdb, 0xb5, 0xe9, 0xcf, 0xfb, 0xc0, 0xb5, 0x91, 0x44, 0x37, 0x71, 0x98, 0x2f, 0x8a, 0x42};
const char R19_INIT0[32] = {0x4, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0};
const char R20_INIT0[32] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
const char R21_INIT0[32] = {0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0};
const char R22_INIT0[32] = {0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0};
const char R23_INIT0[32] = {0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0};
const char R24_INIT0[32] = {0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0};
const char R25_INIT0[32] = {0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0};
const char R26_INIT0[32] = {0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0};
const char R27_INIT0[32] = {0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0};
const char R19_INIT1[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
const char R31_INIT0[32] = {0x22, 0x1e, 0x1b, 0x4b, 0x2d, 0x17, 0x5, 0xc, 0x15, 0x59, 0xe, 0x78, 0x23, 0x26, 0x33, 0x2e, 0x10, 0x7, 0x4f, 0x73, 0x18, 0x36, 0x58, 0xb, 0x29, 0xf, 0x5c, 0x3a, 0xc, 0x62, 0x76, 0x21};

__m256i do_maddw(__m256i a, __m256i b) {
    int32_t intermediate[16] = {0};
    int32_t result[8] = {0};
    for (int i = 0; i < 16; ++i) {
        intermediate[i] = ((int16_t*)&a)[i] * ((int16_t*)&b)[i];
    }

    for (int i = 0; i < 8; ++i) {
        result[i] = intermediate[2*i] + intermediate[2*i + 1];
    }

    return _mm256_loadu_si256((__m256i const *)result);
}

int main(int argc, char **argv) {

    __m256i r0 = _mm256_setzero_si256();
    __m256i r1 = _mm256_setzero_si256();
    __m256i r2 = _mm256_setzero_si256();
    __m256i r3 = _mm256_setzero_si256();
    __m256i r4 = _mm256_setzero_si256();
    __m256i r5 = _mm256_setzero_si256();
    __m256i r6 = _mm256_setzero_si256();
    __m256i r7 = _mm256_setzero_si256();
    __m256i r8 = _mm256_setzero_si256();
    __m256i r9 = _mm256_setzero_si256();
    __m256i r10 = _mm256_setzero_si256();
    __m256i r11 = _mm256_setzero_si256();
    __m256i r12 = _mm256_setzero_si256();
    __m256i r13 = _mm256_setzero_si256();
    __m256i r14 = _mm256_setzero_si256();
    __m256i r15 = _mm256_setzero_si256();
    __m256i r16 = _mm256_setzero_si256();
    __m256i r17 = _mm256_setzero_si256();
    __m256i r18 = _mm256_setzero_si256();
    __m256i r19 = _mm256_setzero_si256();
    __m256i r20 = _mm256_setzero_si256();
    __m256i r21 = _mm256_setzero_si256();
    __m256i r22 = _mm256_setzero_si256();
    __m256i r23 = _mm256_setzero_si256();
    __m256i r24 = _mm256_setzero_si256();
    __m256i r25 = _mm256_setzero_si256();
    __m256i r26 = _mm256_setzero_si256();
    __m256i r27 = _mm256_setzero_si256();
    __m256i r28 = _mm256_setzero_si256();
    __m256i r29 = _mm256_setzero_si256();
    __m256i r30 = _mm256_setzero_si256();
    __m256i r31 = _mm256_setzero_si256();

    r0 = _mm256_loadu_si256((__m256i const *)R0_INIT0);
    r1 = _mm256_loadu_si256((__m256i const *)R1_INIT0);
    r3 = _mm256_loadu_si256((__m256i const *)R3_INIT0);
    r4 = _mm256_loadu_si256((__m256i const *)R4_INIT0);
    r5 = _mm256_loadu_si256((__m256i const *)R5_INIT0);
    r6 = _mm256_loadu_si256((__m256i const *)R6_INIT0);
    r10 = _mm256_loadu_si256((__m256i const *)R10_INIT0);
    r11 = _mm256_loadu_si256((__m256i const *)R11_INIT0);
    r12 = _mm256_loadu_si256((__m256i const *)R12_INIT0);
    r13 = _mm256_loadu_si256((__m256i const *)R13_INIT0);
    r16 = _mm256_loadu_si256((__m256i const *)R16_INIT0);
    r17 = _mm256_loadu_si256((__m256i const *)R17_INIT0);
    r18 = _mm256_loadu_si256((__m256i const *)R18_INIT0);
    r19 = _mm256_loadu_si256((__m256i const *)R19_INIT0);
    r20 = _mm256_loadu_si256((__m256i const *)R20_INIT0);
    r21 = _mm256_loadu_si256((__m256i const *)R21_INIT0);
    r22 = _mm256_loadu_si256((__m256i const *)R22_INIT0);
    r23 = _mm256_loadu_si256((__m256i const *)R23_INIT0);
    r24 = _mm256_loadu_si256((__m256i const *)R24_INIT0);
    r25 = _mm256_loadu_si256((__m256i const *)R25_INIT0);
    r26 = _mm256_loadu_si256((__m256i const *)R26_INIT0);
    r27 = _mm256_loadu_si256((__m256i const *)R27_INIT0);
    r20 = _mm256_permutevar8x32_epi32(r0, r20);
    r21 = _mm256_permutevar8x32_epi32(r0, r21);
    r22 = _mm256_permutevar8x32_epi32(r0, r22);
    r23 = _mm256_permutevar8x32_epi32(r0, r23);
    r24 = _mm256_permutevar8x32_epi32(r0, r24);
    r25 = _mm256_permutevar8x32_epi32(r0, r25);
    r26 = _mm256_permutevar8x32_epi32(r0, r26);
    r27 = _mm256_permutevar8x32_epi32(r0, r27);
    r7 = _mm256_srli_epi32(r1, 0x4);
    r28 = _mm256_xor_si256(r20, r21);
    r28 = _mm256_xor_si256(r28, r22);
    r28 = _mm256_xor_si256(r28, r23);
    r28 = _mm256_xor_si256(r28, r24);
    r28 = _mm256_xor_si256(r28, r25);
    r28 = _mm256_xor_si256(r28, r26);
    r28 = _mm256_xor_si256(r28, r27);
    r7 = _mm256_and_si256(r7, r6);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r8 = _mm256_cmpeq_epi8(r1, r6);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r8 = _mm256_cmpeq_epi8(r1, r6);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_xor_si256(r20, r16);
    r30 = _mm256_and_si256(r20, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r20 = _mm256_add_epi32(r15, r0);
    r7 = _mm256_add_epi8(r8, r7);
    r29 = _mm256_xor_si256(r20, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r7 = _mm256_shuffle_epi8(r5, r7);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r2 = _mm256_add_epi8(r1, r7);
    r29 = _mm256_xor_si256(r21, r16);
    r30 = _mm256_and_si256(r21, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r21 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r21, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r21);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r7 = _mm256_maddubs_epi16(r2, r10);
    r29 = _mm256_xor_si256(r22, r16);
    r30 = _mm256_and_si256(r22, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r22 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r22, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r22);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r2 = do_maddw(r7, r11);
    r29 = _mm256_xor_si256(r23, r16);
    r30 = _mm256_and_si256(r23, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r23 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r23, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r23);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_xor_si256(r24, r16);
    r30 = _mm256_and_si256(r24, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r24 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r24, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r24);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_xor_si256(r25, r16);
    r30 = _mm256_and_si256(r25, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r25 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r25, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r25);
    r2 = _mm256_shuffle_epi8(r2, r12);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_xor_si256(r26, r16);
    r30 = _mm256_and_si256(r26, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r26 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r26, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r26);
    r29 = _mm256_slli_epi32(r17, 0x7);
    r30 = _mm256_srli_epi32(r17, 0x19);
    r15 = _mm256_or_si256(r29, r30);
    r29 = _mm256_slli_epi32(r17, 0x15);
    r30 = _mm256_srli_epi32(r17, 0xb);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r29 = _mm256_slli_epi32(r17, 0x1a);
    r30 = _mm256_srli_epi32(r17, 0x6);
    r29 = _mm256_or_si256(r29, r30);
    r15 = _mm256_xor_si256(r15, r29);
    r2 = _mm256_permutevar8x32_epi32(r2, r13);
    r29 = _mm256_xor_si256(r27, r16);
    r30 = _mm256_and_si256(r27, r18);
    r29 = _mm256_xor_si256(r29, r30);
    r15 = _mm256_add_epi32(r29, r15);
    r27 = _mm256_add_epi32(r15, r0);
    r29 = _mm256_xor_si256(r27, r28);
    r17 = _mm256_permutevar8x32_epi32(r29, r19);
    r20 = _mm256_xor_si256(r20, r27);
    r19 = _mm256_loadu_si256((__m256i const *)R19_INIT1);
    r20 = _mm256_and_si256(r20, r19);
    r31 = _mm256_loadu_si256((__m256i const *)R31_INIT0);

    __m256i cmpresult = _mm256_cmpeq_epi8(r2, r20);
    int32_t result = _mm256_movemask_epi8(cmpresult);

    if (result == -1) {
        return 0;
    } else {
        return 1;
    }

}
