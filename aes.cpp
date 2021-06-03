#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include "aes_table.h"
clock_t start_time, end_time;
u32 byte_unite(u8 b0, u8 b1, u8 b2, u8 b3) {
    //将四个拼接在一起
    u32 block = b0;
    block = (block << 8);
    block += b1;
    block = (block << 8);
    block += b2;
    block = (block << 8);
    block += b3;
    return block;
}
void input_format_128(const char *in, u8 *out){
    //
    for(int i=0; i<16; i++){
        char temp[3]={in[2*i],in[2*i+1]};
        char *ptr;
        out[i]=(u8)(strtol(temp,&ptr,16));
    }
}
void output_format_128(const u8 *in, char *out){
    for(int i=0; i<16; i++){
        char temp[3];
        sprintf(temp,"%02X",in[i]);
        strcat(out,temp);
    }
}

void state_unite(u8 *out, u32 in) {
    //输出的格式化
    out[0] = (u8) ((in) >> 24);
    out[1] = (u8) ((in) >> 16);
    out[2] = (u8) ((in) >> 8);
    out[3] = (u8) (in);
}

void generate_key(const u8 *passwd, u32 *keys) {
    //密钥拓展
    //第一轮
    keys[0] = byte_unite(passwd[0], passwd[1], passwd[2], passwd[3]);
    keys[1] = byte_unite(passwd[4], passwd[5], passwd[6], passwd[7]);
    keys[2] = byte_unite(passwd[8], passwd[9], passwd[10], passwd[11]);
    keys[3] = byte_unite(passwd[12], passwd[13], passwd[14], passwd[15]);
    //剩余10轮
    for (int i = 1; i < 11; i++) {
        u32 temp = keys[4 * (i - 1) + 3];
        keys[4 * i] =
                keys[4 * (i - 1)] ^ (Te2[(temp >> 16) & 0xff] & 0xff000000) ^ (Te3[(temp >> 8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp) & 0xff] & 0x0000ff00) ^ (Te1[(temp >> 24)] & 0x000000ff) ^ rcon[i - 1];
        keys[4 * i + 1] = keys[4 * (i - 1) + 1] ^ keys[4 * i];
        keys[4 * i + 2] = keys[4 * (i - 1) + 2] ^ keys[4 * i + 1];
        keys[4 * i + 3] = keys[4 * (i - 1) + 3] ^ keys[4 * i + 2];
    }
}

void swap(u32 *a, u32 *b) {
    u32 temp = *a;
    *a = *b;
    *b = temp;
}

void generate_inv_keys(const u8 *passwd, u32 *keys) {
    generate_key(passwd, keys);
    //交换顺序
    for (int i = 0, j = 40; i < j; i += 4, j -= 4) {
        swap(&keys[i], &keys[j]);
        swap(&keys[i + 1], &keys[j + 1]);
        swap(&keys[i + 2], &keys[j + 2]);
        swap(&keys[i + 3], &keys[j + 3]);
    }
    //提前修改以适应逆MixColumn等顺序改变
    for (int i = 1; i < 10; i++) {
        keys[4 * i] = Td0[Te1[(keys[4 * i] >> 24)] & 0xff] ^ Td1[Te1[(keys[4 * i] >> 16) & 0xff] & 0xff] ^
                      Td2[Te1[(keys[4 * i] >> 8) & 0xff] & 0xff] ^ Td3[Te1[(keys[4 * i]) & 0xff] & 0xff];
        keys[4 * i + 1] = Td0[Te1[(keys[4 * i + 1] >> 24)] & 0xff] ^ Td1[Te1[(keys[4 * i + 1] >> 16) & 0xff] & 0xff] ^
                          Td2[Te1[(keys[4 * i + 1] >> 8) & 0xff] & 0xff] ^ Td3[Te1[(keys[4 * i + 1]) & 0xff] & 0xff];
        keys[4 * i + 2] = Td0[Te1[(keys[4 * i + 2] >> 24)] & 0xff] ^ Td1[Te1[(keys[4 * i + 2] >> 16) & 0xff] & 0xff] ^
                          Td2[Te1[(keys[4 * i + 2] >> 8) & 0xff] & 0xff] ^ Td3[Te1[(keys[4 * i + 2]) & 0xff] & 0xff];
        keys[4 * i + 3] = Td0[Te1[(keys[4 * i + 3] >> 24)] & 0xff] ^ Td1[Te1[(keys[4 * i + 3] >> 16) & 0xff] & 0xff] ^
                          Td2[Te1[(keys[4 * i + 3] >> 8) & 0xff] & 0xff] ^ Td3[Te1[(keys[4 * i + 3]) & 0xff] & 0xff];
    }
}

void aes_enc(const u8 *in, u8 *out, const u32 *keys) {
    //aes 加密函数
    //第一轮
    u32 s0 = byte_unite(in[0], in[1], in[2], in[3]) ^ keys[0];
    u32 s1 = byte_unite(in[4], in[5], in[6], in[7]) ^ keys[1];
    u32 s2 = byte_unite(in[8], in[9], in[10], in[11]) ^ keys[2];
    u32 s3 = byte_unite(in[12], in[13], in[14], in[15]) ^ keys[3];
    u32 t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    //第2-10轮
    for (int i = 1; i < 10; i++) {
        t0 = Te0[(s0 >> 24)] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[(s3) & 0xff] ^ keys[4 * i];
        t1 = Te0[(s1 >> 24)] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[(s0) & 0xff] ^ keys[4 * i + 1];
        t2 = Te0[(s2 >> 24)] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[(s1) & 0xff] ^ keys[4 * i + 2];
        t3 = Te0[(s3 >> 24)] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[(s2) & 0xff] ^ keys[4 * i + 3];

        s0 = t0, s1 = t1, s2 = t2, s3 = t3;
    }
    //最后一轮的特殊处理（顺便输出）
    s0 = (Te2[(t0 >> 24)] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
         (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t3) & 0xff] & 0x000000ff) ^ keys[40];
    state_unite(out, s0);
    s1 = (Te2[(t1 >> 24)] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
         (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t0) & 0xff] & 0x000000ff) ^ keys[41];
    state_unite(out + 4, s1);
    s2 = (Te2[(t2 >> 24)] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
         (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t1) & 0xff] & 0x000000ff) ^ keys[42];
    state_unite(out + 8, s2);
    s3 = (Te2[(t3 >> 24)] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
         (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t2) & 0xff] & 0x000000ff) ^ keys[43];
    state_unite(out + 12, s3);
}

void aes_dec(const u8 *in, u8 *out, const u32 *keys) {
    //第一轮密钥异或
    u32 s0 = byte_unite(in[0], in[1], in[2], in[3]) ^ keys[0];
    u32 s1 = byte_unite(in[4], in[5], in[6], in[7]) ^ keys[1];
    u32 s2 = byte_unite(in[8], in[9], in[10], in[11]) ^ keys[2];
    u32 s3 = byte_unite(in[12], in[13], in[14], in[15]) ^ keys[3];
    u32 t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    //中间10轮
    for (int i = 1; i < 10; i++) {
        t0 = Td0[(s0 >> 24)] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[(s1) & 0xff] ^ keys[4 * i];
        t1 = Td0[(s1 >> 24)] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[(s2) & 0xff] ^ keys[4 * i + 1];
        t2 = Td0[(s2 >> 24)] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[(s3) & 0xff] ^ keys[4 * i + 2];
        t3 = Td0[(s3 >> 24)] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[(s0) & 0xff] ^ keys[4 * i + 3];
        s0 = t0, s1 = t1, s2 = t2, s3 = t3;
    }
    //最后一轮特殊处理
    s0 = (Td4[(t0 >> 24)] << 24) ^ (Td4[(t3 >> 16) & 0xff] << 16) ^ (Td4[(t2 >> 8) & 0xff] << 8) ^ (Td4[(t1) & 0xff]) ^
         keys[40];
    state_unite(out, s0);
    s1 = (Td4[(t1 >> 24)] << 24) ^ (Td4[(t0 >> 16) & 0xff] << 16) ^ (Td4[(t3 >> 8) & 0xff] << 8) ^ (Td4[(t2) & 0xff]) ^
         keys[41];
    state_unite(out + 4, s1);
    s2 = (Td4[(t2 >> 24)] << 24) ^ (Td4[(t1 >> 16) & 0xff] << 16) ^ (Td4[(t0 >> 8) & 0xff] << 8) ^ (Td4[(t3) & 0xff]) ^
         keys[42];
    state_unite(out + 8, s2);
    s3 = (Td4[(t3 >> 24)] << 24) ^ (Td4[(t2 >> 16) & 0xff] << 16) ^ (Td4[(t1 >> 8) & 0xff] << 8) ^ (Td4[(t0) & 0xff]) ^
         keys[43];
    state_unite(out + 12, s3);

}
double aes_enc_str_time(const char *passwd, const char *plain){
    // 用于计时的函数
    u8 passwd_bytes[16],plain_bytes[16],cipher[16];
    input_format_128(passwd,passwd_bytes);
    input_format_128(plain,plain_bytes);
    u32 keys[44];
    start_time=clock();
    generate_key(passwd_bytes,keys);
    aes_enc(plain_bytes,cipher,keys);
    end_time=clock();
    //output_format_128(cipher,result);
    //printf("%s",result);
    double cost=(double)(end_time-start_time)/CLOCKS_PER_SEC;
    return cost;
}
void aes_enc_str(const char *passwd, const char *plain){
    //aes加密函数
    u8 passwd_bytes[16],plain_bytes[16],cipher[16];
    char result[64];
    input_format_128(passwd,passwd_bytes);
    input_format_128(plain,plain_bytes);
    u32 keys[44];
    generate_key(passwd_bytes,keys);
    aes_enc(plain_bytes,cipher,keys);
    output_format_128(cipher,result);
    printf("%s\n",result);
}
void aes_dec_str(const char *passwd, const char *cipher){
    //aes解密函数
    u8 passwd_bytes[16],cipher_bytes[16],plain[16];
    char result[64];
    input_format_128(passwd,passwd_bytes);
    input_format_128(cipher,cipher_bytes);
    u32 keys[44];
    generate_inv_keys(passwd_bytes,keys);
    aes_dec(cipher_bytes,plain,keys);
    output_format_128(plain,result);
    printf("%s\n",result);
}
int main() {
    double sum=0.0;
    for(int i=0;i<10000;i++){
        sum+= aes_enc_str_time("3475bd76ffba4ec67020f1573ed28b47d7286d298a040b73f521ffcd9de93f24", "1b5e8b0f1bc78d238064826704830cdb");
    }
    printf("%lf s\n",sum);
    aes_enc_str("3475bd76fa040b73f521ffcd9de93f24", "1b5e8b0f1bc78d238064826704830cdb");
    aes_dec_str("2b24424b9fed596659842a4d0b007c61","fba4ec67020f1573ed28b47d7286d298");
}