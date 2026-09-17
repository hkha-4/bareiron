#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "globals.h"
#include "packets.h"
#include "procedures.h"
#include "tools.h"
#include "varnum.h"
#include "velocity_config.h"

#ifdef ENABLE_VELOCITY_FORWARDING

#define VELOCITY_CHANNEL "velocity:player_info"
#define VELOCITY_MAX_FORWARD_SIZE 4096

int __real_cs_loginStart(int fd, uint8_t *uuid, char *name);
void __real_handlePacket(int fd, int length, int packet_id, int state);

static int pending_fd = -1;

static const uint32_t sha_k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7c7,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,
  0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,
  0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,
  0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha_transform(uint32_t h[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
      ((uint32_t)block[i*4+2] << 8) | block[i*4+3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],x=h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25), ch=(e&f)^(~e&g);
    uint32_t t1=x+s1+ch+sha_k[i]+w[i];
    uint32_t s0=rotr(a,2)^rotr(a,13)^rotr(a,22), maj=(a&b)^(a&c)^(b&c);
    uint32_t t2=s0+maj;
    x=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=x;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint8_t block[64]; size_t full = len & ~(size_t)63;
  for (size_t i=0;i<full;i+=64) sha_transform(h,data+i);
  size_t rem=len-full; memset(block,0,sizeof(block)); memcpy(block,data+full,rem); block[rem]=0x80;
  if (rem >= 56) { sha_transform(h,block); memset(block,0,sizeof(block)); }
  uint64_t bits=(uint64_t)len*8;
  for (int i=0;i<8;i++) block[63-i]=(uint8_t)(bits>>(i*8));
  sha_transform(h,block);
  for (int i=0;i<8;i++) { out[i*4]=(uint8_t)(h[i]>>24);out[i*4+1]=(uint8_t)(h[i]>>16);out[i*4+2]=(uint8_t)(h[i]>>8);out[i*4+3]=(uint8_t)h[i]; }
}

static void hmac_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint8_t key[64]={0}, inner[64+VELOCITY_MAX_FORWARD_SIZE], digest[32];
  size_t n=strlen(VELOCITY_FORWARDING_SECRET); if(n>64)n=64; memcpy(key,VELOCITY_FORWARDING_SECRET,n);
  for(int i=0;i<64;i++)key[i]^=0x36; memcpy(inner,key,64); memcpy(inner+64,data,len); sha256(inner,64+len,digest);
  for(int i=0;i<64;i++)key[i]^=0x6a; memcpy(inner,key,64); memcpy(inner+64,digest,32); sha256(inner,96,out);
}

static int buf_varint(const uint8_t *b,size_t n,size_t *p) { int v=0,s=0; while(*p<n&&s<35){uint8_t x=b[(*p)++];v|=(x&127)<<s;if(!(x&128))return v;s+=7;}return -1; }
static int buf_skip_string(const uint8_t *b,size_t n,size_t *p) { int l=buf_varint(b,n,p); if(l<0||*p+(size_t)l>n)return 1;*p+=(size_t)l;return 0; }
static int buf_name(const uint8_t *b,size_t n,size_t *p,char *out) { int l=buf_varint(b,n,p);if(l<1||l>15||*p+(size_t)l>n)return 1;memcpy(out,b+*p,l);out[l]=0;*p+=(size_t)l;return 0; }

int __wrap_cs_loginStart(int fd,uint8_t *uuid,char *name) {
  int r=__real_cs_loginStart(fd,uuid,name); if(r)return r; pending_fd=fd;
  int c=(int)strlen(VELOCITY_CHANNEL); writeVarInt(fd,1+sizeVarInt(0)+sizeVarInt(c)+c); writeByte(fd,0x04); writeVarInt(fd,0); writeVarInt(fd,c); send_all(fd,VELOCITY_CHANNEL,c); return 0;
}

static int verify_forwarded(int fd,int length,uint8_t *uuid,char *name) {
  if(length<34||length>VELOCITY_MAX_FORWARD_SIZE)return 1;
  uint8_t data[VELOCITY_MAX_FORWARD_SIZE]; if(recv_all(fd,data,length,0)!=length)return 1;
  size_t p=0; if(data[p++]!=1||p+16>=(size_t)length)return 1; memcpy(uuid,data+p,16);p+=16;
  if(buf_name(data,length,&p,name))return 1;
  int props=buf_varint(data,length,&p);if(props<0||props>64)return 1;
  for(int i=0;i<props;i++){if(buf_skip_string(data,length,&p)||buf_skip_string(data,length,&p))return 1;int has=buf_varint(data,length,&p);if(has<0)return 1;if(has&&buf_skip_string(data,length,&p))return 1;}
  if(buf_skip_string(data,length,&p))return 1; if(p+32!=(size_t)length)return 1;
  uint8_t expected[32];hmac_sha256(data,length-32,expected);uint8_t diff=0;for(int i=0;i<32;i++)diff|=expected[i]^data[length-32+i];return diff!=0;
}

void __wrap_handlePacket(int fd,int length,int packet_id,int state) {
  if(state==STATE_LOGIN&&packet_id==0x02&&fd==pending_fd) {
    int msg=readVarInt(fd);if(msg!=0||recv_count<1){recv_count=-1;return;}int ok=readByte(fd);if(ok!=1){recv_count=-1;return;}
    int data_len=length-sizeVarInt(msg)-1;uint8_t uuid[16];char name[16];
    if(verify_forwarded(fd,data_len,uuid,name)||reservePlayerData(fd,uuid,name)){recv_count=-1;return;}
    sc_loginSuccess(fd,uuid,name);pending_fd=-1;return;
  }
  __real_handlePacket(fd,length,packet_id,state);
}

#endif
