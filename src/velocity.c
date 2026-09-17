#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "globals.h"
#include "packets.h"
#include "procedures.h"
#include "tools.h"
#include "varnum.h"
#include "velocity_config.h"

#ifdef ENABLE_VELOCITY_FORWARDING

#define VELOCITY_CHANNEL "velocity:player_info"
#define VELOCITY_MAX_FORWARD_SIZE 4096

static uint8_t pending_uuid[MAX_PLAYERS][16];
static char pending_name[MAX_PLAYERS][16];
static int pending_fd[MAX_PLAYERS];

static uint32_t rol32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

/* Small SHA-256 implementation; avoids adding a crypto dependency on ESP targets. */
static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };
  uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  size_t total = ((len + 9 + 63) / 64) * 64;
  uint8_t *msg = calloc(1, total);
  if (!msg) return;
  memcpy(msg, data, len); msg[len] = 0x80;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) msg[total - 1 - i] = (uint8_t)(bits >> (i * 8));
  for (size_t off = 0; off < total; off += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = ((uint32_t)msg[off+i*4]<<24)|((uint32_t)msg[off+i*4+1]<<16)|((uint32_t)msg[off+i*4+2]<<8)|msg[off+i*4+3];
    for (int i = 16; i < 64; i++) { uint32_t a=rol32(w[i-15],25)^rol32(w[i-15],14)^(w[i-15]>>3); uint32_t b=rol32(w[i-2],15)^rol32(w[i-2],13)^(w[i-2]>>10); w[i]=w[i-16]+a+w[i-7]+b; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],q=h[7];
    for (int i=0;i<64;i++) { uint32_t s1=rol32(e,26)^rol32(e,21)^rol32(e,7), ch=(e&f)^(~e&g), t1=q+s1+ch+k[i]+w[i]; uint32_t s0=rol32(a,30)^rol32(a,19)^rol32(a,10), maj=(a&b)^(a&c)^(b&c), t2=s0+maj; q=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=q;
  }
  for (int i=0;i<8;i++) { out[i*4]=h[i]>>24;out[i*4+1]=h[i]>>16;out[i*4+2]=h[i]>>8;out[i*4+3]=h[i]; }
  free(msg);
}

static void hmac_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint8_t key[64]={0}, inner[64+VELOCITY_MAX_FORWARD_SIZE], digest[32];
  size_t klen=strlen(VELOCITY_FORWARDING_SECRET); if(klen>64) klen=64; memcpy(key,VELOCITY_FORWARDING_SECRET,klen);
  for(int i=0;i<64;i++) key[i]^=0x36; memcpy(inner,key,64); memcpy(inner+64,data,len); sha256(inner,64+len,digest);
  for(int i=0;i<64;i++) key[i]^=0x36^0x5c; memcpy(inner,key,64); memcpy(inner+64,digest,32); sha256(inner,96,out);
}

static int read_buf_varint(const uint8_t *b,size_t n,size_t *p) { int v=0,s=0; while(*p<n&&s<35){uint8_t x=b[(*p)++];v|=(x&127)<<s;if(!(x&128))return v;s+=7;}return -1; }
static int read_buf_string(const uint8_t *b,size_t n,size_t *p,char *out,size_t cap) { int l=read_buf_varint(b,n,p); if(l<0||*p+(size_t)l>n)return -1; size_t c=l<cap-1?l:cap-1; memcpy(out,b+*p,c);out[c]=0;*p+=l;return 0; }

void velocity_start(int fd, const uint8_t *uuid, const char *name) {
  int slot=-1; for(int i=0;i<MAX_PLAYERS;i++) if(pending_fd[i]<0||pending_fd[i]==fd){slot=i;break;} if(slot<0)return;
  pending_fd[slot]=fd; memcpy(pending_uuid[slot],uuid,16); strncpy(pending_name[slot],name,15); pending_name[slot][15]=0;
  int cl=strlen(VELOCITY_CHANNEL); writeVarInt(fd,1+sizeVarInt(0)+sizeVarInt(cl)+cl+1); writeByte(fd,0x04); writeVarInt(fd,0); writeVarInt(fd,cl); send_all(fd,VELOCITY_CHANNEL,cl); writeByte(fd,1);
}

int velocity_finish(int fd,int length,uint8_t *uuid,char *name) {
  uint8_t data[VELOCITY_MAX_FORWARD_SIZE]; if(length<1||length>VELOCITY_MAX_FORWARD_SIZE)return 1;
  int message=readVarInt(fd); if(message!=0||recv_count<1)return 1; int remaining=length-sizeVarInt(message); if(remaining<33||remaining>VELOCITY_MAX_FORWARD_SIZE)return 1;
  if(recv_all(fd,data,remaining,0)!=remaining)return 1;
  size_t p=0; if(data[p++]!=1)return 1; if(p+16>remaining)return 1; uint8_t supplied_uuid[16]; memcpy(supplied_uuid,data+p,16);p+=16;
  char supplied_name[16]; if(read_buf_string(data,remaining,&p,supplied_name,sizeof(supplied_name)))return 1;
  int props=read_buf_varint(data,remaining,&p); if(props<0||props>64)return 1;
  for(int i=0;i<props;i++){char tmp[2];if(read_buf_string(data,remaining,&p,tmp,sizeof(tmp))||read_buf_string(data,remaining,&p,tmp,sizeof(tmp)))return 1;int has=read_buf_varint(data,remaining,&p);if(has<0)return 1;if(has&&read_buf_string(data,remaining,&p,tmp,sizeof(tmp)))return 1;}
  char ip[256]; if(read_buf_string(data,remaining,&p,ip,sizeof(ip))||p+32!=remaining)return 1;
  uint8_t expected[32]; hmac_sha256(data,remaining-32,expected); uint8_t diff=0;for(int i=0;i<32;i++)diff|=expected[i]^data[remaining-32+i];if(diff)return 1;
  memcpy(uuid,supplied_uuid,16);strncpy((char*)name,supplied_name,15);name[15]=0;return 0;
}

int velocity_begin_wrap(int fd,uint8_t *uuid,char *name){ velocity_start(fd,uuid,name); return 0; }

#endif
