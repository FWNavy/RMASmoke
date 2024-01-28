#include "esys_context.h"
#include "tss_context.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <endian.h>
#include <iostream>
#include <linux/types.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <string>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>
TSS2_SYS_CONTEXT_INT *GenerateContext() {
  TSS2_SYS_CONTEXT_INT *buffer =
      (TSS2_SYS_CONTEXT_INT *)malloc(sizeof(TSS2_SYS_CONTEXT_INT) + 2048);
  memset(buffer, 0, sizeof(TSS2_SYS_CONTEXT_INT) + 2048);
  UINT8 *cmdBuffer = (UINT8 *)(buffer + sizeof(TSS2_SYS_CONTEXT_INT));
  buffer->cmdBuffer = (UINT8 *)(cmdBuffer);
  return buffer;
}
void ConsumeInputBuffer() {
  char buffer[1];

  while (fread(buffer, 1, 0, stdin))
    ;
}
void ReadFromInput(std::string *input) {}
struct tpm_result {
  __be16 tag;
  __be32 length;
  __be32 ordinal;
  __be16 subcmd;
};
uint32_t SendTPMCommand(char *buf, size_t len, char **respBuf, size_t *respLen,
                        int tpmfd) {
  if (len > 2048) {
    printf("We have a problem!\n");
    return -1;
  }
  int written = write(tpmfd, buf, len);
  if (written != len) {
    printf("written != len\n");
    return -1;
  }
  char *responseBuffer = new char[2048];
  char *response = responseBuffer;
  size_t responseLen = 0;
  memset(responseBuffer, 0, 2048);
  int read_count = 0;
  do {
    size_t rx_to_go = sizeof(responseBuffer) - responseLen;
    response = response + responseLen;
    read_count = read(tpmfd, response, rx_to_go);
    responseLen += read_count;
  } while (read_count);
  response = responseBuffer;
  struct tpm_result *pkt = (struct tpm_result *)responseBuffer;
  uint32_t rv;
  memcpy(&rv, &pkt->ordinal, sizeof(rv));
  rv = be32toh(rv);
  if (respBuf)
    *respBuf = responseBuffer;
  if (*respLen)
    *respLen = read_count;
  printf("Received response: %d", rv);
  return rv;
}
int main(int c, char **argv) {
  if (c <= 1) {
    printf("need more parameters!!");
    return -1;
  }
  TSS2_SYS_CONTEXT_INT *context = GenerateContext();
  TPM2B_AUTH auth;
  FILE *passwd_file = fopen(argv[1], "w+");

  const char *passwd = "default password";
  if (c > 2) {
    passwd = argv[2];
  }

  fprintf(passwd_file, "%s\n", passwd);
  int tpmfd = open("/dev/tpm0", O_SYNC);
  SHA256((unsigned char *)passwd, strlen(passwd), auth.buffer);
  TPM2B_NV_PUBLIC pub;
  memset(&pub, 0, sizeof(pub));
  pub.nvPublic.attributes = TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE;
  pub.nvPublic.dataSize = 2048;
  pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
  pub.nvPublic.authPolicy.size = 0;
  pub.nvPublic.nvIndex = 0x00001007;
  Tss2_Sys_NV_DefineSpace_Prepare((TSS2_SYS_CONTEXT *)context, TPM2_RH_OWNER,
                                  &auth, &pub);
  char *response = NULL;
  size_t len = 0;
  int rv = SendTPMCommand((char*) context->cmdBuffer, context->nextData, &response,&len, tpmfd);
  close(tpmfd);
}
