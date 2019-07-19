#include "tomcrypt.h"

/* blowfish speed test program, W.Ehrhardt June 2006 */
/* encrypt 512 MB, 8000000 64-byte-blocks  */

#define LOOPS (8*1000000)

int main(int argc, char * argv[])
{
  unsigned char key[16], IV[16], buffer[64];
  symmetric_CTR ctr;
  symmetric_CFB cfb;
  symmetric_OFB ofb;
  symmetric_ECB ecb;
  symmetric_CBC cbc;
  omac_state omac;
  unsigned char tag[16];
  int error, i, oidx;
  unsigned k;
  unsigned long taglen;

  if (register_cipher(&blowfish_desc) == -1) {
    printf("Error registering cipher.\n");
    return -1;
  }


  if (argc<2) {
    printf("Usage: %s  [cbc | cfb | ctr | ecb | ofb | omac]", argv[0]);
    return -1;
  }

  if (!strcmp(argv[1],"ctr")) {
    if ((error = ctr_start(find_cipher("blowfish"), IV, key, 16, 0,CTR_COUNTER_BIG_ENDIAN
    , &ctr)) != CRYPT_OK) {
      printf("ctr_start error: %s\n", error_to_string(error));
      return -1;
    }
    for (i=0; i<LOOPS; i++) {
      if ((error = ctr_encrypt(buffer, buffer, sizeof(buffer), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(error));
        return -1;
      }
    }
  }

  else if (!strcmp(argv[1],"cfb")) {
    if ((error = cfb_start(find_cipher("blowfish"), IV, key, 16, 0, &cfb)) != CRYPT_OK) {
      printf("cfb_start error: %s\n", error_to_string(error));
      return -1;
    }
    for (i=0; i<LOOPS; i++) {
      if ((error = cfb_encrypt(buffer, buffer, sizeof(buffer), &cfb)) != CRYPT_OK) {
        printf("cfb_encrypt error: %s\n", error_to_string(error));
        return -1;
      }
    }
  }

  else if (!strcmp(argv[1],"ofb")) {
    /* start up OFB mode */
    if ((error = ofb_start(find_cipher("blowfish"), IV, key, 16, 0, &ofb)) != CRYPT_OK) {
      printf("ofb_start error: %s\n", error_to_string(error));
      return -1;
    }

    for (i=0; i<LOOPS; i++) {
      if ((error = ofb_encrypt(buffer, buffer, sizeof(buffer), &ofb)) != CRYPT_OK) {
        printf("ofb_encrypt error: %s\n", error_to_string(error));
        return -1;
      }
    }
  }

  else if (!strcmp(argv[1],"ecb")) {
    /* start up ecb mode */
    if ((error = ecb_start(find_cipher("blowfish"), key, 16, 0, &ecb)) != CRYPT_OK) {
      printf("ecb_start error: %s\n", error_to_string(error));
      return -1;
    }

    for (i=0; i<LOOPS; i++) {
      if ((error = ecb_encrypt(buffer, buffer, sizeof(buffer), &ecb)) != CRYPT_OK) {
        printf("ecb_encrypt error: %s\n", error_to_string(error));
        return -1;
      }
    }
  }

  else if (!strcmp(argv[1],"cbc")) {
    /* start up cbc mode */
    if ((error = cbc_start(find_cipher("blowfish"), IV, key, 16, 0, &cbc)) != CRYPT_OK) {
      printf("cbc_start error: %s\n", error_to_string(error));
      return -1;
    }

    for (i=0; i<LOOPS; i++) {
      if ((error = cbc_encrypt(buffer, buffer, sizeof(buffer), &cbc)) != CRYPT_OK) {
        printf("cbc_encrypt error: %s\n", error_to_string(error));
        return -1;
      }
    }
  }

  else if (!strcmp(argv[1],"omac")) {
    if ((oidx = find_cipher("blowfish")) == -1) {
      printf("OMAC: Unable to find blowfish cipher\n");
      return -1;
    }
    if ((error = omac_init(&omac, oidx, key, 16)) != CRYPT_OK) {
      printf("omac_init error: %s\n", error_to_string(error));
      return -1;
    }
    for (i=0; i<LOOPS; i++) {
      if ((error = omac_process(&omac, buffer, sizeof(buffer))) != CRYPT_OK) {
        printf("omac_process error: %s\n", error_to_string(error));
        return -1;
      }
    }

    taglen = sizeof(tag);
    if ((error = omac_done(&omac, tag, &taglen)) != CRYPT_OK) {
      printf("omac_done error: %s\n", error_to_string(error));
      return -1;
    }

  }

  else printf("Usage: %s  [cbc | cfb | ctr | ecb | ofb | omac]", argv[0]);

  return 0;
}

