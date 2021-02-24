#include "dumbAES_key_expansion.h"
#include "dumbAES_transformations.h"
#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

/******************************************************************************/
// Static consts
/******************************************************************************/

uint32_t rcon[10] = {
  0x01000000, 0x02000000, 0x04000000, 0x08000000, 
  0x10000000, 0x20000000, 0x40000000, 0x80000000, 
  0x1B000000, 0x36000000
};

/******************************************************************************/
// Global functions
/******************************************************************************/

// Brief:
//   Expand the cipher key to multiple round keys.
dumbAES_status_t expand_key(const uint8_t     *cipher_key,
                            size_t            key_size,
                            uint32_t          *expanded_key)
{
  if (cipher_key == NULL || expanded_key == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  size_t nk = 0;
  size_t nr = 0;
  switch (key_size) {
    case DUMBAES_KEYSIZE_128:
      nk = AES_128_NK;
      nr = AES_128_NR;
      break;
    case DUMBAES_KEYSIZE_192:
      nk = AES_192_NK;
      nr = AES_192_NR;
      break;
    case DUMBAES_KEYSIZE_256:
      nk = AES_256_NK;
      nr = AES_256_NR;
      break;
    default:
      return DUMBAES_STATUS_FAILURE;
      break;
  }

  for (size_t i = 0; i < nk; ++i) {
    uint32_t temp_word = \
      (uint32_t)cipher_key[4 * i] << 24 |
      (uint32_t)cipher_key[4 * i + 1] << 16 |
      (uint32_t)cipher_key[4 * i + 2] << 8  |
      (uint32_t)cipher_key[4 * i + 3] << 0;
    expanded_key[i] = temp_word;
  }

  for (size_t i = nk; i < 4 * (nr + 1); ++i) {
    uint32_t temp = expanded_key[i - 1];
    if (i % nk == 0) {
    rot_word(&temp);
    sub_word(&temp);
    temp ^= rcon[i / nk - 1];
    } else if (nk > 6 && i % nk == 4) {
      sub_word(&temp);
    }
    expanded_key[i] = expanded_key[i - nk] ^ temp;
  }

  return DUMBAES_STATUS_SUCCESS;
}