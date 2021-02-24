#ifndef DUMBAES_CIPHER_H
#define DUMBAES_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#include "dumbAES_defines.h"
#include "dumbAES_status.h"

/******************************************************************************/
// Typedefs
/******************************************************************************/

typedef struct state_s {
  uint8_t bytes[DUMBAES_NB * 4];
} state_t;

typedef struct round_key_s {
  uint8_t bytes[DUMBAES_NB * 4];
} round_key_t;

/******************************************************************************/
// Global functions
/******************************************************************************/

// Brief:
//   Perform AES encryption of one block of data.
dumbAES_status_t dumbAES_encrypt(const uint8_t     *input, 
                                 size_t            input_size,
                                 uint8_t           *output, 
                                 size_t            output_size, 
                                 const uint8_t     *key, 
                                 size_t            keysize);

#endif // DUMBAES_CIPHER_H