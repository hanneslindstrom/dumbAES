#ifndef DUMBAES_KEY_EXPANSION_H
#define DUMBAES_KEY_EXPANSION_H

#include <stdint.h>

#include "dumbAES_status.h"
#include "dumbAES_cipher.h"

/******************************************************************************/
// Global functions
/******************************************************************************/

// Brief:
//   Expand the cipher key to multiple round keys.
dumbAES_status_t expand_key(const uint8_t     *cipher_key,
                            size_t            key_size,
                            uint32_t          *expanded_key);

#endif // DUMBAES_KEY_EXPANSION_H