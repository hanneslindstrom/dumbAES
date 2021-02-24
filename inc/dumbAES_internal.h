#ifndef DUMBAES_INTERNAL_H
#define DUMBAES_INTERNAL_H

#include "dumbAES_cipher.h"

/******************************************************************************/
// Global functions
/******************************************************************************/

// Brief:
//   Copy input data into state in expected order for internal representation.
void dumbAES_input_into_state(state_t       *state,
                              const uint8_t *input);

// Brief:
//   Output final state in the expected representation.
void dumbAES_state_into_output(state_t *state,
                               uint8_t *output);

// Brief:
//   Convert a raw arraw of words (forming a round key) into a dedicated
//   struct following the expected internal representation of a round key.
void dumbAES_raw_roundkey_into_roundkey(round_key_t *round_key,
                                        uint32_t    *raw_round_key);

#endif // DUMBAES_INTERNAL_H