#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

/******************************************************************************/
// Global functions
/******************************************************************************/

// Brief:
//   Copy input data into state in expected order for internal representation.
void dumbAES_input_into_state(state_t       *state,
                              const uint8_t *input)
{
  for (int row = 0; row < 4; ++row) {
    for (int col = 0; col < DUMBAES_NB; ++col) {
      state->bytes[col * 4 + row] = input[row * 4 + col];
    }
  }
}

// Brief:
//   Output final state in the expected representation.
void dumbAES_state_into_output(state_t *state,
                               uint8_t *output)
{
  for (int col = 0; col < DUMBAES_NB; ++col) {
    for (int row = 0; row < 4; ++row) {
      output[col * 4 + row] = state->bytes[row * 4 + col];
    }
  }
}

// Brief:
//   Convert a raw arraw of words (forming a round key) into a dedicated
//   struct following the expected internal representation of a round key.
void dumbAES_raw_roundkey_into_roundkey(round_key_t *round_key,
                                        uint32_t    *raw_round_key)
{
  for (int i = 0; i < DUMBAES_NB; ++i) {
    raw_round_key[i] = \
      (uint32_t)((uint8_t*)&raw_round_key[i])[0] << 24 |
      (uint32_t)((uint8_t*)&raw_round_key[i])[1] << 16 |
      (uint32_t)((uint8_t*)&raw_round_key[i])[2] << 8  |
      (uint32_t)((uint8_t*)&raw_round_key[i])[3] << 0;
  }
  for (int row = 0; row < 4; ++row) {
    for (int col = 0; col < DUMBAES_NB; ++col) {
      round_key->bytes[col * 4 + row] = \
        ((uint8_t*)raw_round_key)[row * 4 + col];
    }
  }
}