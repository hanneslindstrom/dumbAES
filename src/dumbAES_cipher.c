#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "dumbAES_cipher.h"
#include "dumbAES_internal.h"
#include "dumbAES_key_expansion.h"
#include "dumbAES_transformations.h"
#include "dumbAES_defines.h"

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
                                 size_t            key_size)
{
  if (input == NULL || output == NULL || key == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  if (input_size != DUMBAES_BLOCKSIZE) {
    return DUMBAES_STATUS_FAILURE;
  }

  if (input_size > output_size) {
    return DUMBAES_STATUS_FAILURE;
  }

  size_t nr = 0;
  switch (key_size) {
    case DUMBAES_KEYSIZE_128:
      nr = AES_128_NR;
      break;
    case DUMBAES_KEYSIZE_192:
      nr = AES_192_NR;
      break;
    case DUMBAES_KEYSIZE_256:
      nr = AES_256_NR;
      break;
    default:
      return DUMBAES_STATUS_FAILURE;
      break;
  }

  // Perform key expansion routine.
  uint32_t expanded_key[4 * (DUMBAES_MAX_NR + 1)] = { 0 };
  expand_key(key, key_size, expanded_key);

  // Format and place raw round keys into array of dedicated structs.
  round_key_t round_keys[DUMBAES_MAX_NR + 1] = { 0 };
  for (size_t i = 0; i < nr + 1; ++i) {
    dumbAES_raw_roundkey_into_roundkey(&round_keys[i], &expanded_key[i * 4]);
  }

  // Initialize state from input.
  state_t state = { 0 };
  dumbAES_input_into_state(&state, input);

  // Perform first round of transformation.
  add_round_key(&state, &round_keys[0]);

  // Perform middle nr - 1 rounds of transformations.
  for (size_t round = 1; round < nr; ++round)
  {
    sub_bytes(&state);
    shift_rows(&state);
    mix_columns(&state);
    add_round_key(&state, &round_keys[round]);
  }

  // Perform final round of transformation.
  sub_bytes(&state);
  shift_rows(&state);
  add_round_key(&state, &round_keys[nr]);

  // Output final state.
  dumbAES_state_into_output(&state, output);

  return DUMBAES_STATUS_SUCCESS;
}