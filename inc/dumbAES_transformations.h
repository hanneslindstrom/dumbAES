#ifndef DUMBAES_TRANSFORMATION_H
#define DUMBAES_TRANSFORMATION_H

#include <stdint.h>

#include "dumbAES_cipher.h"
#include "dumbAES_status.h"

/******************************************************************************/
// Typedefs
/******************************************************************************/

typedef struct sbox_s {
  uint8_t lookup_table[256];
} sbox_t;

typedef struct mix_column_matrix_s {
  uint8_t scalars[16];
} mix_column_matrix_t;

/******************************************************************************/
// Global functions
/******************************************************************************/

//----------------------------------
// Main cipher transformations

// Brief:
//   Apply a non-linear transformation to every byte in the state using a
//   substitution table.
dumbAES_status_t sub_bytes(state_t *state);

// Brief:
//   Cyclically shift the contents of the rows of the state with an increasing
//   shift for every row.
dumbAES_status_t shift_rows(state_t *state);

// Brief:
//   Apply a mixing transformation to the columns of the state one-by-one.
dumbAES_status_t mix_columns(state_t *state);

// Brief:
//   'Add' the round key to the intermediate state result by performing a
//   bitwise XOR operation.
dumbAES_status_t add_round_key(state_t     *state,
                               round_key_t *round_key);

//----------------------------------
// Key expansion transformations

// Brief:
//   Substitute all bytes in a word according to the given substitution LUT.
dumbAES_status_t sub_word(uint32_t *word);

// Brief:
//   Right-shift the bytes in the given word.
dumbAES_status_t rot_word(uint32_t *word);

#endif // DUMBAES_TRANSFORMATION_H