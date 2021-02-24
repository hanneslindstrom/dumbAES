#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "dumbAES_transformations.h"
#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

/******************************************************************************/
// Static consts
/******************************************************************************/

static const sbox_t encrypt_sbox = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const mix_column_matrix_t encrypt_mix_column_matrix = {
  2, 3, 1, 1,
  1, 2, 3, 1,
  1, 1, 2, 3,
  3, 1, 1, 2
};

/******************************************************************************/
// Static functions
/******************************************************************************/

// Brief:
//   Substitute a byte according to the given substitution LUT.
static inline void sub_byte(sbox_t  *sbox,
                            uint8_t *byte) {
  *byte = sbox->lookup_table[*byte];
}

// Brief:
//   Left-shift the bytes in the given input-row.
static void shift_row(uint8_t *row, 
                      size_t  num_bytes,
                      size_t  shift) {
  uint8_t tmp_shift_buf[DUMBAES_NB - 1] = { 0 };
  memcpy(tmp_shift_buf, row, shift);
  for (size_t i = 0; i < num_bytes - shift; ++i) {
    row[i] = row[i + shift];
  }
  memcpy(&row[num_bytes - shift], tmp_shift_buf, shift);
}

// Brief:
//   Perform multiplication in the Gaolis field GF(2^8) using a modified
//   version of the "peasant's algorithm".
static uint8_t GF_mult(uint8_t a,
                       uint8_t b) {
    uint8_t p = 0;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
          p ^= a;
        }
        b >>= 1;
        bool carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) {
          a ^= 0x1B;
        }
    }
    return p;
}

// Brief:
//   Mix the bytes of a column in the state using a matrix-multiplication.
static void mix_column(mix_column_matrix_t *mix_column_matrix, 
                       state_t             *state, 
                       size_t              state_col) {
  uint8_t output_column[4] = { 0 };
  uint8_t matrix_value = 0;
  uint8_t vector_value = 0;

  // Perform matrix-vector multiplications.
  for (size_t matrix_row = 0; matrix_row < 4; ++matrix_row) {
    for (size_t matrix_col = 0; matrix_col < DUMBAES_NB; ++matrix_col) {
      matrix_value = mix_column_matrix->scalars[matrix_row * 4 + matrix_col];
      vector_value = state->bytes[state_col + matrix_col * 4];
      output_column[matrix_row] ^= GF_mult(matrix_value, vector_value);
    }
  }

  // Copy results to state.
  for (size_t i = 0; i < 4; ++i) {
    state->bytes[state_col + i * 4] = output_column[i];
  }
}

/******************************************************************************/
// Global functions
/******************************************************************************/

//----------------------------------
// Main cipher transformations

// Brief:
//   Apply a non-linear transformation to every byte in the state using a
//   substitution table.
dumbAES_status_t sub_bytes(state_t *state)
{
  if (state == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  for (size_t i = 0; i < DUMBAES_NB * 4; ++i) {
    sub_byte((sbox_t*)&encrypt_sbox, &state->bytes[i]);
  }

  return DUMBAES_STATUS_SUCCESS;
}

// Brief:
//   Cyclically shift the contents of the rows of the state with an increasing
//   shift for every row.
dumbAES_status_t shift_rows(state_t *state)
{
  if (state == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  for (size_t i = 1; i < 4; ++i) {
    shift_row(&state->bytes[i * DUMBAES_NB], DUMBAES_NB, i);
  }

  return DUMBAES_STATUS_SUCCESS;
}

// Brief:
//   Apply a mixing transformation to the columns of the state one-by-one.
dumbAES_status_t mix_columns(state_t *state)
{
  if (state == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  for (size_t i = 0; i < DUMBAES_NB; ++i) {
    mix_column((mix_column_matrix_t*)&encrypt_mix_column_matrix, 
               state,
               i);
  }

  return DUMBAES_STATUS_SUCCESS;
}

// Brief:
//   'Add' the round key to the intermediate state result by performing a
//   bitwise XOR operation.
dumbAES_status_t add_round_key(state_t     *state,
                               round_key_t *round_key)
{
  if (state == NULL || round_key == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  for (size_t row = 0; row < 4; ++row) {
    for (size_t col = 0; col < DUMBAES_NB; ++col) {
      state->bytes[col + row * 4] ^= round_key->bytes[col + row * 4];
    }
  }

  return DUMBAES_STATUS_SUCCESS;
}

//----------------------------------
// Key expansion transformations

// Brief:
//   Substitute all bytes in a word according to the given substitution LUT.
dumbAES_status_t sub_word(uint32_t *word)
{
  if (word == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  for (size_t i = 0; i < 4; ++i) {
    sub_byte((sbox_t*)&encrypt_sbox, &((uint8_t*)word)[i]);
  }

  return DUMBAES_STATUS_SUCCESS;
}

// Brief:
//   Right-shift the bytes in the given word.
dumbAES_status_t rot_word(uint32_t *word)
{
  if (word == NULL) {
    return DUMBAES_STATUS_FAILURE;
  }

  shift_row((uint8_t*)word, 4, 3);

  return DUMBAES_STATUS_SUCCESS;
}