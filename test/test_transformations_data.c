#include "dumbAES_defines.h"

/******************************************************************************/
// Structs
/******************************************************************************/

typedef struct {
  size_t id;
  uint8_t input[DUMBAES_BLOCKSIZE];
  uint8_t round_key[DUMBAES_NB * 4];
  uint8_t expected_output[DUMBAES_BLOCKSIZE];
} state_test_vector_t;

/******************************************************************************/
// Test data
/******************************************************************************/

const state_test_vector_t sub_bytes_test_vectors[] = {
  {
    0,
    {0x19, 0xa0, 0x9a, 0xe9, 0x3d, 0xf4, 0xc6, 0xf8, 0xe3, 0xe2, 0x8d, 0x48, 0xbe, 0x2b, 0x2a, 0x08},
    {},
    {0xd4, 0xe0, 0xb8, 0x1e, 0x27, 0xbf, 0xb4, 0x41, 0x11, 0x98, 0x5d, 0x52, 0xae, 0xf1, 0xe5, 0x30}
  },
  {
    1,
    {0xa4, 0x68, 0x6b, 0x02, 0x9c, 0x9f, 0x5b, 0x6a, 0x7f, 0x35, 0xea, 0x50, 0xf2, 0x2b, 0x43, 0x49},
    {},
    {0x49, 0x45, 0x7f, 0x77, 0xde, 0xdb, 0x39, 0x02, 0xd2, 0x96, 0x87, 0x53, 0x89, 0xf1, 0x1a, 0x3b}
  },
  {
    2,
    {0xaa, 0x61, 0x82, 0x68, 0x8f, 0xdd, 0xd2, 0x32, 0x5f, 0xe3, 0x4a, 0x46, 0x03, 0xef, 0xd2, 0x9a},
    {},
    {0xac, 0xef, 0x13, 0x45, 0x73, 0xc1, 0xb5, 0x23, 0xcf, 0x11, 0xd6, 0x5a, 0x7b, 0xdf, 0xb5, 0xb8}
  },
  {
    3,
    {0x48, 0x67, 0x4d, 0xd6, 0x6c, 0x1d, 0xe3, 0x5f, 0x4e, 0x9d, 0xb1, 0x58, 0xee, 0x0d, 0x38, 0xe7},
    {},
    {0x52, 0x85, 0xe3, 0xf6, 0x50, 0xa4, 0x11, 0xcf, 0x2f, 0x5e, 0xc8, 0x6a, 0x28, 0xd7, 0x07, 0x94}
  },
  {
    4,
    {0xe0, 0xc8, 0xd9, 0x85, 0x92, 0x63, 0xb1, 0xb8, 0x7f, 0x63, 0x35, 0xbe, 0xe8, 0xc0, 0x50, 0x01},
    {},
    {0xe1, 0xe8, 0x35, 0x97, 0x4f, 0xfb, 0xc8, 0x6c, 0xd2, 0xfb, 0x96, 0xae, 0x9b, 0xba, 0x53, 0x7c}
  }
};

const state_test_vector_t shift_rows_test_vectors[] = {
  {
    0,
    {0xd4, 0xe0, 0xb8, 0x1e, 0x27, 0xbf, 0xb4, 0x41, 0x11, 0x98, 0x5d, 0x52, 0xae, 0xf1, 0xe5, 0x30},
    {},
    {0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae, 0xf1, 0xe5}
  },
  {
    1,
    {0x49, 0x45, 0x7f, 0x77, 0xde, 0xdb, 0x39, 0x02, 0xd2, 0x96, 0x87, 0x53, 0x89, 0xf1, 0x1a, 0x3b},
    {},
    {0x49, 0x45, 0x7f, 0x77, 0xdb, 0x39, 0x02, 0xde, 0x87, 0x53, 0xd2, 0x96, 0x3b, 0x89, 0xf1, 0x1a}
  },
  {
    2,
    {0xac, 0xef, 0x13, 0x45, 0x73, 0xc1, 0xb5, 0x23, 0xcf, 0x11, 0xd6, 0x5a, 0x7b, 0xdf, 0xb5, 0xb8},
    {},
    {0xac, 0xef, 0x13, 0x45, 0xc1, 0xb5, 0x23, 0x73, 0xd6, 0x5a, 0xcf, 0x11, 0xb8, 0x7b, 0xdf, 0xb5}
  },
  {
    3,
    {0x52, 0x85, 0xe3, 0xf6, 0x50, 0xa4, 0x11, 0xcf, 0x2f, 0x5e, 0xc8, 0x6a, 0x28, 0xd7, 0x07, 0x94},
    {},
    {0x52, 0x85, 0xe3, 0xf6, 0xa4, 0x11, 0xcf, 0x50, 0xc8, 0x6a, 0x2f, 0x5e, 0x94, 0x28, 0xd7, 0x07}
  },
  {
    4,
    {0xe1, 0xe8, 0x35, 0x97, 0x4f, 0xfb, 0xc8, 0x6c, 0xd2, 0xfb, 0x96, 0xae, 0x9b, 0xba, 0x53, 0x7c},
    {},
    {0xe1, 0xe8, 0x35, 0x97, 0xfb, 0xc8, 0x6c, 0x4f, 0x96, 0xae, 0xd2, 0xfb, 0x7c, 0x9b, 0xba, 0x53}
  }
};

const state_test_vector_t mix_columns_test_vectors[] = {
  {
    0,
    {0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae, 0xf1, 0xe5},
    {},
    {0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a, 0x7a, 0x4c}
  },
  {
    1,
    {0x49, 0x45, 0x7f, 0x77, 0xdb, 0x39, 0x02, 0xde, 0x87, 0x53, 0xd2, 0x96, 0x3b, 0x89, 0xf1, 0x1a},
    {},
    {0x58, 0x1b, 0xdb, 0x1b, 0x4d, 0x4b, 0xe7, 0x6b, 0xca, 0x5a, 0xca, 0xb0, 0xf1, 0xac, 0xa8, 0xe5}
  },
  {
    2,
    {0xac, 0xef, 0x13, 0x45, 0xc1, 0xb5, 0x23, 0x73, 0xd6, 0x5a, 0xcf, 0x11, 0xb8, 0x7b, 0xdf, 0xb5},
    {},
    {0x75, 0x20, 0x53, 0xbb, 0xec, 0x0b, 0xc0, 0x25, 0x09, 0x63, 0xcf, 0xd0, 0x93, 0x33, 0x7c, 0xdc}
  },
  {
    3,
    {0x52, 0x85, 0xe3, 0xf6, 0xa4, 0x11, 0xcf, 0x50, 0xc8, 0x6a, 0x2f, 0x5e, 0x94, 0x28, 0xd7, 0x07},
    {},
    {0x0f, 0x60, 0x6f, 0x5e, 0xd6, 0x31, 0xc0, 0xb3, 0xda, 0x38, 0x10, 0x13, 0xa9, 0xbf, 0x6b, 0x01}
  },
  {
    4,
    {0xe1, 0xe8, 0x35, 0x97, 0xfb, 0xc8, 0x6c, 0x4f, 0x96, 0xae, 0xd2, 0xfb, 0x7c, 0x9b, 0xba, 0x53},
    {},
    {0x25, 0xbd, 0xb6, 0x4c, 0xd1, 0x11, 0x3a, 0x4c, 0xa9, 0xd1, 0x33, 0xc0, 0xad, 0x68, 0x8e, 0xb0}
  }
};

const state_test_vector_t add_round_key_test_vectors[] = {
  {
    0,
    {0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a, 0x7a, 0x4c},
    {0xa0, 0x88, 0x23, 0x2a, 0xfa, 0x54, 0xa3, 0x6c, 0xfe, 0x2c, 0x39, 0x76, 0x17, 0xb1, 0x39, 0x05},
    {0xa4, 0x68, 0x6b, 0x02, 0x9c, 0x9f, 0x5b, 0x6a, 0x7f, 0x35, 0xea, 0x50, 0xf2, 0x2b, 0x43, 0x49}
  },
  {
    1,
    {0x58, 0x1b, 0xdb, 0x1b, 0x4d, 0x4b, 0xe7, 0x6b, 0xca, 0x5a, 0xca, 0xb0, 0xf1, 0xac, 0xa8, 0xe5},
    {0xf2, 0x7a, 0x59, 0x73, 0xc2, 0x96, 0x35, 0x59, 0x95, 0xb9, 0x80, 0xf6, 0xf2, 0x43, 0x7a, 0x7f},
    {0xaa, 0x61, 0x82, 0x68, 0x8f, 0xdd, 0xd2, 0x32, 0x5f, 0xe3, 0x4a, 0x46, 0x03, 0xef, 0xd2, 0x9a}
  },
  {
    2,
    {0x75, 0x20, 0x53, 0xbb, 0xec, 0x0b, 0xc0, 0x25, 0x09, 0x63, 0xcf, 0xd0, 0x93, 0x33, 0x7c, 0xdc},
    {0x3d, 0x47, 0x1e, 0x6d, 0x80, 0x16, 0x23, 0x7a, 0x47, 0xfe, 0x7e, 0x88, 0x7d, 0x3e, 0x44, 0x3b},
    {0x48, 0x67, 0x4d, 0xd6, 0x6c, 0x1d, 0xe3, 0x5f, 0x4e, 0x9d, 0xb1, 0x58, 0xee, 0x0d, 0x38, 0xe7}
  },
  {
    3,
    {0x0f, 0x60, 0x6f, 0x5e, 0xd6, 0x31, 0xc0, 0xb3, 0xda, 0x38, 0x10, 0x13, 0xa9, 0xbf, 0x6b, 0x01},
    {0xef, 0xa8, 0xb6, 0xdb, 0x44, 0x52, 0x71, 0x0b, 0xa5, 0x5b, 0x25, 0xad, 0x41, 0x7f, 0x3b, 0x00},
    {0xe0, 0xc8, 0xd9, 0x85, 0x92, 0x63, 0xb1, 0xb8, 0x7f, 0x63, 0x35, 0xbe, 0xe8, 0xc0, 0x50, 0x01}
  },
  {
    4,
    {0x25, 0xbd, 0xb6, 0x4c, 0xd1, 0x11, 0x3a, 0x4c, 0xa9, 0xd1, 0x33, 0xc0, 0xad, 0x68, 0x8e, 0xb0},
    {0xd4, 0x7c, 0xca, 0x11, 0xd1, 0x83, 0xf2, 0xf9, 0xc6, 0x9d, 0xb8, 0x15, 0xf8, 0x87, 0xbc, 0xbc},
    {0xf1, 0xc1, 0x7c, 0x5d, 0x00, 0x92, 0xc8, 0xb5, 0x6f, 0x4c, 0x8b, 0xd5, 0x55, 0xef, 0x32, 0x0c}
  }
};