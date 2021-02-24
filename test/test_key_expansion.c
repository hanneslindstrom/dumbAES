#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "dumbAES_cipher.h"
#include "dumbAES_key_expansion.h"
#include "dumbAES_status.h"
#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

#include "test_key_expansion_data.c"

/******************************************************************************/
// Static variables
/******************************************************************************/

//static state_t test_state;

/******************************************************************************/
// Test setup- and teardown functions
/******************************************************************************/

// This is run before EACH TEST.
void setUp(void)
{
}

// This is run after EACH TEST.
void tearDown(void)
{
}

/******************************************************************************/
// Test functions
/******************************************************************************/

void test_expand_key(const key_test_vector_t *test_vector, size_t key_size)
{
  
  printf("Testing expand_key with test vector #%zu\n", 
             test_vector->id);

  uint32_t output_key[4 * (DUMBAES_MAX_NR + 1)] = { 0 };

  size_t nr = 0;
  switch (key_size) {
    case 16:
      nr = AES_128_NR;
      break;
    case 24:
      nr = AES_192_NR;
      break;
    case 32:
      nr = AES_256_NR;
      break;
    default:
      TEST_ASSERT_TRUE(0);
      break;
  }

  // Perform key expansion.
  dumbAES_status_t status = expand_key(test_vector->cipher_key,
                                       key_size,
                                       output_key);

  TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
  TEST_ASSERT_EQUAL_HEX32_ARRAY(test_vector->expected_output,
                                output_key,
                                4 * (nr + 1));
}

void test_expand_key_128(void)
{
  for (size_t i = 0;
       i < sizeof(expand_key_test_vectors_128) / sizeof(key_test_vector_t);
       ++i) {
    test_expand_key(&expand_key_test_vectors_128[i], 16);
  }
}

void test_expand_key_192(void)
{
  for (size_t i = 0;
       i < sizeof(expand_key_test_vectors_192) / sizeof(key_test_vector_t);
       ++i) {
    test_expand_key(&expand_key_test_vectors_192[i], 24);
  }
}

void test_expand_key_256(void)
{
  for (size_t i = 0;
       i < sizeof(expand_key_test_vectors_256) / sizeof(key_test_vector_t);
       ++i) {
    test_expand_key(&expand_key_test_vectors_256[i], 32);
  }
}

/******************************************************************************/
// Test runner
/******************************************************************************/

int main(void) 
{
  UNITY_BEGIN();

  // Run tests.
  RUN_TEST(test_expand_key_128, __LINE__);
  RUN_TEST(test_expand_key_192, __LINE__);
  RUN_TEST(test_expand_key_256, __LINE__);

  return UNITY_END();
}
