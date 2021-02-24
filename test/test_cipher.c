#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "dumbAES_cipher.h"
#include "dumbAES_status.h"
#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

#include "test_cipher_data.c"

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

void test_encrypt(const aes_test_vector_t *test_vector, size_t key_size)
{
  
  printf("Testing encrypt with test vector #%zu\n", 
             test_vector->id);

  uint8_t output[DUMBAES_BLOCKSIZE] = { 0 };

  // Perform key expansion.
  dumbAES_status_t status = dumbAES_encrypt(test_vector->input, 
                                            DUMBAES_BLOCKSIZE,
                                            output, 
                                            DUMBAES_BLOCKSIZE, 
                                            test_vector->key, 
                                            key_size);

  TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(test_vector->expected_output,
                               output,
                               DUMBAES_BLOCKSIZE);
}

void test_encrypt_128(void)
{
  for (size_t i = 0; i < sizeof(encrypt_test_vectors_128) / sizeof(aes_test_vector_t); ++i) {
    test_encrypt(&encrypt_test_vectors_128[i], 16);
  }
}

void test_encrypt_192(void)
{
  for (size_t i = 0; i < sizeof(encrypt_test_vectors_192) / sizeof(aes_test_vector_t); ++i) {
    test_encrypt(&encrypt_test_vectors_192[i], 24);
  }
}

void test_encrypt_256(void)
{
  for (size_t i = 0; i < sizeof(encrypt_test_vectors_256) / sizeof(aes_test_vector_t); ++i) {
    test_encrypt(&encrypt_test_vectors_256[i], 32);
  }
}

/******************************************************************************/
// Test runner
/******************************************************************************/

int main(void) 
{
  UNITY_BEGIN();

  // Run tests.
  RUN_TEST(test_encrypt_128, __LINE__);
  RUN_TEST(test_encrypt_192, __LINE__);
  RUN_TEST(test_encrypt_256, __LINE__);

  return UNITY_END();
}