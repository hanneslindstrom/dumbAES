#include <stdio.h>
#include <string.h>

#include "unity.h"

#include "dumbAES_cipher.h"
#include "dumbAES_transformations.h"
#include "dumbAES_status.h"
#include "dumbAES_internal.h"
#include "dumbAES_defines.h"

#include "test_transformations_data.c"

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

void test_sub_bytes(void)
{
  for (size_t i = 0;
       i < sizeof(sub_bytes_test_vectors) / sizeof(state_test_vector_t);
       ++i) {
  
    printf("Testing sub_bytes with test vector #%zu\n", 
               sub_bytes_test_vectors[i].id);

    state_t test_state = { 0 };

    // Manually copy test input to state.
    memcpy(test_state.bytes, 
           sub_bytes_test_vectors[i].input, 
           DUMBAES_NB * 4);

    // Perform transformation.
    dumbAES_status_t status = sub_bytes(&test_state);

    TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(sub_bytes_test_vectors[i].expected_output,
                                 test_state.bytes,
                                 DUMBAES_NB * 4);
  }
}

void test_shift_rows(void)
{
  for (size_t i = 0;
       i < sizeof(shift_rows_test_vectors) / sizeof(state_test_vector_t);
       ++i) {
  
    printf("Testing shift_rows with test vector #%zu\n", 
               shift_rows_test_vectors[i].id);

    state_t test_state = { 0 };

    // Manually copy test input to state.
    memcpy(test_state.bytes, 
           shift_rows_test_vectors[i].input, 
           DUMBAES_NB * 4);

    // Perform transformation.
    dumbAES_status_t status = shift_rows(&test_state);

    TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(shift_rows_test_vectors[i].expected_output,
                                 test_state.bytes,
                                 DUMBAES_NB * 4);
  }
}

void test_mix_columns(void)
{
  for (size_t i = 0;
       i < sizeof(mix_columns_test_vectors) / sizeof(state_test_vector_t);
       ++i) {
  
    printf("Testing mix_columns with test vector #%zu\n", 
               mix_columns_test_vectors[i].id);

    state_t test_state = { 0 };

    // Manually copy test input to state.
    memcpy(test_state.bytes, 
           mix_columns_test_vectors[i].input, 
           DUMBAES_NB * 4);

    // Perform transformation.
    dumbAES_status_t status = mix_columns(&test_state);

    TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(mix_columns_test_vectors[i].expected_output,
                                 test_state.bytes,
                                 DUMBAES_NB * 4);
  }
}

void test_add_round_key(void)
{
  for (size_t i = 0;
       i < sizeof(add_round_key_test_vectors) / sizeof(state_test_vector_t);
       ++i) {
  
    printf("Testing add_round_key with test vector #%zu\n", 
               add_round_key_test_vectors[i].id);

    state_t test_state = { 0 };

    // Manually copy test input to state.
    memcpy(test_state.bytes, 
           add_round_key_test_vectors[i].input, 
           DUMBAES_NB * 4);

    round_key_t round_key = { 0 };
    memcpy(&round_key.bytes, &add_round_key_test_vectors[i].round_key, 16);

    // Perform transformation.
    dumbAES_status_t status = add_round_key(&test_state, &round_key);

    TEST_ASSERT_EQUAL_INT(DUMBAES_STATUS_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(add_round_key_test_vectors[i].expected_output,
                                 test_state.bytes,
                                 DUMBAES_NB * 4);
  }
}

/******************************************************************************/
// Test runner
/******************************************************************************/

int main(void) 
{
  UNITY_BEGIN();

  // Run tests.
  RUN_TEST(test_sub_bytes, __LINE__);
  RUN_TEST(test_shift_rows, __LINE__);
  RUN_TEST(test_mix_columns, __LINE__);
  RUN_TEST(test_add_round_key, __LINE__);

  return UNITY_END();
}

