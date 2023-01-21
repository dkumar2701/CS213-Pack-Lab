// Application to test unpack utilities
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


int test_lfsr_step(void) {
  // A properly created LFSR should do two things
  //  1. It should generate specific new state based on a known initial state
  //  2. It should iterate through all 2^16 integers, once each (except 0)

  // Create an array to track if the LFSR hit each integer (except 0)
  // 2^16 possibilities
  bool* lfsr_states = malloc_and_check(1<<16);
  memset(lfsr_states, 0, 1<<16);

  // Initial 16 LFSR states
  uint16_t correct_lfsr_states[16] = {0x1337, 0x899B, 0x44CD, 0x2266,
                                      0x9133, 0xC899, 0xE44C, 0x7226,
                                      0x3913, 0x9C89, 0x4E44, 0x2722,
                                      0x9391, 0xC9C8, 0x64E4, 0x3272};

  // Step the LFSR until a state repeats
  bool repeat = false;
  size_t steps = 0;
  uint16_t new_state = 0x1337; // known initial state
  while (!repeat) {

    // Iterate LFSR
    steps++;
    new_state = lfsr_step(new_state);

    // Check if this state has already been reached
    repeat = lfsr_states[new_state];
    lfsr_states[new_state] = true;

    // Check first 16 LFSR steps
    if(steps < 16) {
      if (new_state != correct_lfsr_states[steps]) {
        printf("ERROR: at step %lu, expected state 0x%04X but received state 0x%04X\n",
            steps, correct_lfsr_states[steps], new_state);
        free(lfsr_states);
        return 1;
      }
    }
  }

  // Check that all integers were hit. Should take 2^16 steps (2^16-1 integers, plus a repeat)
  if (steps != 1<<16) {
    printf("ERROR: expected %d iterations before a repeat, but ended after %lu steps\n", 1<<16, steps);
    free(lfsr_states);
    return 1;
  }

  // Cleanup
  free(lfsr_states);
  return 0;
}

//parse no compress, checksum, encrypt
int test_parse_good(void){
  uint8_t header[4] = {0x02, 0x13, 0x01, 0x00 };
  packlab_config_t config;
  parse_header(&header[0], 4, &config);

  if (config.should_checksum != 0 || config.should_decompress != 0 || config.should_decrypt != 0){
    printf("ERROR: expected compress: %d, checksum: %d, encrypt: %d, got %d, %d, %d", 0, 0, 0, config.should_decompress, config.should_checksum, config.should_decrypt);
    return 1;
  }

  if (config.data_offset != 4){
    printf("ERROR: Data Offset is incorrect\n");
    return 1;
  }
  return 0;
 

}

//parse yes compress, no checksum, no encrypt
int test_parse_compress(void){
  uint8_t header2[20] = {0x02, 0x13, 0x01, 0x80, 
                         0x02, 0xAF, 0x76, 0x92, 
                         0xB3, 0x83, 0xD8, 0x81, 
                         0x54, 0xAC, 0xB2, 0x34, 
                         0x78, 0x12, 0x13, 0xB8};
  packlab_config_t config2;
  parse_header(&header2[0], 20, &config2);

  
  if (config2.should_checksum != 0 || config2.should_decompress != 1 || config2.should_decrypt != 0){
    printf("ERROR: expected compress: %d, encrypt: %d, checksum: %d, got %d, %d, %d", 1, 0, 0, config2.should_decompress, config2.should_checksum, config2.should_decrypt);
    return 1;
  }

  if (config2.data_offset != 20){
    printf("ERROR: Data Offset is incorrect\n");
    return 1;
  }
  
  return 0;
 
}

//parse yes checksum, no compress, no encrypt
int test_parse_checksum(void){
  uint8_t header2[20] = {0x02, 0x13, 0x01, 0x20, 
                         0x02, 0xAF};
  packlab_config_t config2;
  parse_header(&header2[0], 6, &config2);

  
  if (config2.should_checksum != 1 || config2.should_decompress != 0 || config2.should_decrypt != 0){
    printf("ERROR: expected compress: %d, encrypt: %d, checksum: %d, got %d, %d, %d", 0, 0, 1, config2.should_decompress, config2.should_checksum, config2.should_decrypt);
    return 1;
  }

  if (config2.checksum_value != 0x02AF){
    printf("ERROR: checksum value is incorrect.");
    return 1;
  }

  if (config2.data_offset != 6){
    printf("ERROR: Data Offset is incorrect\n");
    return 1;
  }
  
  return 0;
 
}


//parse all
int test_parse_all(void){
  uint8_t header2[22] = {0x02, 0x13, 0x01, 0xE0, 
                         0x02, 0xAF, 0x76, 0x92, 
                         0xB3, 0x83, 0xD8, 0x81, 
                         0x54, 0xAC, 0xB2, 0x34, 
                         0x78, 0x12, 0x13, 0xB8,
                         0x12, 0x34};
  packlab_config_t config2;
  parse_header(&header2[0], 22, &config2);

  
  if (config2.should_checksum != 1 || config2.should_decompress != 1 || config2.should_decrypt != 1){
    printf("ERROR: expected compress: %d, encrypt: %d, checksum: %d, got %d, %d, %d", 1, 1, 1, config2.should_decompress, config2.should_checksum, config2.should_decrypt);
    return 1;
  }
  
  if (config2.checksum_value != 0x1234){
    printf("ERROR: checksum value is incorrect.");
    return 1;
  }

  if (config2.data_offset !=22){
    printf("ERROR: Data offset is incorrect");
    return 1;
  }

  return 0;
 
}



//TESTING calculate_checksum
int test_checksum(void){
  uint8_t data[4] = {0x12, 0x31, 0x01, 0x03};

  uint16_t expected_value = 0x47;
  uint16_t calculated = calculate_checksum(&data[0], 4);

  if (calculated != expected_value){
    printf("ERROR: Checksum calculation wrong. Expected %u, received %u \n", expected_value, calculated);
    return 1;
  }

  return 0;

}

int main(void) {

  // Test the LFSR implementation
  int result = test_lfsr_step();
  if (result != 0) {
    printf("Error when testing LFSR implementation\n");
    return 1;
  }
  
  int resultparse= test_parse_good();
  if (resultparse != 0){
    printf("Error when testing parse_good");
    return 1;
  }
  
  int resultparsecompress= test_parse_compress();
  if (resultparsecompress != 0){
    printf("Error when testing parse_compress");
    return 1;
  }
  
  int resultparsechecksum= test_parse_checksum();
  if (resultparsechecksum != 0){
    printf("Error when testing parse_checksum");
    return 1;
  }

  int resultparseall= test_parse_all();
  if (resultparseall != 0){
    printf("Error when testing parse_all");
    return 1;
  }

  //TESTS FOR calculate_checksum()

  int resultchecksum= test_checksum();
  if (resultchecksum != 0){
    printf("Error when testing checksum");
    return 1;
  }

  // TODO - add tests here for other functionality
  // You can craft arbitrary array data as inputs to the functions
  // Parsing headers, checksumming, decryption, and decompressing are all testable

  printf("All tests passed successfully!\n");
  return 0;
}

