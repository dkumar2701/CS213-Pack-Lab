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


int main(void) {

  // Test the LFSR implementation
  int result = test_lfsr_step();
  if (result != 0) {
    printf("Error when testing LFSR implementation\n");
    return 1;
  }

  // TODO - add tests here for other functionality
  // You can craft arbitrary array data as inputs to the functions
  // Parsing headers, checksumming, decryption, and decompressing are all testable

  printf("All tests passed successfully!\n");
  return 0;
}

