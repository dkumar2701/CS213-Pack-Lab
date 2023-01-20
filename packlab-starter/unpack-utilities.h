// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Definitions
#define DICTIONARY_LENGTH 16
#define ESCAPE_BYTE 0x07
#define MAX_RUN_LENGTH 16

// Struct to hold header configuration data
typedef struct {
  size_t data_offset;
  bool should_decompress;
  uint8_t dictionary_data[DICTIONARY_LENGTH];
  bool should_decrypt;
  bool should_checksum;
  uint16_t checksum_value;
} packlab_config_t;


// Prints error message and then exits the program with a return code of one
void error_and_exit(const char* message);

// Allocates `size` bytes of heap data and returns a pointer to it
// Faults and exits the program if malloc fails
void* malloc_and_check(size_t size);

// Parses the header data to determine configuration for the packed file
// Configuration information is written into config
// Any unnecessary fields in config are left untouched
void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config);

// Decompresses input data, creating output data
// Returns the length of valid data inside the output data (<=output_len)
// Expects a previously calculated compression dictionary
// Writes uncompressed data directly into `output_data`
size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data);

// Returns the next LFSR state
// Implemented with a fixed LFSR 
// Does not save state internally. To iterate, update as oldstate = lfsr_step(oldstate)
uint16_t lfsr_step(uint16_t oldstate);

// Decrypts input data, creating output data
// Writes decrypted data directly into `output_data`
void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key);

// Calculates a 16-bit checksum value over input data
uint16_t calculate_checksum(uint8_t* input_data, size_t input_len);

