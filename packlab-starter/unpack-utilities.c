// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {

  // TODO
  // Validate the header and set configurations based on it
  // Call error_and_exit() if the header is invalid or input_len is shorter than expected
    if (input_data[0] != 0x02 || input_data[1] != 0x13) {
        error_and_exit("ERROR: magic bytes or version byte are incorrect.");
    }
    if (input_data[2] != 0x01) {
        error_and_exit("ERROR: magic bytes or version byte are incorrect.");
    }

    //check if size is correct
    if (input_len < 4){
      error_and_exit("ERROR: header length is incorrect");
    }

    //check if last 5 bits are 0's
    if ((input_data[3] & 0x00) != 0x00){
      error_and_exit("ERROR: unused bits are not 0.");
    }

  
    config->should_decompress = 0;
    config->should_checksum = 0;
    config->should_decrypt = 0;

    if ((input_data[3] & 0x80) == 0x80) {
        for (int i = 4; i < 20; i++) {
            config->dictionary_data[i - 4] = input_data[i];
        }
        config->should_decompress = 1;
    }
    if ((input_data[3] & 0x20) == 0x20) {
        if (config->should_decompress == 1) {
            config->checksum_value = ((uint16_t)input_data[20] << 8) | input_data[21];
            config->should_checksum = 1;
        }
        else if(config->should_decompress == 0) {
            config->checksum_value = ((uint16_t)input_data[4] << 8) | input_data[5];
            config->should_checksum = 1;
        }
    }
    if ((input_data[3] & 0x40) == 0x40) {
        config->should_decrypt = 1;
    }
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {

  // TODO
  // Calculate a checksum over input_data
  // Return the checksum value
    uint16_t sumdata = 0;
    for (int i = 0; i < input_len; i++) {
        sumdata += input_data[i];
    }
  return sumdata;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state
    uint16_t newstate = 0;
    newstate = ((((oldstate << 15) ^ (oldstate << 4)) ^ (oldstate << 2)) ^ (oldstate << 1)) & 0x8000;
    newstate = newstate | ((oldstate >> 1) & 0x7fff);
  return newstate;
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in big-endian order
  // Beware: input_data may be an odd number of bytes
    uint16_t newkey = encryption_key;
    for (int i = 0; i < input_len; i = i+2) {
        output_data[i] = ((uint8_t)newkey >> 8) ^ input_data[i];
        if (i + 1 < input_len) {
            output_data[i + 1] = ((uint8_t)newkey & 0x00ff) ^ input_data[i + 1];
            newkey = lfsr_step(newkey);
        }
    }
}

size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data
    size_t output_index = 0;
    uint8_t loop_num = 0;
    for (int i = 0; i < input_len - 1; i++) {
        if (input_data[i] == 0x07 && input_data[i + 1] != 0x00) {
            loop_num = (input_data[i + 1] >> 4) & 0x0f;
            for (int j = 0; j < loop_num; j++) {
                output_data[output_index] = dictionary_data[(input_data[i + 1] & 0x0f)];
                output_index = output_index + 1;
            }
            i = i + 2;
        }
        else {
            output_data[output_index] = input_data[i];
            output_index = output_index + 1;
        }
        output_data[output_index] = input_data[input_len - 1];
        output_index = output_index + 1;
    }
    return output_index;
}

