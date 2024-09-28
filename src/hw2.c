#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "hw2.h"
#define MAX_COMPLETION_SIZE 1024  

// Helper function to get a specific range of bits from an integer
unsigned int get_bits(unsigned int value, int start, int end) {
    return (value >> start) & ((1U << (end - start + 1)) - 1);
}

void print_packet(unsigned int packet[]) {
    // Extracting the first 32-bit integer (int[0])
    unsigned int length = get_bits(packet[0], 0, 9);  // Length is bits 0-9
    unsigned int packet_type = get_bits(packet[0], 29, 31);  // Packet Type bits 29-31

    // Extracting the second 32-bit integer (int[1])
    unsigned int requester_id = get_bits(packet[1], 16, 31);  // Requester ID is bits 16-31
    unsigned int tag = get_bits(packet[1], 8, 15);  // Tag is bits 8-15
    unsigned int last_be = get_bits(packet[1], 4, 7);  // Last BE is bits 4-7
    unsigned int first_be = get_bits(packet[1], 0, 3);  // First BE is bits 0-3

    // Extracting the third 32-bit integer (int[2])
    unsigned int address = (packet[2] >> 2);  // Address is bits 2-31

    printf("%d\n", packet_type);
    printf("%d\n", address);
    printf("%d\n", length);
    printf("%d\n", requester_id);
    printf("%d\n", tag);
    printf("%d\n", last_be);
    printf("%d\n", first_be);

    if (packet_type == 2) {  // Memory Write Request
        for (unsigned int i = 3; i < 3 + length; i++) {
            int data = (int)packet[i];  // Treating data as signed
            printf("%d\n", data);
        }
    }
}

void store_values(unsigned int packets[], char *memory)
{
    int packet_index = 0;
    while (1) {
        unsigned int *packet = &packets[packet_index];
        
        // Check if this is a valid Write Request packet
        if ((packet[0] & 0xC0000000) != 0x40000000) {
            break;  // Not a Write Request, stop processing
        }

        unsigned int address = (packet[2] & 0xFFFFFFFC);
        unsigned int length = packet[0] & 0x3FF;
        unsigned int first_be = packet[1] & 0xF;
        unsigned int last_be = (packet[1] >> 4) & 0xF;

        // Check if address is within 1MB range
        if (address >= 1024 * 1024) {
            packet_index += 3 + length;
            continue;  // Skip this packet
        }

        for (unsigned int i = 0; i < length; i++) {
            unsigned int data = packet[i + 3];
            unsigned int be = (i == 0) ? first_be : ((i == length - 1) ? last_be : 0xF);

            for (int j = 0; j < 4; j++) {
                if (be & (1 << j)) {
                    memory[address + (i * 4) + j] = (data >> (j * 8)) & 0xFF;
                }
            }
        }

        packet_index += 3 + length;
    }
}



unsigned int* create_completion(unsigned int packets[], const char *memory)
{
    static unsigned int completions[MAX_COMPLETION_SIZE];
    int completion_count = 0;
    int packet_index = 0;

    while (1) {
        unsigned int *packet = &packets[packet_index];
        
        // Check if this is a valid Read Request packet
        if ((packet[0] & 0xC0000000) != 0x00000000) {
            break;  // Not a Read Request, stop processing
        }

        unsigned int address = (packet[2] & 0xFFFFFFFC);
        unsigned int length = packet[0] & 0x3FF;
        unsigned int requester_id = (packet[1] >> 16) & 0xFFFF;
        unsigned int tag = (packet[1] >> 8) & 0xFF;
        unsigned int first_be = packet[1] & 0xF;
        unsigned int last_be = (packet[1] >> 4) & 0xF;

        unsigned int remaining_length = length;
        unsigned int current_address = address;

        while (remaining_length > 0) {
            unsigned int completion_length = remaining_length;
            if ((current_address & 0x3FFF) + (completion_length * 4) > 0x4000) {
                completion_length = (0x4000 - (current_address & 0x3FFF)) / 4;
            }

            // Check if we have enough space in the completions array
            if (completion_count + 3 + completion_length >= MAX_COMPLETION_SIZE) {
                // Handle error: buffer overflow
                return NULL;
            }

            // Construct completion header
            completions[completion_count] = 0x4A000000 | completion_length;
            completions[completion_count + 1] = (220 << 16) | (remaining_length * 4);
            completions[completion_count + 2] = (requester_id << 16) | (tag << 8) | (current_address & 0x7F);

            // Copy data from memory to completion payload
            for (unsigned int i = 0; i < completion_length; i++) {
                unsigned int data = 0;
                unsigned int be = (i == 0) ? first_be : ((i == remaining_length - 1) ? last_be : 0xF);

                for (int j = 0; j < 4; j++) {
                    if (be & (1 << j)) {
                        data |= (unsigned int)(memory[current_address + (i * 4) + j]) << (j * 8);
                    }
                }

                completions[completion_count + 3 + i] = data;
            }

            completion_count += 3 + completion_length;
            remaining_length -= completion_length;
            current_address += completion_length * 4;
        }

        packet_index += 3;
    }

    // Add a terminating entry
    if (completion_count < MAX_COMPLETION_SIZE) {
        completions[completion_count] = 0;
    } else {
        // Handle error: no space for terminating entry
        return NULL;
    }

    // Allocate and copy to a new buffer of exact size
    unsigned int *result = malloc((completion_count + 1) * sizeof(unsigned int));
    if (result == NULL) {
        // Handle error: malloc failed
        return NULL;
    }
    memcpy(result, completions, (completion_count + 1) * sizeof(unsigned int));

    return result;
}