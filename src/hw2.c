#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "hw2.h"
// Helper function to get a specific range of bits from an integer
unsigned int get_bits(unsigned int value, int start, int end) {
    return (value >> start) & ((1U << (end - start + 1)) - 1);
}

void print_packet(unsigned int packet[]) {
    // Extract header fields
    unsigned int type = (packet[0] >> 30) & 0x3;
    
    // Check for invalid packet type
    if (type != 0 && type != 1) {
        printf("No Output (invalid packet)\n");
        return;
    }

    unsigned int length = packet[0] & 0x3FF;
    unsigned int requester_id = (packet[1] >> 16) & 0xFFFF;
    unsigned int tag = (packet[1] >> 8) & 0xFF;
    unsigned int last_be = (packet[1] >> 4) & 0xF;
    unsigned int first_be = packet[1] & 0xF;
    unsigned int address = packet[2];
    unsigned int address_offset = address & 0x3;  // Get the 2 least significant bits
    address = (address & 0xFFFFFFFC) + address_offset;  // Apply the offset


    // Print packet type with "Packet Type: " prefix
    printf("Packet Type: %s\n", (type == 0) ? "Read" : "Write");

    // Print the fields in the correct order
    printf("Address: %d\n", address);
    printf("Length: %d\n", length);
    printf("Requester ID: %d\n", requester_id);
    printf("Tag: %d\n", tag);
    printf("Last BE: %d\n", last_be);
    printf("1st BE: %d\n", first_be);

    // If it's a Write Request, print the payload data
    if (type == 1) {  // Write Request
        printf("Data:");
        for (unsigned int i = 0; i < length; i++) {
            printf(" %d", (int)packet[3 + i]);
          // Print data payload as signed integers
        }
        printf(" ");
        printf("\n");
    } else {  // Read Request
        printf("Data: \n");
    }
}


void store_values(unsigned int packets[], char *memory) {
    unsigned int *packet = packets;
    while (1) {
        unsigned int type = get_bits(packet[0], 30, 31);
        if (type != 1) break;  // Stop if not a Write Request

        unsigned int length = get_bits(packet[0], 0, 9);
        unsigned int first_be = get_bits(packet[1], 0, 3);
        unsigned int last_be = get_bits(packet[1], 4, 7);
        unsigned int address = get_bits(packet[2], 2, 31) * 4;  // Convert to byte address

        if (address >= 1024 * 1024) {  // Check if address is within 1MB
            packet += 3 + length;  // Move to next packet
            continue;
        }

        for (unsigned int i = 0; i < length; i++) {
            unsigned int data = packet[3 + i];
            unsigned int be = (i == 0) ? first_be : (i == length - 1) ? last_be : 0xF;

            for (int j = 0; j < 4; j++) {
                if (be & (1 << j)) {
                    memory[address + i * 4 + j] = (data >> (j * 8)) & 0xFF;
                }
            }
        }

        packet += 3 + length;  // Move to next packet
    }
}

#define COMPLETER_ID 220
#define MEMORY_SIZE (1024 * 1024)  // 1MB memory size
#define MAX_COMPLETIONS (MEMORY_SIZE / 4 + 3 * (MEMORY_SIZE / 0x4000 + 1))  // Worst case: entire memory + headers

unsigned int* create_completion(unsigned int packets[], const char *memory) {
    unsigned int *completions = malloc(MAX_COMPLETIONS * sizeof(unsigned int));
    if (!completions) return NULL;

    unsigned int completion_index = 0;
    unsigned int *current_packet = packets;

    while (1) {
        unsigned int type = get_bits(current_packet[0], 30, 31);
        if (type != 0) break;  // Stop if not a Read Request

        unsigned int length = get_bits(current_packet[0], 0, 9);
        unsigned int requester_id = get_bits(current_packet[1], 16, 31);
        unsigned int tag = get_bits(current_packet[1], 8, 15);
        unsigned int first_be = get_bits(current_packet[1], 0, 3);
        unsigned int last_be = get_bits(current_packet[1], 4, 7);
        unsigned int address = get_bits(current_packet[2], 2, 31) * 4;
        unsigned int address_offset = get_bits(current_packet[2], 0, 1);
        address += address_offset;  // Apply the offset

        // Calculate total byte count considering byte enable fields
        unsigned int total_byte_count = length * 4;
        if (length == 1) {
            total_byte_count = __builtin_popcount(first_be);
        } else if (length > 1) {
            total_byte_count -= 4 - __builtin_popcount(first_be);
            total_byte_count -= 4 - __builtin_popcount(last_be);
        }

        unsigned int remaining_byte_count = total_byte_count;
        unsigned int current_address = address;

        while (remaining_byte_count > 0) {
            unsigned int chunk_size = 0x4000 - (current_address % 0x4000);
            if (chunk_size > remaining_byte_count) {
                chunk_size = remaining_byte_count;
            }

            unsigned int chunk_length = (chunk_size + 3) / 4;

            // Ensure we have enough space in completions array
            if (completion_index + chunk_length + 3 >= MAX_COMPLETIONS) {
                free(completions);
                return NULL;  // Buffer overflow, return NULL
            }

            // Completion header
            completions[completion_index++] = 0x4A000000 | chunk_length;
            completions[completion_index++] = (COMPLETER_ID << 16) | remaining_byte_count;
            completions[completion_index++] = (requester_id << 16) | (tag << 8) | (current_address & 0x7F);

            // Copy data from memory to completions
            for (unsigned int i = 0; i < chunk_length; i++) {
                unsigned int data = 0;
                for (int j = 0; j < 4 && (i * 4 + j) < chunk_size; j++) {
                    if (current_address + i * 4 + j < MEMORY_SIZE) {
                        data |= (unsigned char)memory[current_address + i * 4 + j] << (j * 8);
                    }
                }
                completions[completion_index++] = data;
            }

            current_address += chunk_size;
            remaining_byte_count -= chunk_size;
        }

        current_packet += 3;  // Move to next packet
    }

    // Add terminating 0
    if (completion_index < MAX_COMPLETIONS) {
        completions[completion_index] = 0;
    } else {
        free(completions);
        return NULL;  // Buffer overflow, return NULL
    }

    return completions;
}