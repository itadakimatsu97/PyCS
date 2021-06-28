// Include standard I/O declarations
#include <stdio.h>
// Include string declarations
#include <string.h>
// Program entry point
int main(int argc, char** argv) {
    // Terminate if program is not run with three parameters.
    if (argc != 4) {
        // Print out the proper use of the program
        puts("./a.out <size> <offset> <string>");
        // Return failure
        return -1;
    }
    // Convert size to an integer
    int size = atoi(argv[1]);
    // Convert offset to an integer
    int offset = atoi(argv[2]);
    // Place string into its own string on the stack
    char* str = argv[3];
    // Declare a 256 byte buffer on the stack
    char buffer[256];
    // Print the location of the buffer for calculating the offset.
    printf("Buffer:\t\t%8x\n", &buffer);
    // Fill the buffer with the letter 'A'.
    memset(buffer, 65, 255);
    // Null-terminate the buffer.
    buffer[255] = 0;
    // Attempt to copy the string into the specified location.
    strncpy(buffer + offset, str, size);
    // Print out the buffer.
    printf('%s', buffer);
    // Return success
    return 0;
}