// this is for lazy peoples to store password locally with ZipCrypto Encryption !!
#include <stdlib.h>
#include <stdio.h>

int main() {
    const char *filename = "password.txt";
    const char *zipname = "password.zip";

    // Command to zip with encryption
    char zip_command[256];
    snprintf(zip_command, sizeof(zip_command),
             "zip -e %s %s", zipname, filename);

    // Run zip command (this will prompt for password)
    int result = system(zip_command);
    if (result != 0) {
        fprintf(stderr, "Error: zip command failed.\n");
        return 1;
    }

    // Delete the original file
    char rm_command[256];
    snprintf(rm_command, sizeof(rm_command),
             "rm %s", filename);

    result = system(rm_command);
    if (result != 0) {
        fprintf(stderr, "Error: failed to delete %s\n", filename);
        return 1;
    }

    printf("File zipped and original deleted successfully.\n");
    return 0;
}

