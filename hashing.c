#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 8192  // Buffer size for file reading

void hash_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;
    size_t bytesRead;

    // Create and initialize the EVP_MD_CTX context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("Error creating EVP_MD_CTX");
        fclose(file);
        return;
    }

    // Initialize the digest operation (SHA-256)
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("Error initializing digest");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    // Read the file and update the hash calculation
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            perror("Error updating digest");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }

    // Finalize the hash
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_length) != 1) {
        perror("Error finalizing digest");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    fclose(file);

    // Free the EVP_MD_CTX context
    EVP_MD_CTX_free(mdctx);

    // Print the hash in hexadecimal format
    printf("SHA-256 hash of file %s:\n", filename);
    for (unsigned int i = 0; i < hash_length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    hash_file(argv[1]);
    return 0;
}
