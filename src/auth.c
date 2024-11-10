// Connection management using the master password.

#include "auth.h"
#include "password_manager.h"
/**
* Construct the path of the master password file depending on the username.
*
* @param username The username of the user
* @param file_path The buffer where the file path will be stored
*/
void generate_master_password_file_path(const char *username, char* file_path) {
    // So it is like a printf but instead of printing it will store the result in the file_path variable so a buffer.
    // https://cplusplus.com/reference/cstdio/snprintf/

    snprintf(file_path, MASTER_PASSWORD_SIZE, "%s%s.gpg", MASTER_PASSWORD_FILE_PATH_PREFIX, username);
}

void generate_password_file_path(const char *username, char* file_path) {
    snprintf(file_path, FILE_PATH_SIZE, "%s%s.gpg", PASSWORD_MANAGER_PATH_PREFIX, username);
}
/**
 * Manage the user session by authenticating the user and setting up their password manager (if it exists).
 *
 * @param authenticated_username The buffer to store the authenticated username
 * @param key The buffer where the derived key will be stored
 * @return 1 if authentication is successful, 0 otherwise
 */
int manage_user_session(char *authenticated_username, unsigned char* key) {
    char username[USERNAME_SIZE];
    char file_path[FILE_PATH_SIZE];

    printf("[?] - Enter your username: ");
    fgets(username, USERNAME_SIZE, stdin);
    username[strcspn(username, "\n")] = 0;

    if (!check_if_master_password_exists(username)) {
        printf("[+] - Master password created.\n");
    }


    generate_password_file_path(username, file_path);

    unsigned char iv[IV_SIZE];
    setup_user_password_file(username, iv);


    char passwd[MASTER_PASSWORD_SIZE];
    printf("[?] - Enter your master password: ");
    fgets(passwd, MASTER_PASSWORD_SIZE, stdin);
    passwd[strcspn(passwd, "\n")] = 0;

    if (verify_master_password(username, passwd, key)) {
        printf("[+] - Welcome %s.\n", username);
        strncpy(authenticated_username, username, USERNAME_SIZE);
        return 1;
    } else {
        printf("[!] - Authentication failed for user %s.\n", username);
        return 0;
    }
}

/**
* Create a master password for a user if that one does not exist. That one will be stored in a file.
*
* @param username The username of the user
*/
void create_master_password(const char *username) {
    // Method allowing the creation of a master password during the user first connection.
    char passwd[MASTER_PASSWORD_SIZE];
    char passwd_confirm[MASTER_PASSWORD_SIZE];
    char file_path[FILE_PATH_SIZE];

    generate_master_password_file_path(username, file_path);
    //printf("[DEBUG] - Path for master password file: %s\n", file_path);



    printf("[?] - Type your new master password: ");
    fgets(passwd, MASTER_PASSWORD_SIZE, stdin);
    passwd[strcspn(passwd, "\n")] = 0;

    printf("[?] - Confirm your new master password: ");
    fgets(passwd_confirm, MASTER_PASSWORD_SIZE, stdin);
    passwd_confirm[strcspn(passwd_confirm, "\n")] = 0;

    if (strcmp(passwd, passwd_confirm) != 0) {
        printf("[!] - Passwords do not match.\n");
        return;
    }

    unsigned char hash[SHA1_HASH_SIZE];
    unsigned int hash_size;
    sha1_hash(passwd, strlen(passwd), hash, &hash_size); // I will use it to encrypt and decrypt the password manager file (and I will not store the key because bad !)

    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "[X] - Error generating IV.\n");
        return;
    }

    // Here I encrypt the Magic String that I will use to check if the password is correct (so the key is correct)

    unsigned char encrypted_magic[strlen(MAGIC_STRING) + EVP_MAX_BLOCK_LENGTH]; // I add some padding to be sure to have enough space
    size_t encrypted_len = aes_encrypt((unsigned char*)MAGIC_STRING, strlen(MAGIC_STRING), hash, iv, encrypted_magic);
    if (encrypted_len <= 0) {
        fprintf(stderr, "[X] - Error encrypting magic string.\n");
        return;
    }

    FILE *password_file = fopen(file_path, "wb");
    if (password_file == NULL) {
        fprintf(stderr, "[X] - Error creating master password file.\n");
        return;
    }

    if (fwrite(iv, sizeof(unsigned char), IV_SIZE, password_file) != IV_SIZE) {
        fprintf(stderr, "[X] - Error writing IV to file.\n");
        fclose(password_file);
        return;
    }

    // I need to write the length of the encrypted magic string to the file so I can read it later.
    // I need to put that in clear because I need to know how many bytes I need to read to get the encrypted magic string
    // I don't think it's a problem but it gives some information to an attacker.
    if (fwrite(&encrypted_len, sizeof(size_t), 1, password_file) != 1) {
        fprintf(stderr, "[X] - Error writing encrypted length to file.\n");
        close_file(password_file);
        return;
    }

    if (fwrite(encrypted_magic, 1, encrypted_len, password_file) != encrypted_len) {
        fprintf(stderr, "[X] - Error writing encrypted magic string to file.\n");
        close_file(password_file);
        return;
    }


    printf("[+] - Master Password file created successfully for user: %s.\n", username);

    close_file(password_file);

    /*
      So I have a file where I stock in that order :
        - IV
        - Size of the encrypted magic string
        - Encrypted magic string
     */

}

/**
* Verify if the master password is correct for a user. I check if the hash of the password is the same as the one stored in the file.
* If it is the case, I store the hash in the key buffer.
*
* @param username The username of the user
* @param passwd The password to verify
*/
int verify_master_password(const char* username, const char *passwd, unsigned char* key) {
    char file_path[FILE_PATH_SIZE];
    generate_master_password_file_path(username, file_path);
    //printf("[DEBUG] - Path for master password file: %s\n", file_path);

    unsigned int input_hash_size;
    sha1_hash(passwd, strlen(passwd), key, &input_hash_size); // I hash the password to try to decrypt the magic string.

    FILE *password_file = open_file(file_path, "rb");
    if (password_file == NULL) {
        printf("[!] - Error opening master password file for %s.\n", username);
        return 0;
    }


    unsigned char iv[IV_SIZE];
    if (fread(iv, sizeof(unsigned char), IV_SIZE, password_file) != IV_SIZE) {
        fprintf(stderr, "[!] - Error reading IV from file.\n");
        fclose(password_file);
        return 0;
    }

    size_t encrypted_len;
    if (fread(&encrypted_len, sizeof(size_t), 1, password_file) != 1) {
        fprintf(stderr, "[!] - Error reading encrypted length from file.\n");
        fclose(password_file);
        return 0;
    }


    //printf("[DEBUG] - Encrypted Length Read: %zu\n", encrypted_len);

    unsigned char *encrypted_magic = malloc(encrypted_len);
    if (encrypted_magic == NULL) {
        printf("[X] - Memory allocation failed.\n");
        close_file(password_file);
        return 0;
    }

    if (fread(encrypted_magic, 1, encrypted_len, password_file) != encrypted_len) {
        printf("[!] - Error reading encrypted magic string.\n");
        free(encrypted_magic);
        close_file(password_file);
        return 0;
    }


    unsigned char decrypted_magic[strlen(MAGIC_STRING)];
    aes_decrypt(encrypted_magic, encrypted_len, key, iv, decrypted_magic);
    free(encrypted_magic);
    fclose(password_file);

    //printf("[DEBUG] - Decrypted magic string: %s\n", decrypted_magic);

    if (memcmp(decrypted_magic, MAGIC_STRING, strlen(MAGIC_STRING)) != 0) {
        printf("[!] Incorrect password.\n");
        return 0;
    }

    printf("[+] - Master password is correct.\n");
    return 1;

}

/**
* Check if a master password exists for a user so if that one already have a password manager.
*
* @param username The username of the user
* @return 0 if the user does not have a master password, 1 otherwise (no need to create a new one)
*/
int check_if_master_password_exists(const char *username) {
    char file_path[FILE_PATH_SIZE];
    generate_master_password_file_path(username, file_path);

    FILE *master_passwd_file = open_file(file_path, "rb");

    if (master_passwd_file == NULL) {
        printf("[!] - No master password found for %s.\n", username);
        create_master_password(username);
        return 0;
    } else {
        printf("[+] - Master password found for %s.\n", username);
        close_file(master_passwd_file);
        return 1;
    }
}



