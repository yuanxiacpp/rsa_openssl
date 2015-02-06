#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <string>

#define KEY_LENGTH  2048
#define PUB_EXP     3
int encrypt_len = 1;
std::string pri_key, pub_key;
bool generateRSAKeys() {
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char* prikey = (char*)malloc(pri_len + 1);
    char* pubkey = (char*)malloc(pub_len + 1);

    BIO_read(pri, prikey, pri_len);
    BIO_read(pub, pubkey, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    printf("\n%s\n%s\n", prikey, pubkey);
    pri_key(prikey);
    pub_key(pubkey);
    return true;
}
std::string encryptWithPub(char* msg) {
    char* encrypt;
    RSA *rsa = NULL;
    BIO* keybio = BIO_new_mem_buf(pub_key, -1);
    if (keybio == NULL) {
        printf("failed to create key BIO\n");
        return "false";
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    int encrypt_len;
    char *err = (char*)malloc(130);
    if ((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt, 
                                          rsa, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return "false";
    }
    printf("encrypted message: %s\n", encrypt);
    return std::string(encrypt);

}
std::string decryptWtihPri(char* msg) {
    char* decrypt = (char*)malloc(encrypt_len);
    RSA *rsa = NULL;
    BIO* keybio = BIO_new_mem_buf(pri_key.c_str(), -1);
    if (keybio == NULL) {
        printf("failed to create key BIO\n");
        return "false";
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    char *err = (char*)malloc(130);
    if (RSA_private_decrypt(encrypt_len, (unsigned char*)msg, (unsigned char*) decrypt, rsa,
                            RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        return "false";
    }
    printf("Decrypted message: %s\n", decrypt);
    return std::string(decrypt);
}

int main() {
    if (!generateRSAKeys())
        printf("generateRSAKeys error\n");

    std::string test("just for testing purpose");
    decryptWtihPri(encryptWithPub(test.c_str()).c_str());

    
/*
    // Get the message to encrypt
    printf("Message to encrypt: ");
    fgets(msg, KEY_LENGTH-1, stdin);
    msg[strlen(msg)-1] = '\0';

    // Encrypt the message
    encrypt = (char*)malloc(RSA_size(keypair));
    int encrypt_len;
    err = (char*)malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return 1;
    }

    printf("Encrypted message: %s\n", encrypt);
    
    // Decrypt it
    decrypt = (char*)malloc(encrypt_len);
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        return 1;
    }
    printf("Decrypted message: %s\n", decrypt);

  */  
    return 0;
}