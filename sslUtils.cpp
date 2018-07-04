//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <iostream>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"

BIO *bio_err = 0;


int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

int pem_passwd_cb(char *buf, int size, int rwflag, void *password) {
 const char *pwd = "123456";
 strcpy(buf, pwd);
 return (strlen(buf));
}

//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	/* In this function, you handle
	 * 1) The SSL handshake between the server and the client.
	 * 2) Authentication
	 * 		a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
	 * 		b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
	 */
	/*Initialize the SSL library and loads all SSL algorithms and error message*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	/* choose the method as its connection method */
	if(role == 0)
		ctx = SSL_CTX_new(SSLv23_server_method());
	else
		ctx = SSL_CTX_new(SSLv23_client_method());


	/*	Loads server/client's own certificate */
	if (SSL_CTX_use_certificate_file(ctx,certfile,SSL_FILETYPE_PEM) <= 0)
	{
		printf("Certificate error!\n");
		berr_exit("The certificate of user has error!\n");
	}

	/* Loads the private key of the identify certificate */
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
	if(SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) <= 0)
	{
		printf("Private key error!\n");
		berr_exit("The private key has error!\n");
	}

	/* Check whether the loaded public and private keys match */
	if (SSL_CTX_check_private_key(ctx) < 1)
	{
		printf("The private key and public key does not match!");
		berr_exit("The private key and public key does not match!");
	}

	/* Loads the trust certificate store for given context */
	SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL);

	/* Configure how the context shall verify peer's certificate */
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);//set the verify mode as verify the peer or verify fail with no peer certificate

	/* Rejects if the presented certificate is not signed by the trusted CA */
	ssl = SSL_new(ctx);

	if (SSL_get_verify_result(ssl) != X509_V_OK){
		printf("Certificate doesn't verify!");
		berr_exit("Certificate doesn't verify!");
	}

	/* set up a secure channel */
	BIO *bio; //create a object bio
	bio = BIO_new_socket(contChannel,BIO_NOCLOSE);
	SSL_set_bio(ssl, bio, bio);
	int r = 4;
	/* create ssl connection between server and client */
	//server
	if (role == 0)
	{
		r = SSL_accept(ssl);
		if (r != 1)
		{
			printf("accept error! %i %i\n", SSL_get_error(ssl, r), r);
			berr_exit("accept error!\n");
		}
	}
	//client
	else
	{
		r = SSL_connect(ssl);
		if (r != 1)
		{
			printf("%i %i", SSL_get_error(ssl, r), r);
			berr_exit("connection error!\n");
		}
		/*Check the common name*/
		X509 *peer;
		char peer_CN[256];
		/* Set default common name */
		const char *CommonName = "TP Server shimin@kth.se jzhe@kth.se";
		peer = SSL_get_peer_certificate(ssl);
		/* Get common name */
		X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
		/* Check the common name, client rejects if it is not match the default common name */
		if (strcasecmp(peer_CN, CommonName)){
			printf("Common name doesn't match default common name\n");
			berr_exit("Common name doesn't match default common name\n");
		}
	}



	  printf("Finish set up \n");


	  return ssl;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


/*AES 256 key length is 256 bit while iv is 128 bit, since the unsigned char's length is in bytes*/
int keyLen = 32;
int ivLen = 16;
unsigned char *key = new unsigned char[keyLen];
unsigned char *iv = new unsigned char[ivLen];
void dataChannelKeyExchange(int role, SSL *ssl) {
	/* In this function, you handle
	 * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
	 * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
	 */
    /* Server generates Key and iv and send to the client */
	if(role == 0){
	for (int i = 0; i < 32; i++){
		key[i] = (unsigned char)rand();
	}
	SSL_write(ssl, key, keyLen);

	for (int i = 0; i < 16; i++){
			iv[i] = (unsigned char)rand();
		}
	SSL_write(ssl, iv, ivLen);
	}
	/* Client receives the key and iv, checks the length of key and iv */
	else{
	int r;
	r = SSL_read(ssl, key, keyLen);
	if (r != keyLen)
	{
		printf("Key's length is wrong!");
		berr_exit("The key's length is wrong!");
	}

	r = SSL_read(ssl, iv, ivLen);
	if (r != ivLen)
	{
		printf("iv's length is wrong!");
		berr_exit("iv's length is wrong!");
	}
	}
}

int encrypt(unsigned char *plainText, int plainTextLen,
		unsigned char *cipherText) {
	/* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
	 * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */
//	memcpy(cipherText, plainText, plainTextLen);
//	return plainTextLen;
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertextLen;

	  /* Create and initialise the context */
	  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
	   * and IV size appropriate for your cipher
	   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	   * IV size for *most* modes is the same as the block size. For AES this
	   * is 128 bits */
	  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	    handleErrors();

	  /* Provide the message to be encrypted, and obtain the encrypted output.
	   * EVP_EncryptUpdate can be called multiple times if necessary
	   */
	  if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
	    handleErrors();
	  ciphertextLen = len;

	  /* Finalise the encryption. Further ciphertext bytes may be written at
	   * this stage.
	   */
	  if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) handleErrors();
	  ciphertextLen += len;

	  /* Clean up */
	  EVP_CIPHER_CTX_free(ctx);

	  return ciphertextLen;

}

int decrypt(unsigned char *cipherText, int cipherTextLen,
		unsigned char *plainText) {
	/* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
	 * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */
//	memcpy(plainText, cipherText, cipherTextLen);
//	return cipherTextLen;

	if(cipherTextLen % 16 != 0){
		return 0;
	}
	  EVP_CIPHER_CTX *ctx;

	  int len;

	  int plaintextLen;

	  /* Create and initialise the context */
	  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
	   * and IV size appropriate for your cipher
	   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	   * IV size for *most* modes is the same as the block size. For AES this
	   * is 128 bits */
	  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	    handleErrors();

	  /* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */
	  if(1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
	    handleErrors();
	  plaintextLen = len;

	  /* Finalise the decryption. Further plaintext bytes may be written at
	   * this stage.
	   */
	  if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
	  plaintextLen += len;

	  /* Clean up */
	  EVP_CIPHER_CTX_free(ctx);

	  return plaintextLen;

}

