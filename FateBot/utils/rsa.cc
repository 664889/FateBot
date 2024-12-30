#include "rsa.hh"
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <string>

std::string base64Encode(const unsigned char *buffer, size_t length) {
  BIO *bio = BIO_new(BIO_s_mem());
  BIO *b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);
  std::string encodedData(bufferPtr->data, bufferPtr->length);
  BIO_free_all(bio);
  return encodedData;
}

std::string Utility::sign(const std::string &uuid) {

  std::string privateKeyStr =
      "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIICWAIBAAKBgLkG1MbGaKzsCnfEz/v5Pv0mSffavUujhNKjmAAUdlBuE6v+uxMH\n"
      "ezdep9kH1FZRZHtYRjN1M6oeqckKVMhK82DMkoRxjCjwyknnM6VKO8uMbI3jbZwE\n"
      "jEv7yyNjxNIF7jVq5ifJujc13uainCQw2Y2UyJD3pmSgZp7xkt9vM9lVAgMBAAEC\n"
      "gYAdGhn1edeU+ztaQzaDZ1yk7JTNyzXi48FMcDbELHO/itDFSLeb8p1KxDSaSkT3\n"
      "nq2zSNsh1NlfdJs358wWBNPqrSBOEQGrcwUqob59mLQysxddE8HKN0kN7ZfLiebp\n"
      "y1xHxTqV1VEBmTlon9sMyYa5wbjJ8teSBQnvXP5JCnw2sQJAytZc/rIxKSazx2is\n"
      "os89qJFkzIEK4QhopCvSiDWarsYRi79KIxizrL0PCK0qAu6OXFsy5F2Ei+YXw++I\n"
      "Hhgx2wJA6YVwCKnGybW5hDKy7+XdFPpy0mhLxcGMWo9LQKCCSTKXqj6IOH3HOvnc\n"
      "iXN7NUf/TwN6mFzrsBHzyKrXJhAAjwJAnNIhMfW41nUKt9hw6KtLo4FNqmL2c0da\n"
      "B9utuQugnRGbzSzG992IRLwi3HVtLrkbrcIA1diLutHZe+48ke/o0wJANVdPogr1\n"
      "53llKPdTvEyrVXFn7Pv54vA1GTKGI/sGB6ZQ0oh6IT1J1wTgBV2llSQfA3Nt+4Ou\n"
      "KofPQdUUVBNvrQJAeFeVPpvWJTiMWCN2NMmJXqqdva8J1XIT047x5fdg72LcPOU+\n"
      "xCGlz9vV3+AAQ31C2phoyd/QhvpL85p39n6Ibg==\n"
      "-----END RSA PRIVATE KEY-----";
  // Load private key from string
  BIO *bio = BIO_new_mem_buf((void *)privateKeyStr.data(), -1);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (!pkey) {
    std::cerr << "Error reading private key" << std::endl;
    return "";
  }

  // Create context for the signing operation
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *pkey_ctx = NULL;

  if (EVP_DigestSignInit(ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) <= 0) {
    std::cerr << "Error initializing DigestSign" << std::endl;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return "";
  }

  // Hash the UUID and sign it
  if (EVP_DigestSignUpdate(ctx, uuid.c_str(), uuid.size()) <= 0) {
    std::cerr << "Error during DigestSignUpdate" << std::endl;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return "";
  }

  // Finalize the signature
  size_t sigLen = 0;
  if (EVP_DigestSignFinal(ctx, NULL, &sigLen) <= 0) {
    std::cerr << "Error finalizing DigestSign" << std::endl;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return "";
  }

  unsigned char *signature = (unsigned char *)OPENSSL_malloc(sigLen);
  if (!signature) {
    std::cerr << "Error allocating memory for signature" << std::endl;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return "";
  }

  if (EVP_DigestSignFinal(ctx, signature, &sigLen) <= 0) {
    std::cerr << "Error obtaining final signature" << std::endl;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
    return "";
  }

  // Base64 encode the signature
  std::string encodedSignature = base64Encode(signature, sigLen);

  // Cleanup
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  OPENSSL_free(signature);

  return encodedSignature;
}