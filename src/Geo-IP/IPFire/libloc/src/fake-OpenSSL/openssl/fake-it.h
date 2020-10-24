#ifndef OpenSSL_fake_it_h
#define OpenSSL_fake_it_h

/*
 * Overrides for 'openssl/include/err.h':
 */
#define ERR_get_error()           0
#define ERR_error_string(err, x)  "faked error"

/*
 * Overrides for 'openssl/include/pem.h':
 */
#define PEM_read_PUBKEY(file, pkey, pem_password_cb, user_data) NULL
#define PEM_read_PrivateKey(bio, pkey, pem_password_cb, user)   NULL

/*
 * Overrides for 'openssl/include/evp.h':
 */
#define EVP_PKEY              void
#define EVP_MD_CTX            void
#define EVP_MD_CTX_new()      NULL
#define EVP_MD_CTX_free(ctx)  ((void)0)
#define EVP_PKEY_free(key)    ((void)0)

#define EVP_DigestVerifyInit(ctx, pctx, md_type, engine, key)  0
#define EVP_DigestVerifyUpdate(ctx, data, data_len)            0
#define EVP_DigestVerifyFinal(ctx, sig, sig_len)               0

#define EVP_DigestSignInit(ctx, pctx, type, engine, pkey)  0
#define EVP_DigestSignUpdate(ctx, data, len)               0
#define EVP_DigestSignFinal(ctx, sig, sig_len)             0

#endif