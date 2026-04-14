#include "chimera.h"

static struct crypto_skcipher *aes_tfm = NULL;
static struct crypto_akcipher  *rsa_tfm = NULL;

static const __u8 rsa_pub_key[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    /* 256 bytes of modulus + exponent follow placeholder, replace on build */
    0x00, 0xAA, 0xBB, 0xCC, /* ... full 256-byte N || 0x010001 (e=65537) */
    /* Total: 294 bytes. mutator.py fills this from your generated keypair. */
};
static const size_t rsa_pub_len = sizeof(rsa_pub_key);

int aes256_init(const __u8 *key, const __u8 *iv)
{
    int ret;

    if (aes_tfm)
        crypto_free_skcipher(aes_tfm);

    aes_tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(aes_tfm))
        return PTR_ERR(aes_tfm);

    ret = crypto_skcipher_setkey(aes_tfm, key, AES_KEY_SIZE);
    if (ret)
        goto err;

    memcpy(g_state.aes_iv, iv, AES_BLOCK_SIZE);
    return 0;

err:
    crypto_free_skcipher(aes_tfm);
    aes_tfm = NULL;
    return ret;
}

static int aes_cbc_crypt(const __u8 *in, __u8 *out, size_t len, int encrypt)
{
    struct skcipher_request *req = NULL;
    struct scatterlist src_sg, dst_sg;
    DECLARE_CRYPTO_WAIT(wait);
    __u8 *padded_in = NULL;
    size_t padded_len;
    int ret, pad_bytes;

    if (!aes_tfm || len == 0)
        return -EINVAL;

    pad_bytes = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    padded_len = len + pad_bytes;

    padded_in = kzalloc(padded_len, GFP_KERNEL);
    if (!padded_in)
        return -ENOMEM;

    memcpy(padded_in, in, len);
    memset(padded_in + len, pad_bytes, pad_bytes);

    req = skcipher_request_alloc(aes_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  crypto_req_done, &wait);

    sg_init_one(&src_sg, padded_in, padded_len);
    sg_init_one(&dst_sg, out, padded_len);

    __u8 frame_iv[AES_BLOCK_SIZE];
    memcpy(frame_iv, g_state.aes_iv, AES_BLOCK_SIZE);
    frame_iv[0] ^= (g_state.seq_num >> 24) & 0xFF;
    frame_iv[1] ^= (g_state.seq_num >> 16) & 0xFF;
    frame_iv[2] ^= (g_state.seq_num >> 8)  & 0xFF;
    frame_iv[3] ^=  g_state.seq_num        & 0xFF;

    if (encrypt)
        ret = crypto_skcipher_encrypt(req);
    else
        ret = crypto_skcipher_decrypt(req);

    ret = crypto_wait_req(ret, &wait);

    skcipher_request_free(req);
out:
    kfree(padded_in);
    return ret == 0 ? (int)padded_len : ret;
}

int aes256_encrypt(const __u8 *in, __u8 *out, size_t len)
{
    return aes_cbc_crypt(in, out, len, 1);
}

int aes256_decrypt(const __u8 *in, __u8 *out, size_t len)
{
    return aes_cbc_crypt(in, out, len, 0);
}

int rsa_encrypt_session_key(const __u8 *session_key, __u8 *out, size_t *out_len)
{
    struct akcipher_request *req = NULL;
    struct scatterlist src_sg, dst_sg;
    DECLARE_CRYPTO_WAIT(wait);
    __u8 padded_key[RSA_KEY_SIZE];
    int ret;

    if (rsa_tfm)
        crypto_free_akcipher(rsa_tfm);

    rsa_tfm = crypto_alloc_akcipher("rsa", 0, 0);
    if (IS_ERR(rsa_tfm))
        return PTR_ERR(rsa_tfm);

    ret = crypto_akcipher_set_pub_key(rsa_tfm, rsa_pub_key, rsa_pub_len);
    if (ret)
        goto err;

    memset(padded_key, 0x00, RSA_KEY_SIZE);
    padded_key[0] = 0x00;
    padded_key[1] = 0x02;
    get_random_bytes(padded_key + 2, RSA_KEY_SIZE - 3 - AES_KEY_SIZE);
    for (int i = 2; i < RSA_KEY_SIZE - AES_KEY_SIZE - 1; i++) {
        while (padded_key[i] == 0x00)
            get_random_bytes(&padded_key[i], 1);
    }
    padded_key[RSA_KEY_SIZE - AES_KEY_SIZE - 1] = 0x00;
    memcpy(padded_key + RSA_KEY_SIZE - AES_KEY_SIZE, session_key, AES_KEY_SIZE);

    req = akcipher_request_alloc(rsa_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto err;
    }

    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  crypto_req_done, &wait);

    sg_init_one(&src_sg, padded_key, RSA_KEY_SIZE);
    sg_init_one(&dst_sg, out, RSA_KEY_SIZE);
    akcipher_request_set_crypt(req, &src_sg, &dst_sg, RSA_KEY_SIZE, RSA_KEY_SIZE);

    ret = crypto_wait_req(crypto_akcipher_encrypt(req), &wait);
    if (ret == 0)
        *out_len = RSA_KEY_SIZE;

    akcipher_request_free(req);
err:
    crypto_free_akcipher(rsa_tfm);
    rsa_tfm = NULL;
    return ret;
}

void rk_crypto_cleanup(void)
{
    if (aes_tfm) {
        crypto_free_skcipher(aes_tfm);
        aes_tfm = NULL;
    }
    if (rsa_tfm) {
        crypto_free_akcipher(rsa_tfm);
        rsa_tfm = NULL;
    }
    memset(g_state.session_key, 0, AES_KEY_SIZE);
    memset(g_state.aes_iv, 0, AES_BLOCK_SIZE);
}
