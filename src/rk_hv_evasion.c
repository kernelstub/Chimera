#include "chimera.h"

#define RDTSC_SAMPLES     100
#define RDTSC_THRESHOLD   500

static inline __u64 rdtsc_raw(void)
{
    unsigned int low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((__u64)high << 32) | low;
}

static int detect_cpuid_leaf1(void)
{
    unsigned int eax, ebx, ecx, edx;

    eax = 0x1;
    cpuid(&eax, &ebx, &ecx, &edx);

    return (ecx >> 31) & 0x1;
}

static int detect_cpuid_hv_vendor(char *vendor_out, size_t max_len)
{
    unsigned int eax, ebx, ecx, edx;
    char vendor[13];

    eax = 0x40000000;
    cpuid(&eax, &ebx, &ecx, &edx);

    if (eax == 0)
        return 0;

    memcpy(vendor,     &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';

    if (strstr(vendor, "VMware")  ||
        strstr(vendor, "Microsoft") ||
        strstr(vendor, "KVMKVMKVM") ||
        strstr(vendor, "XenVMMXen") ||
        strstr(vendor, "VBoxVBoxVBox") ||
        strstr(vendor, "QNXQNXQNX")) {
        if (vendor_out)
            strscpy(vendor_out, vendor, max_len);
        return 1;
    }

    return 0;
}

static int detect_msr_vmcontrol(void)
{
    u64 msr_val;
    int vmxon_locked, vmx_enabled;

    rdmsrl(MSR_IA32_FEATURE_CONTROL, msr_val);

    vmxon_locked = (msr_val >> 0) & 0x1;
    vmx_enabled  = (msr_val >> 2) & 0x1;

    if (vmxon_locked && !boot_cpu_has(X86_FEATURE_VMX))
        return 1;

    return 0;
}

static int detect_rdtsc_variance(void)
{
    __u64 t1, t2, delta;
    __u64 deltas[RDTSC_SAMPLES];
    __u64 sum = 0, sum_sq = 0, mean, variance;
    int spike_count = 0;

    for (int i = 0; i < 10; i++)
        rdtsc_raw();

    for (int i = 0; i < RDTSC_SAMPLES; i++) {
        t1 = rdtsc_raw();
        t2 = rdtsc_raw();
        delta = t2 - t1;
        deltas[i] = delta;
        sum += delta;
    }

    mean = sum / RDTSC_SAMPLES;

    for (int i = 0; i < RDTSC_SAMPLES; i++) {
        __u64 diff = deltas[i] - mean;
        sum_sq += diff * diff;
        if (deltas[i] > RDTSC_THRESHOLD)
            spike_count++;
    }

    variance = sum_sq / RDTSC_SAMPLES;

    if (spike_count > (RDTSC_SAMPLES / 10))
        return 1;

    if (variance > 10000)
        return 1;

    return 0;
}

static int detect_cpuinfo_flag(void)
{
    struct file *fp;
    char buf[4096];
    loff_t pos = 0;
    ssize_t n;
    int ret = 0;

    fp = filp_open("/proc/cpuinfo", O_RDONLY, 0);
    if (IS_ERR(fp))
        return 0;

    n = kernel_read(fp, buf, sizeof(buf) - 1, &pos);
    filp_close(fp, NULL);

    if (n <= 0)
        return 0;

    buf[n] = '\0';
    if (strstr(buf, "hypervisor"))
        ret = 1;

    memset(buf, 0, sizeof(buf));
    return ret;
}

static int detect_dmi_vendor(void)
{
    struct file *fp;
    char buf[256];
    loff_t pos = 0;
    ssize_t n;
    int ret = 0;

    const char *dmi_paths[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
        NULL
    };

    const char *vm_strings[] = {
        "QEMU", "VMware", "VirtualBox", "VirtIO", "innotek",
        "Xen", "KVM", "Bochs", "Microsoft Corporation",
        NULL
    };

    for (int i = 0; dmi_paths[i]; i++) {
        fp = filp_open(dmi_paths[i], O_RDONLY, 0);
        if (IS_ERR(fp))
            continue;

        n = kernel_read(fp, buf, sizeof(buf) - 1, &pos);
        filp_close(fp, NULL);

        if (n > 0) {
            buf[n] = '\0';
            if (n > 0 && buf[n-1] == '\n')
                buf[n-1] = '\0';

            for (int j = 0; vm_strings[j]; j++) {
                if (strcasestr(buf, vm_strings[j])) {
                    ret = 1;
                    goto out;
                }
            }
        }
        memset(buf, 0, sizeof(buf));
        pos = 0;
    }

out:
    memset(buf, 0, sizeof(buf));
    return ret;
}

int rk_hv_detect(struct hv_info *out)
{
    int score = 0;

    memset(out, 0, sizeof(*out));

    out->cpuid_leaf1 = detect_cpuid_leaf1();
    score += out->cpuid_leaf1;

    score += detect_cpuid_hv_vendor(out->vendor, sizeof(out->vendor));

    out->msr_vmxon = detect_msr_vmcontrol();
    score += out->msr_vmxon;

    out->rdtsc_variance = detect_rdtsc_variance();
    score += out->rdtsc_variance;

    score += detect_cpuinfo_flag();
    score += detect_dmi_vendor();

    out->detected = (score >= 2);

    return out->detected;
}
