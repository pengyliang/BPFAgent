# clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -D__KERNEL__ \
#     -Ienv/4.19/linux-headers-4.19.325/include \
#     -Ienv/4.19/linux-headers-4.19.325/include/uapi \
#     -Ienv/4.19/linux-headers-4.19.325/arch/x86/include \
#     -Ienv/4.19/linux-headers-4.19.325/arch/x86/include/uapi \
#     -Ienv/4.19/linux-headers-4.19.325/include/generated \
#     -Ienv/4.19/linux-headers-4.19.325/arch/x86/include/generated \
#     -c /host/data/feature/isa_upgrade_incompatible/isa_upgrade_incompatible.bpf.c \
#     -o /host/output/4.19/build/feature/isa_upgrade_incompatible/isa_upgrade_incompatible.bpf.o

clang -O2 -g -target bpf \
    -I/usr/include/x86_64-linux-gnu \
    -c /host/data/feature/isa_upgrade_incompatible/isa_upgrade_incompatible.bpf.c \
    -o /host/output/4.19/build/feature/isa_upgrade_incompatible/isa_upgrade_incompatible.bpf.o
    