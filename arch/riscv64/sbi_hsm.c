
#include <arch/riscv64/sbi_hsm.h>
#include <arch/riscv64/sbi.h>

#include <kanawha/init.h>

#define SBI_HSM_EXTID 0x48534D

static int hsm_support = 0;
static int hsm_support_errno = -EDEFER;
static int
sbi_probe_hsm_support(void)
{
    int res;
    res = sbi_probe_extension(SBI_HSM_EXTID);
    if(res) {
        hsm_support = 0;
        hsm_support_errno = res;
        return 0;
    }

    hsm_support = 1;
    hsm_support_errno = 0;
    return 0;
}
declare_init_desc(post_topo, sbi_probe_hsm_support, "Probing SBI HSM Extension Support");

int
sbi_hart_start(
        hartid_t hartid,
        void __phys *start_addr,
        uint64_t opaque)
{
    if(!hsm_support) {
        return hsm_support_errno;
    }

    struct sbiret ret;
    ret = sbi_ecall(
            SBI_HSM_EXTID,
            0x0, // function id
            hartid,
            (uintptr_t)start_addr,
            opaque,
            0,
            0,
            0);
    int res = sbiret_to_errno(&ret);
    if(res) {
        return res;
    }

    return 0;
}

int
sbi_hart_get_status(
        hartid_t hartid)
{
    if(!hsm_support) {
        return hsm_support_errno;
    }

    struct sbiret ret;
    ret = sbi_ecall(
            SBI_HSM_EXTID,
            0x2, // function id
            hartid,
            0,
            0,
            0,
            0,
            0);
    int res = sbiret_to_errno(&ret);
    if(res < 0) {
        return res;
    }

    return ret.value;
}

