
#include <arch/riscv64/sbi.h>
#include <arch/riscv64/sbi_ipi.h>

#include <kanawha/init.h>

#define SBI_IPI_EXTID 0x735049
#define SBI_IPI_EXTID_LEGACY 0x4

static int sbi_ipi_found = 0;
static int sbi_ipi_errno = -EDEFER;

int
sbi_send_ipi(hartid_t hartid)
{
    int res;

    if(!sbi_ipi_found)
    {
        return sbi_ipi_errno;
    }

    struct sbiret ret;
    ret = sbi_ecall(SBI_IPI_EXTID,
                    0x0, // function id
                    1,
                    hartid,
                    0,
                    0,
                    0,
                    0);

    res = sbiret_to_errno(&ret);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
sbi_ipi_extension_init(void)
{
    int res;

    res = sbi_probe_extension(SBI_IPI_EXTID);
    if(res)
    {
        sbi_ipi_errno = -ENXIO;
        return res;
    }

    sbi_ipi_found = 1;
    sbi_ipi_errno = 0;

    return 0;
}
declare_init_desc(post_topo,
                  sbi_ipi_extension_init,
                  "Initializing SBI IPI Extension");
