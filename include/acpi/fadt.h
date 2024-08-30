#ifndef __KANAWHA__ACPI_FADT_H__
#define __KANAWHA__ACPI_FADT_H__

#include <kanawha/stdint.h>
#include <acpi/table.h>
#include <acpi/gas.h>

#define FADT_SIG_STRING "FACP"

#define DECLARE_U8_CONSTANTS(__NAME, __VAL, ...)\
    const static uint8_t __NAME = __VAL;

#define ACPI_FADT_PM_PROFILE_XLIST(X)\
X(ACPI_FADT_PM_PROFILE_UNSPEC,            0)\
X(ACPI_FADT_PM_PROFILE_DESKTOP,           1)\
X(ACPI_FADT_PM_PROFILE_MOBILE,            2)\
X(ACPI_FADT_PM_PROFILE_WORKSTATION,       3)\
X(ACPI_FADT_PM_PROFILE_ENTERPRISE_SERVER, 4)\
X(ACPI_FADT_PM_PROFILE_SOHO_SERVER,       5)\
X(ACPI_FADT_PM_PROFILE_APPLIANCE_PC,      6)\
X(ACPI_FADT_PM_PROFILE_PERF_SERVER,       7)\
X(ACPI_FADT_PM_PROFILE_TABLET,            8)
ACPI_FADT_PM_PROFILE_XLIST(DECLARE_U8_CONSTANTS)

#undef DECLARE_U8_CONSTANTS

#define ACPI_FADT_FLAG_WBINVD                (1ULL<<0)
#define ACPI_FADT_FLAG_WBINVD_FLUSH          (1ULL<<1)
#define ACPI_FADT_FLAG_PROC_C1               (1ULL<<2)
#define ACPI_FADT_FLAG_P_LVL2_UP             (1ULL<<3)
#define ACPI_FADT_FLAG_PWR_BUTTON            (1ULL<<4)
#define ACPI_FADT_FLAG_SLP_BUTTON            (1ULL<<5)
#define ACPI_FADT_FLAG_FIX_RTC               (1ULL<<6)
#define ACPI_FADT_FLAG_RTC_S4                (1ULL<<7)
#define ACPI_FADT_FLAG_TMR_VAL_EXT           (1ULL<<8)
#define ACPI_FADT_FLAG_DCK_CAP               (1ULL<<9)
#define ACPI_FADT_FLAG_RESET_REG_SUP         (1ULL<<10)
#define ACPI_FADT_FLAG_SEALED_CASE           (1ULL<<11)
#define ACPI_FADT_FLAG_HEADLESS              (1ULL<<12)
#define ACPI_FADT_FLAG_CPU_SW_SLP            (1ULL<<13)
#define ACPI_FADT_FLAG_PCI_EXP_WAK           (1ULL<<14)
#define ACPI_FADT_FLAG_USE_PLATFORM_CLOCK    (1ULL<<15)
#define ACPI_FADT_FLAG_S4_RTC_STS_VALID      (1ULL<<16)
#define ACPI_FADT_FLAG_REMOTE_POWER_ON_CAP   (1ULL<<17)
#define ACPI_FADT_FLAG_FORCE_APIC_CLUSTER    (1ULL<<18)
#define ACPI_FADT_FLAG_FORCE_APIC_PHYS       (1ULL<<19)
#define ACPI_FADT_FLAG_HW_REDUCED_ACPI       (1ULL<<20)
#define ACPI_FADT_FLAG_LOW_POWER_S0_IDLE_CAP (1ULL<<21)
#define ACPI_FADT_FLAG_PERSISTENT_CPU_CACHES (1ULL<<22)

#define ACPI_FADT_IAPC_BOOT_ARCH_LEGACY_DEVICES       (1ULL<<0)
#define ACPI_FADT_IAPC_BOOT_ARCH_8042                 (1ULL<<1)
#define ACPI_FADT_IAPC_BOOT_ARCH_VGA_NOT_PRESENT      (1ULL<<2)
#define ACPI_FADT_IAPC_BOOT_ARCH_MSI_NOT_PRESENT      (1ULL<<3)
#define ACPI_FADT_IAPC_BOOT_ARCH_NO_PCIE_ASPM_CTRL    (1ULL<<4)
#define ACPI_FADT_IAPC_BOOT_ARCH_CMOS_RTC_NOT_PRESENT (1ULL<<5)

#define ACPI_FADT_ARM_BOOT_ARCH_PSCI_COMPLIANT (1ULL<<0)
#define ACPI_FADT_ARM_BOOT_ARCH_PSCI_USE_HVC   (1ULL<<1)

struct acpi_fadt {
    struct acpi_table_hdr hdr;
    uint32_t facs_ptr;
    uint32_t dsdt_ptr;
    uint8_t __resv_0;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t sci_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alarm;
    uint8_t month_alarm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t __resv_1;
    uint32_t flags;
    struct acpi_gas reset_reg;
    uint8_t reset_value;
    uint16_t arm_boot_arch;
    uint8_t minor_version;
    uint64_t facs_xptr;
    uint64_t dsdt_xptr;
    struct acpi_gas x_pm1a_evt_blk;
    struct acpi_gas x_pm1b_evt_blk;
    struct acpi_gas x_pm1a_cnt_blk;
    struct acpi_gas x_pm1b_cnt_blk;
    struct acpi_gas x_pm2_cnt_blk;
    struct acpi_gas x_pm_tmr_blk;
    struct acpi_gas x_gpe0_blk;
    struct acpi_gas x_gpe1_blk;
    struct acpi_gas sleep_ctrl_reg;
    struct acpi_gas sleep_status_reg;
    uint64_t hypervisor_vendor_id;
};

#endif
