#ifndef __KANAWHA__X64_VENDOR_H__
#define __KANAWHA__X64_VENDOR_H__

#define X64_VENDOR_XLIST(X)\
X(UNKNOWN,       "Unknown")\
X(INTEL,         "GenuineIntel")\
X(AMD,           "AuthenticAMD")\
X(AMD_OLD,       "AMDisbetter!")\
X(VIA,           "VIA VIA VIA ")\
X(TRANSMETA,     "GenuineTMx86")\
X(TRANSMETA_OLD, "TransmetaCPU")\
X(CYRIX,         "CyrixInstead")\
X(CENTAUR,       "CentaurHauls")\
X(NEXGEN,        "NexGenDriven")\
X(UMC,           "UMC UMC UMC ")\
X(SIS,           "SiS SiS SiS ")\
X(NSC,           "Geode by NSC")\
X(RISE,          "RiseRiseRise")\
X(VORTEX,        "Vortex86 SoC")\
X(AO486,         "MiSTer AO486")\
X(AO486_OLD,     "GenuineAO486")\
X(ZHAOXIN,       "  Shanghai  ")\
X(HYGON,         "HygonGenuine")\
X(ELBRUS,        "E2K MACHINE ")\
X(QEMU,          "TCGTCGTCGTCG")\
X(KVM,           " KVMKVMKVM  ")\
X(VMWARE,        "VMwareVMware")\
X(VIRTUALBOX,    "VBoxVBoxVBox")\
X(XEN,           "XenVMMXenVMM")\
X(HYPERV,        "Microsoft Hv")\
X(PARALLELS,     " prl hyperv ")\
X(PARALLELS_ALT, " lrpepyh vr ")\
X(BHYVE,         "bhyve bhyve ")\
X(QNX,           " QNXQVMBSQG ")\

typedef enum x64_vendor
{
#define X64_VENDOR_ENUM(__NAME, ...)\
    X64_VENDOR_ ## __NAME,
X64_VENDOR_XLIST(X64_VENDOR_ENUM)
#undef X64_VENDOR_ENUM

} x64_vendor_t;

x64_vendor_t
x64_get_vendor(void);

const char *
x64_vendor_string(x64_vendor_t vendor);

#endif
