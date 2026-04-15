#ifndef __KANAWHA__USB_XHCI_REG_H__
#define __KANAWHA__USB_XHCI_REG_H__

#include <drivers/usb/xhci/xhci.h>

#define USB_XHCI_PCI_CLASS (0x0C)
#define USB_XHCI_PCI_SUBCLASS (0x03)
#define USB_XHCI_PCI_PROG_IF (0x30)

// NAME, SIZE, REGISTER-SET, OFFSET
#define USB_XHCI_REG_XLIST(X)                                                  \
    X(CAPLENGTH, 8, CAP, 0x00)                                                 \
    X(HCIVERSION, 16, CAP, 0x02)                                               \
    X(HCSPARAMS1, 32, CAP, 0x04)                                               \
    X(HCSPARAMS2, 32, CAP, 0x08)                                               \
    X(HCSPARAMS3, 32, CAP, 0x0C)                                               \
    X(HCCPARAMS1, 32, CAP, 0x10)                                               \
    X(DBOFF, 32, CAP, 0x14)                                                    \
    X(RTSOFF, 32, CAP, 0x18)                                                   \
    X(HCCPARAMS2, 32, CAP, 0x1C)                                               \
    X(VTIOSOFF, 32, CAP, 0x20)                                                 \
    X(USBCMD, 32, OP, 0x00)                                                    \
    X(USBSTS, 32, OP, 0x04)                                                    \
    X(PAGESIZE, 32, OP, 0x08)                                                  \
    X(DNCTRL, 32, OP, 0x14)                                                    \
    X(CRCR, 64, OP, 0x18)                                                      \
    X(DCBAAP, 64, OP, 0x30)                                                    \
    X(CONFIG, 32, OP, 0x38)                                                    \
    X(MFINDEX, 32, RUNTIME, 0x00)

// FIELD, REG, MSB, LSB
#define USB_XHCI_FIELD_XLIST(X)                                                \
                                                                               \
    X(MaxSlots, HCSPARAMS1, 8, 0)                                              \
    X(MaxIntrs, HCSPARAMS1, 18, 8)                                             \
    X(MaxPorts, HCSPARAMS1, 31, 24)                                            \
                                                                               \
    X(IST, HCSPARAMS2, 3, 0)                                                   \
    X(ERST_Max, HCSPARAMS2, 7, 4)                                              \
    X(SPR, HCSPARAMS2, 26, 26)                                                 \
    X(Max_Scratchpad_Bufs_Hi, HCSPARAMS2, 25, 21)                              \
    X(Max_Scratchpad_Bufs_Lo, HCSPARAMS2, 31, 27)                              \
                                                                               \
    X(U1_Device_Exit_Latency, HCSPARAMS3, 7, 0)                                \
    X(U2_Device_Exit_Latency, HCSPARAMS3, 31, 16)                              \
                                                                               \
    X(AC64, HCCPARAMS1, 0, 0)                                                  \
    X(BNC, HCCPARAMS1, 1, 1)                                                   \
    X(CSZ, HCCPARAMS1, 2, 2)                                                   \
    X(PPC, HCCPARAMS1, 3, 3)                                                   \
    X(PIND, HCCPARAMS1, 4, 4)                                                  \
    X(LHRC, HCCPARAMS1, 5, 5)                                                  \
    X(LTC, HCCPARAMS1, 6, 6)                                                   \
    X(NSS, HCCPARAMS1, 7, 7)                                                   \
    X(PAE, HCCPARAMS1, 8, 8)                                                   \
    X(SPC, HCCPARAMS1, 9, 9)                                                   \
    X(SEC, HCCPARAMS1, 10, 10)                                                 \
    X(CFC, HCCPARAMS1, 11, 11)                                                 \
    X(MaxPSASize, HCCPARAMS1, 15, 12)                                          \
    X(xECP, HCCPARAMS1, 31, 16)                                                \
                                                                               \
    X(U3C, HCCPARAMS2, 0, 0)                                                   \
    X(CMC, HCCPARAMS2, 1, 1)                                                   \
    X(FSC, HCCPARAMS2, 2, 2)                                                   \
    X(CTC, HCCPARAMS2, 3, 3)                                                   \
    X(LEC, HCCPARAMS2, 4, 4)                                                   \
    X(CIC, HCCPARAMS2, 5, 5)                                                   \
    X(ETC, HCCPARAMS2, 6, 6)                                                   \
    X(ETC_TSC, HCCPARAMS2, 7, 7)                                               \
    X(GSC, HCCPARAMS2, 8, 8)                                                   \
    X(VTC, HCCPARAMS2, 9, 9)                                                   \
                                                                               \
    X(R_S, USBCMD, 0, 0)                                                       \
    X(HCRST, USBCMD, 1, 1)                                                     \
    X(INTE, USBCMD, 2, 2)                                                      \
    X(HSEE, USBCMD, 3, 3)                                                      \
    X(LHCRST, USBCMD, 7, 7)                                                    \
    X(CSS, USBCMD, 8, 8)                                                       \
    X(CRS, USBCMD, 9, 9)                                                       \
    X(EWE, USBCMD, 10, 10)                                                     \
    X(EU3S, USBCMD, 11, 11)                                                    \
    X(CME, USBCMD, 13, 13)                                                     \
    X(ETE, USBCMD, 14, 14)                                                     \
    X(TSC_EN, USBCMD, 15, 15)                                                  \
    X(VTIOE, USBCMD, 16, 16)                                                   \
                                                                               \
    X(HCH, USBSTS, 0, 0)                                                       \
    X(HSE, USBSTS, 2, 2)                                                       \
    X(EINT, USBSTS, 3, 3)                                                      \
    X(PCD, USBSTS, 4, 4)                                                       \
    X(SSS, USBSTS, 8, 8)                                                       \
    X(RSS, USBSTS, 9, 9)                                                       \
    X(SRE, USBSTS, 10, 10)                                                     \
    X(CNR, USBSTS, 11, 11)                                                     \
    X(HCE, USBSTS, 12, 12)                                                     \
                                                                               \
    X(Page_Size, PAGESIZE, 15, 0)                                              \
                                                                               \
    X(N0, DNCTRL, 0, 0)                                                        \
    X(N1, DNCTRL, 1, 1)                                                        \
    X(N2, DNCTRL, 2, 2)                                                        \
    X(N3, DNCTRL, 3, 3)                                                        \
    X(N4, DNCTRL, 4, 4)                                                        \
    X(N5, DNCTRL, 5, 5)                                                        \
    X(N6, DNCTRL, 6, 6)                                                        \
    X(N7, DNCTRL, 7, 7)                                                        \
    X(N8, DNCTRL, 8, 8)                                                        \
    X(N9, DNCTRL, 9, 9)                                                        \
    X(N10, DNCTRL, 10, 10)                                                     \
    X(N11, DNCTRL, 11, 11)                                                     \
    X(N12, DNCTRL, 12, 12)                                                     \
    X(N13, DNCTRL, 13, 13)                                                     \
    X(N14, DNCTRL, 14, 14)                                                     \
    X(N15, DNCTRL, 15, 15)                                                     \
                                                                               \
    X(RCS, CRCR, 0, 0)                                                         \
    X(CS, CRCR, 1, 1)                                                          \
    X(CA, CRCR, 2, 2)                                                          \
    X(CRR, CRCR, 3, 3)                                                         \
                                                                               \
    X(MaxSlotsEn, CONFIG, 7, 0)                                                \
    X(U3E, CONFIG, 8, 8)                                                       \
    X(CIE, CONFIG, 9, 9)                                                       \
                                                                               \
    X(Microframe_Index, MFINDEX, 13, 0)                                        \
                                                                               \
    // -- End Fields --

#define usb_xhci_read(xhci_ptr, __NAME) (__usb_xhci_read_##__NAME((xhci_ptr)))
#define usb_xhci_write(xhci_ptr, __NAME, __VAL)                                \
    (__usb_xhci_write_##__NAME((xhci_ptr), (__VAL)))

// Needs to be called before any registers are accessed
int
usb_xhci_bootstrap_reg_access(struct usb_xhci *xhci);

/*
 * Macro Implementation
 *
 * BEWARE: HERE THERE BE DRAGONS
 *
 */

#define __USB_XHCI_PCI_READ_FUNC_8 pci_bar_readb
#define __USB_XHCI_PCI_READ_FUNC_16 pci_bar_readw
#define __USB_XHCI_PCI_READ_FUNC_32 pci_bar_readl
#define __USB_XHCI_PCI_READ_FUNC_64 pci_bar_readq

#define __USB_XHCI_PCI_WRITE_FUNC_8 pci_bar_writeb
#define __USB_XHCI_PCI_WRITE_FUNC_16 pci_bar_writew
#define __USB_XHCI_PCI_WRITE_FUNC_32 pci_bar_writel
#define __USB_XHCI_PCI_WRITE_FUNC_64 pci_bar_writeq

#define __USB_XHCI_LE_TYPE_8 uint8_t
#define __USB_XHCI_LE_TYPE_16 le16_t
#define __USB_XHCI_LE_TYPE_32 le32_t
#define __USB_XHCI_LE_TYPE_64 le64_t

#define __USB_XHCI_LE_TO_HOST_8
#define __USB_XHCI_LE_TO_HOST_16 letoh16
#define __USB_XHCI_LE_TO_HOST_32 letoh32
#define __USB_XHCI_LE_TO_HOST_64 letoh64

#define __USB_XHCI_HOST_TO_LE_8
#define __USB_XHCI_HOST_TO_LE_16 htole16
#define __USB_XHCI_HOST_TO_LE_32 htole32
#define __USB_XHCI_HOST_TO_LE_64 htole64

#define __USB_XHCI_REG_SET_OFFSET_CAP(xhci_ptr) (0x0)
#define __USB_XHCI_REG_SET_OFFSET_OP(xhci_ptr) ((xhci_ptr)->op_reg_offset)
#define __USB_XHCI_REG_SET_OFFSET_RUNTIME(xhci_ptr)                            \
    ((xhci_ptr)->runtime_reg_offset)

#define USB_XHCI_DEFINE_READ_REG(__NAME, __SIZE, __REG_SET, __OFFSET)          \
    static inline uint##__SIZE##_t __usb_xhci_read_##__NAME(                   \
        struct usb_xhci *xhci)                                                 \
    {                                                                          \
        size_t reg_set_offset = __USB_XHCI_REG_SET_OFFSET_##__REG_SET(xhci);   \
        __USB_XHCI_LE_TYPE_##__SIZE le;                                        \
        le = __USB_XHCI_PCI_READ_FUNC_##__SIZE(&xhci->func->bars[0],           \
                                               reg_set_offset + (__OFFSET));   \
        return __USB_XHCI_LE_TO_HOST_##__SIZE(le);                             \
    }

USB_XHCI_REG_XLIST(USB_XHCI_DEFINE_READ_REG)

#define USB_XHCI_DEFINE_WRITE_REG(__NAME, __SIZE, __REG_SET, __OFFSET)         \
    static inline void __usb_xhci_write_##__NAME(struct usb_xhci *xhci,        \
                                                 uint##__SIZE##_t __value)     \
    {                                                                          \
        size_t reg_set_offset = __USB_XHCI_REG_SET_OFFSET_##__REG_SET(xhci);   \
        __USB_XHCI_LE_TYPE_##__SIZE le =                                       \
            __USB_XHCI_HOST_TO_LE_##__SIZE(__value);                           \
        __USB_XHCI_PCI_WRITE_FUNC_##__SIZE(&xhci->func->bars[0],               \
                                           reg_set_offset + (__OFFSET),        \
                                           le);                                \
    }

USB_XHCI_REG_XLIST(USB_XHCI_DEFINE_WRITE_REG)

#define USB_XHCI_DEFINE_READ_FIELD(__FIELD, __REG, __MSB, __LSB)               \
    static inline size_t __usb_xhci_read_##__FIELD(struct usb_xhci *xhci)      \
    {                                                                          \
        size_t reg = usb_xhci_read(xhci, __REG);                               \
        return (reg >> (__LSB)) & ((1ULL << (((__MSB) - (__LSB)) + 1)) - 1);   \
    }

USB_XHCI_FIELD_XLIST(USB_XHCI_DEFINE_READ_FIELD)

#define USB_XHCI_DEFINE_WRITE_FIELD(__FIELD, __REG, __MSB, __LSB)              \
    static inline void __usb_xhci_write_##__FIELD(struct usb_xhci *xhci,       \
                                                  size_t value)                \
    {                                                                          \
        size_t reg = usb_xhci_read(xhci, __REG);                               \
        int bitwidth = (__MSB) - (__LSB) + 1;                                  \
        size_t mask = ((1ULL << bitwidth) - 1);                                \
        size_t shift = (__LSB);                                                \
        reg &= ~(mask << shift);                                               \
        reg |= ((value & mask) << shift);                                      \
                                                                               \
        DEBUG_ASSERT_MSG((value & ~mask) == 0,                                 \
                         "Tried to write too large a value into USB XHCI"      \
                         " register " #__REG " field " #__FIELD                \
                         " (value=%p, width=%d)",                              \
                         (uintptr_t)value,                                     \
                         (int)bitwidth);                                       \
                                                                               \
        usb_xhci_write(xhci, __REG, reg);                                      \
    }

USB_XHCI_FIELD_XLIST(USB_XHCI_DEFINE_WRITE_FIELD)

// Undef

#undef __USB_XHCI_PCI_READ_FUNC_8
#undef __USB_XHCI_PCI_READ_FUNC_16
#undef __USB_XHCI_PCI_READ_FUNC_32
#undef __USB_XHCI_PCI_READ_FUNC_64

#undef __USB_XHCI_PCI_WRITE_FUNC_8
#undef __USB_XHCI_PCI_WRITE_FUNC_16
#undef __USB_XHCI_PCI_WRITE_FUNC_32
#undef __USB_XHCI_PCI_WRITE_FUNC_64

#undef __USB_XHCI_LE_TYPE_8
#undef __USB_XHCI_LE_TYPE_16
#undef __USB_XHCI_LE_TYPE_32
#undef __USB_XHCI_LE_TYPE_64

#undef __USB_XHCI_LE_TO_HOST_8
#undef __USB_XHCI_LE_TO_HOST_16
#undef __USB_XHCI_LE_TO_HOST_32
#undef __USB_XHCI_LE_TO_HOST_64

#undef __USB_XHCI_HOST_TO_LE_8
#undef __USB_XHCI_HOST_TO_LE_16
#undef __USB_XHCI_HOST_TO_LE_32
#undef __USB_XHCI_HOST_TO_LE_64

#undef __USB_XHCI_REG_SET_OFFSET_CAP
#undef __USB_XHCI_REG_SET_OFFSET_OP
#undef __USB_XHCI_REG_SET_OFFSET_RUNTIME

#undef USB_XHCI_DEFINE_READ_REG
#undef USB_XHCI_DEFINE_WRITE_REG

#undef USB_XHCI_DEFINE_READ_FIELD
#undef USB_XHCI_DEFINE_WRITE_FIELD

#undef USB_XHCI_REG_XLIST
#undef USB_XHCI_FIELD_XLIST

static inline void
usb_xhci_write_doorbell(struct usb_xhci *xhci,
                        size_t doorbell_index,
                        uint8_t target,
                        uint16_t task)
{
    uint32_t value = ((uint32_t)task << 16) | target;
    pci_bar_writel(&xhci->func->bars[0],
                   xhci->doorbell_offset + ((uint32_t)doorbell_index * 4),
                   htole32(value));
}

#endif
