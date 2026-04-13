
obj-$(CONFIG_PCI) += pci.o

pci-y += \
	cfg.o \
	bar.o \
	cap.o \
	match.o \
	bus.o \
	device.o \
	func.o \
	irq.o \
	msi.o \
	msix.o \
	mailbox.o

pci-$(CONFIG_PCI_PORT_CAM) += port_cam.o
pci-$(CONFIG_PCI_MMIO_ECAM) += mmio_ecam.o
pci-$(CONFIG_PCI_DEVTREE) += devtree.o

pci-$(CONFIG_SYSFS_PCI) += sysfs.o

pci-$(CONFIG_PCIE_ACPI_MCFG) += mcfg.o

pci-$(CONFIG_POLLING_PCI_MAILBOX) += poll.o

