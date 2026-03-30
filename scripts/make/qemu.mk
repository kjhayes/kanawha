
QEMU_PREFIX :=
#QEMU_PREFIX := ~/qemu/build/

QEMU_DEBUG_LOG ?= qemu.log
QEMU_FLAGS += -D $(QEMU_DEBUG_LOG) -d guest_errors

QEMU_FLAGS += -trace "virtio_*"

#QEMU_FLAGS += -device virtio-gpu-pci

# QEMU_FLAGS += -drive file=$(ROOT_DIR)/root.ext2,if=none,id=virtio-disk-root,format=raw \
# 			  -device virtio-blk-pci,drive=virtio-disk-root,id=root-disk

# QEMU_FLAGS += -drive id=ahcidisk,file=ahci.img,if=none \
#               -device ahci,id=ahci \
#               -device ide-hd,drive=ahcidisk,bus=ahci.0

QEMU_FLAGS += -device virtio-rng

# QEMU_FLAGS += -audio driver=pa,model=virtio
# QEMU_FLAGS += -audiodev pa,id=speaker -machine pcspk-audiodev=speaker

#QEMU_FLAGS += -drive id=disk,file=ahci.img,if=none \
              -device ahci,id=ahci \
              -device ide-hd,drive=disk,bus=ahci.0

#QEMU_FLAGS += -device virtio-serial-pci,id=virtio-serial0
#QEMU_FLAGS += -chardev memory,id=charconsole0,logfile=serial.log
#QEMU_FLAGS += -device virtconsole,chardev=charconsole0,id=console0

QEMU_FLAGS += -device edu
QEMU_FLAGS += -device pci-testdev

#QEMU_FLAGS += -netdev user,id=net0,net=192.168.76.0/24,dhcpstart=192.168.76.9 \
			  -object filter-dump,id=f1,netdev=net0,file=netdump.dat
#QEMU_FLAGS += -device virtio-net-pci,netdev=net0,mq=on,vectors=1

# QEMU_FLAGS += \
#               -device nec-usb-xhci,id=xhci                      \
#               -drive if=none,id=stick0,format=raw,file=./usb0.img \
#               -device usb-storage,bus=xhci.0,drive=stick0,id=stick0 \
#               -drive if=none,id=stick1,format=raw,file=./usb1.img \
#               -device usb-storage,bus=xhci.0,drive=stick1,id=stick1 \

QEMU_FLAGS += \
		-drive file=nvme.img,if=none,id=nvm,format=raw \
 		-device nvme,serial=deadbeef,drive=nvm

#QEMU_FLAGS += -device e1000e

ifdef CONFIG_X64
QEMU := $(QEMU_PREFIX)qemu-system-x86_64
ISO := $(OUTPUT_DIR)/kanawha.iso
QEMU_DEPS += $(ISO)
QEMU_FLAGS += -cdrom $(ISO)

QEMU_FLAGS += -serial stdio
QEMU_FLAGS += -smp 1
QEMU_FLAGS += -vga cirrus
QEMU_FLAGS += -device virtio-gpu-pci
QEMU_FLAGS += -accel kvm 
QEMU_FLAGS += -machine q35
QEMU_FLAGS += -m 4G
endif

# ifdef CONFIG_RISCV64
# QEMU := $(QEMU_PREFIX)qemu-system-riscv64
# QEMU_FLAGS += -kernel $(KANAWHA_OUTPUT_DIR)/kanawha.bin
# QEMU_FLAGS += -bios default
# QEMU_FLAGS += -serial stdio
# QEMU_FLAGS += -M virt
# QEMU_FLAGS += -m 2G
# 
# QEMU_DEPS += $(OUTPUT_DIR)/initrd
# QEMU_FLAGS += -initrd $(OUTPUT_DIR)/initrd
# 
# #QEMU_FLAGS += -machine dumpdtb=virt.dtb
# endif

ifdef QEMU
qemu: $(QEMU_DEPS)
	$(QEMU) $(QEMU_FLAGS)
qemu-gdb: $(QEMU_DEPS)
	$(QEMU) $(QEMU_FLAGS) -gdb tcp::1234 -no-reboot -no-shutdown

endif

