
ENTRY(_start);

PHDRS {
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
  rodata PT_LOAD FLAGS(4);
  note PT_NULL FLAGS(0);
}

SECTIONS {

    . = 0x1000;

    .text : {
        *(.text*);
        *(.text.*);
        . = ALIGN(0x1000);
    } :text = 0xCCCCCCCC

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata*);
        *(.rodata.*);
        . = ALIGN(0x1000);
    } :rodata

    . = ALIGN(0x1000);
    .data : {
        *(.data*);
        *(.data.*);
        . = ALIGN(0x1000);
    } :data

    . = ALIGN(0x1000);
    .bss : {
        *(.bss*);
        *(.bss.*);
        . = ALIGN(0x1000);
    } :data

    /DISCARD/ : {
        *(.eh_frame*);
        *(.eh_frame.*);
    }
}

