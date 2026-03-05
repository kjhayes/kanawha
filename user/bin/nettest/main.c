
#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *progname = "nettest";
__attribute__((noreturn)) static void
panic_usage(void)
{
    fprintf(stderr, "Usage: %s [DEVICE]\n", progname);
    exit(EXIT_FAILURE);
}

#define ETH_MAC_ADDR_LEN 6
#define ETH_FRAME_HEADER_LEN 14

#define ETH_TYPE_IPV4 0x0800

struct eth_mac_addr
{
    uint8_t data[ETH_MAC_ADDR_LEN];
} __attribute__((packed));

struct eth_frame_header
{
    struct eth_mac_addr dst_addr;
    struct eth_mac_addr src_addr;
    uint16_t type;
} __attribute__((packed));

struct eth_frame
{
    struct eth_frame_header hdr;
    uint8_t data[];
};

void
send_ethernet_packet(const char *eth_dev_path)
{
    size_t datalen = 16;
    size_t framelen = sizeof(struct eth_frame) + datalen;

    uint8_t buffer[framelen];

    struct eth_frame *frame = (struct eth_frame *)buffer;
    memset(frame->hdr.dst_addr.data, 0xFF, 6);
    memset(frame->hdr.src_addr.data, 0x00, 6);
    frame->hdr.type = htobe16(ETH_TYPE_IPV4);

    int fd = open(eth_dev_path, O_RDWR);
    int written = write(fd, buffer, framelen);

    printf("Wrote 0x%lx Bytes\n", written);
}

void
send_ping(const char *ip_dev_path)
{
    printf("Unimplemented!\n");
    return;
}

int
main(int argc, const char **argv)
{
    if(argc > 0)
    {
        progname = argv[0];
    }

    int ethernet = 0;
    int ping = 0;

    {
        int opt;
        while((opt = getopt(argc, (char **)argv, "ep")) != -1)
        {
            switch(opt)
            {
            // Handle Any Short Options
            case 'e':
                ethernet = 1;
                break;
            case 'p':
                ping = 1;
                break;
            default:
                panic_usage();
            }
        }
    }

    const char *device_path = NULL;

    {
        int pos_argc = argc - optind;
        if(pos_argc < 0)
        {
            pos_argc = 0;
        }
        const char **pos_argv = argv + optind;

        if(pos_argc != 1)
        {
            panic_usage();
        }
        device_path = pos_argv[0];
    }

    if(ethernet)
    {
        send_ethernet_packet(device_path);
    }
    else if(ping)
    {
        send_ping(device_path);
    }

    return 0;
}
