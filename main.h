

#include <unistd.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>


#include <arpa/inet.h>
#include <sys/socket.h>

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h> // mmap
#include <roaring/roaring.h>
#include <stdint.h>

#define MAX(x, y) (x) > (y) ? (x) : (y)
#define MIN(x, y) (x) < (y) ? (x) : (y)
/* 动态类型的柔性数组 */
typedef struct _DynamicChunk {
    uint64_t len;
    unsigned char data[0];
} DynamicChunk;

typedef struct _Chunk {
    uint64_t len;
    unsigned char *data;
} Chunk;



/*
Mapper format:
PktIdOffsetMapperHeader
PktIdOffsetMapperNode
PktIdOffsetMapperNode
PktIdOffsetMapperNode
...
*/

#define MAPPER_MAGIC 0x6e616974676e6570U // "pengtian"
#define MAPPER_NAME_SIZE 256 
#define MAPPER_MIN_ID UINT64_C(0)
#define MAPPER_MAX_ID UINT64_C(0xffffffff)
// #define MAPPER_MAX_ID UINT64_C(0xffffffff)
 
typedef struct _PktIdOffsetMapperHeader {
    uint64_t magic;
    uint64_t cnt; // total pkt size
    uint64_t start_timestamp; // first纳秒时间戳
    uint64_t end_timestamp; // last纳秒时间戳
    unsigned char name[MAPPER_NAME_SIZE];
} PktIdOffsetMapperHeader;

typedef struct _PktIdOffsetMapperNode {
    uint64_t offset; // pcap偏移
    uint64_t timestamp; // 纳秒时间戳
} PktIdOffsetMapperNode;

#define container_of(ptr, type, member) ({              \
const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
(type *)( (char *)__mptr - offsetof(type,member) );})


typedef struct _BitmapChunk {
    roaring_bitmap_t *r; /* for bit value 1 */
    Chunk ck;
    roaring_bitmap_t *r0; /* for bit value 0 */
    Chunk ck0;
} BitmapChunk;

struct vlanhdr {
	uint16_t proto;
	uint16_t tci;
};

/*
create a bitmap for each bit
*/
/* this struct should be aligned, all index is network bytes order */
typedef struct _FullIndex {
    /* record to log all index bit */
    BitmapChunk self[1];
    /* ether */
    union {
        struct {
            BitmapChunk ether_smac[6*8];
            BitmapChunk ether_dmac[6*8];
            /* 0x0800 */
            BitmapChunk ether_type[2*8];
        } __attribute__((__packed__));
        BitmapChunk ether_hdr[14*8];
    } __attribute__((__packed__));
    /* vlan, only support 1 layer vlan */
    union {
        struct {
            BitmapChunk vlan_priority[3];
            BitmapChunk vlan_tci[1];
            BitmapChunk vlan_id[12];
            BitmapChunk vlan_type[2*8];
        } __attribute__((__packed__));;
        BitmapChunk vlan_hdr[4*8];
    };
    /* arp */
    union {
        struct {
            BitmapChunk arp_hard_addr[2*8];
            BitmapChunk arp_proto[2*8];
            BitmapChunk arp_hard_len[1*8];
            BitmapChunk arp_proto_addr[1*8];
            BitmapChunk arp_opeartion[2*8];
            BitmapChunk arp_smac[6*8];
            BitmapChunk arp_sip[4*8];
            BitmapChunk arp_dmac[6*8];
            BitmapChunk arp_dip[4*8];
        } __attribute__((__packed__));;
        BitmapChunk arp_hdr[28*8];
    } __attribute__((__packed__));
    /* ipv4 */
    union {
        struct {
            BitmapChunk ip_ihl[4];
            BitmapChunk ip_ver[4];
            BitmapChunk ip_tos[1*8];
            BitmapChunk ip_len[2*8];
            BitmapChunk ip_id[2*8];
            BitmapChunk ip_frag[2*8];
            BitmapChunk ip_ttl[1*8];
            BitmapChunk ip_proto[1*8];
            BitmapChunk ip_cksum[2*8];
            BitmapChunk ip_src[4*8];
            BitmapChunk ip_dst[4*8];
        } __attribute__((__packed__));;
        BitmapChunk ip_hdr[20*8];
    } __attribute__((__packed__));
    /* ipv6 */
    union {
        struct {
            BitmapChunk ip6_prio[4];
            BitmapChunk ip6_ver[4];
            BitmapChunk ip6_flowlbl[3*8];
            BitmapChunk ip6_payload_len[2*8];
            BitmapChunk ip6_proto[1*8];
            BitmapChunk ip6_hop_limit[1*8];
            BitmapChunk ip6_src[16*8];
            BitmapChunk ip6_dst[16*8];
        } __attribute__((__packed__));;
        BitmapChunk ip6_hdr[40*8];
    } __attribute__((__packed__));
    /* tcp */
    union {
        struct {
            BitmapChunk tcp_sport[2*8];
            BitmapChunk tcp_dport[2*8];
            BitmapChunk tcp_seq[4*8];
            BitmapChunk tcp_ack[4*8];
            BitmapChunk tcp_doff[4];
            BitmapChunk tcp_reserve[4];
            BitmapChunk tcp_flags[1*8];
            BitmapChunk tcp_win[2*8];
            BitmapChunk tcp_cksum[2*8];
            BitmapChunk tcp_urp[2*8];
        } __attribute__((__packed__));;
        BitmapChunk tcp_hdr[20*8];
    } __attribute__((__packed__));
    /* udp */
    union {
        struct {
            BitmapChunk udp_sport[2*8];
            BitmapChunk udp_dport[2*8];
            BitmapChunk udp_dlen[2*8];
            BitmapChunk udp_cksum[2*8];
        } __attribute__((__packed__));;
        BitmapChunk udp_hdr[8*8];
    } __attribute__((__packed__));
    /* icmp */
    union {
        struct {
            BitmapChunk icmp_type[1*8];
            BitmapChunk icmp_code[1*8];
            BitmapChunk icmp_cksum[2*8];
        } __attribute__((__packed__));;
        BitmapChunk icmp_hdr[1*8];
    } __attribute__((__packed__));

} __attribute__((__packed__)) FullIndex ;
enum {
    INDEX_TYPE_SELF = 0,
    INDEX_TYPE_ETHER,
    INDEX_TYPE_VLAN ,
    INDEX_TYPE_ARP ,
    INDEX_TYPE_IPV4 ,
    INDEX_TYPE_IPV6 ,
    INDEX_TYPE_TCP ,
    INDEX_TYPE_UDP ,
    INDEX_TYPE_ICMP ,
    INDEX_TYPE_MAX 
};

void update_index_common(FullIndex *idx, int idx_type, const uint8_t *hdr, const uint8_t *hdr_mask, uint32_t hdr_sz, int64_t pkt_id);