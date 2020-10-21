#include <stdio.h>
#include <stdint.h>
#include "main.h"
/* 
sample index type 
    index_key: XXX
    index_type: 256/65536
    index_bpf_name: 
    index_plugin: get_value_func
    index_data: 
*/

/*
根据data获取数据
@data: payload数据 TODO: 外部结构体
@bs: 1, 2, 4, int的字节数
@ret: 获取到的值
@u: 外部数据

@ret: 0(成功), 其他(失败)
*/
typedef int (*GetValueFunc_t)(void *data, int bs, uint64_t *ret, void *u);

typedef struct _IndexFunc {
    GetValueFunc_t get;
} IndexFunc;

#define INDEX_MAX_SZ 64
/* 索引类型, 字节数 */
enum IndexType {
    IndexTypeB1 = 1,
    IndexTypeB2 = 2,
    IndexTypeB4 = 4
};
typedef struct _CommonIndexData {
    unsigned char key[INDEX_MAX_SZ];
    unsigned char bpf_name[INDEX_MAX_SZ];
    unsigned int type;
    IndexFunc func;
    DynamicChunk *data;
} CommonIndex;


/*
sources
*/

int IntValueFunc(void *data, int bs, uint64_t *ret, void *u){
    // data: iphdr
    uint16_t v16; 
    int64_t v64;
    switch (bs)
    {
    case IndexTypeB1:
        *ret = *((uint8_t *)data);
        break;
    case IndexTypeB2:
	v16 = ntohs(*((uint16_t *)data));
        *ret = v16;
        break;
    case IndexTypeB4:
        v64 = (uint64_t)ntohl(*((uint32_t *)data));
        *ret = v64;
        break;
    default:
        return 1;
        break;
    }
    return 0;
}
int can_bye = 0;
int compress_bitmap = 1;
int g_mapper_fd;
PktIdOffsetMapperHeader g_mapper_header = {
    .magic = MAPPER_MAGIC
};
FullIndex full_index = {0};
FullIndex full_index_loaded = {0};

CommonIndex sip0_index = {
    .key = "sip0",
    .bpf_name = "sip0",
    .type = IndexTypeB2,
    .func = {
        .get = &IntValueFunc
    }
};

// uint32_t calc_index_bit_offset(FullIndex *idx, )

/*
note: this function should ensure all bitmap offset has in self_bitmap
@parm:
    idx: target idx to update
    base_idx: base index to copy from when pkt_id < 0
    idx_type: index type
    hdr: extern struct pointer
    hdr_mask: pointer mask, if bit set, we should handle the bit, if hdr_mask is NULL, same as hdr
    hdr_sz: extern struct size_t
    pkt_id: 
        target packet id,
        if -1 will set all bits between MAPPER_MIN_ID~MAPPER_MAX_ID
        or copy from base index

*/
void update_index_generic(FullIndex *idx, FullIndex *base_idx, int idx_type, const uint8_t *hdr, const uint8_t *hdr_mask, uint32_t hdr_sz, int64_t pkt_id) {
    int sz = 0;
    int i = 0;
    int offset = 0;
    const uint8_t *mask;
    const int per_sz = sizeof(BitmapChunk);
    BitmapChunk *r = NULL;
    BitmapChunk *self = NULL;
    if (!hdr || !idx || !hdr_sz)
        return;
    if (idx_type <= INDEX_TYPE_SELF || idx_type >= INDEX_TYPE_MAX) {
        return;
    }
    self = idx->self;
    switch (idx_type)
    {
    case INDEX_TYPE_ETHER:
        r = idx->ether_hdr;
        sz = sizeof(idx->ether_hdr);
        break;
    case INDEX_TYPE_VLAN:
        r = idx->vlan_hdr;
        sz = sizeof(idx->vlan_hdr);
        break;
    case INDEX_TYPE_ARP:
        r = idx->arp_hdr;
        sz = sizeof(idx->arp_hdr);
        break;
    case INDEX_TYPE_IPV4:
        r = idx->ip_hdr;
        sz = sizeof(idx->ip_hdr);
        break;
    case INDEX_TYPE_IPV6:
        r = idx->ip6_hdr;
        sz = sizeof(idx->ip6_hdr);
        break;
    case INDEX_TYPE_TCP:
        r = idx->tcp_hdr;
        sz = sizeof(idx->tcp_hdr);
        break;
    case INDEX_TYPE_UDP:
        r = idx->udp_hdr;
        sz = sizeof(idx->udp_hdr);
        break;
    case INDEX_TYPE_ICMP:
        r = idx->icmp_hdr;
        sz = sizeof(idx->icmp_hdr);
        break;
    default:
        printf("Invalid index type: %d, skip\n", idx_type);
        return;
        break;
    }
    sz = sz / per_sz;
    /* convert bytes to bit index */
    if ((hdr_sz << 3) != sz) {
        printf("Internal Error! %d header bits %d != %d\n", idx_type, hdr_sz<<3, sz);
        return;
    }
    mask = hdr_mask ? hdr_mask: hdr;
    i = 0;
    sz = 0; /* from now on: sz is the offset from relative r */
    /* foreach each bytes in hdr */
    while(i < hdr_sz) {
        /* check and set bit into bitmap start from r */
        uint32_t j = 0;
        uint32_t m = mask[i] & 0xffU;
        uint32_t v = hdr[i] & m ;
        if (m) {
            printf("hdr_sz:%d i:%d v:0x%02x\n", hdr_sz, i, v);
            /* foreach every bit to set */
            while(j < 8*sizeof(uint8_t)) {
                /* current bitmap */
                uint32_t bit_set = (v & 0x1U);
                /* get current BitChunk by retalive ptr + origin relative bytes offset */
                BitmapChunk *bc = r + sz;
                roaring_bitmap_t *rb = NULL;
                roaring_bitmap_t *rb_base = NULL;
                int index;
                offset = (uint8_t*)bc - (uint8_t*)idx;
                index = offset / sizeof(BitmapChunk);
                printf("    i:%d j:%d index%s:%d offset: %u = %p - %p, r:%p sizeof BC: %d sz:%d\n", i, j, bit_set ? "": "0", index, offset, bc, idx, r, sizeof(BitmapChunk), sz);
                /* save offset i into self index, it will be used for search and merge */
                if (bit_set) {
                    rb = bc->r;
                    roaring_bitmap_add(self->r, index);
                } else {
                    rb = bc->r0;
                    roaring_bitmap_add(self->r0, index);
                }

                /* if bit set , add into r */
                if (pkt_id >= 0) {
                    printf("     adding pkt_id\n");
                    roaring_bitmap_add(rb, pkt_id);
                }
                else
                {
                    if (base_idx) {
                        BitmapChunk *bc_base = NULL;
                        bc_base = (BitmapChunk *)((uint8_t*)base_idx + offset);
                        rb_base = bit_set ? bc_base->r : bc_base->r0;
                        printf("     oring with base_idx:%p bc_base:%p offset:%lu\n", base_idx, bc_base, offset);
                        roaring_bitmap_or_inplace(rb, rb_base);
                    } else {
                        printf("     adding range\n");
                        roaring_bitmap_add_range_closed(rb, MAPPER_MIN_ID, MAPPER_MAX_ID);
                    }
                }
                printf("after %d handling, bc:%p rb:%p rcard:%lu rb_base card: %d\n"
                    , sz, bc, rb, roaring_bitmap_get_cardinality(rb), rb_base ? roaring_bitmap_get_cardinality(rb_base): 0
                );
                // roaring_bitmap_printf(rb);
                printf("\n");

                v >>= 1;
                j++;
                sz++;
            }  /* end while */
        } else {
            sz += 8*sizeof(uint8_t);
        }
        i++;
    } /* end while */
    printf("update over, self card:%d self card0:%d\n", roaring_bitmap_get_cardinality(self->r), roaring_bitmap_get_cardinality(self->r0));
    printf("\tr: ");
    roaring_bitmap_printf(self->r);
    printf("\n\tr0: ");
    roaring_bitmap_printf(self->r0);
    printf("\n");
}

void update_index_common(FullIndex *idx, int idx_type, const uint8_t *hdr, const uint8_t *hdr_mask, uint32_t hdr_sz, int64_t pkt_id) {
    update_index_generic(idx, NULL, idx_type, hdr, hdr_mask, hdr_sz, pkt_id);
}

void update_index_common_fast(FullIndex *idx, FullIndex *base_idx, int idx_type, const uint8_t *hdr, const uint8_t *hdr_mask, uint32_t hdr_sz) {
    update_index_generic(idx, base_idx, idx_type, hdr, hdr_mask, hdr_sz, -1);
}


void packet_process(uint64_t pkt_id, uint64_t offset, uint64_t sz, const unsigned char *data, uint64_t nano_sec) {
    printf("TODO: handle packet, pkt_id: %lu offset: %lu fake pcap_hdr_sz: %lu real pcap_hdr_sz:%lu timeval: %lu data sz: %lu\n"
        , pkt_id, offset, sizeof(struct pcap_pkthdr), sizeof(struct timeval), sz
    );
    /* assume data is ether*/
    struct ethhdr *eth = NULL;
    struct vlanhdr *vlan = NULL;
    struct arphdr *arp = NULL;
    struct iphdr *ip = NULL;
    struct ip6_hdr *ipv6 = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;;
    struct icmphdr *icmp = NULL;;

    uint8_t ip_proto = 0;
    uint16_t ether_type = 0;
    uint64_t sip = 0;
    uint64_t dip = 0;
    uint8_t sip_val[4];
    uint8_t dip_val[4];
    uint16_t sport, dport;

    eth = (struct ethhdr *)data;

    ether_type = ntohs(eth->h_proto);
    switch (ether_type)
    {
    case ETH_P_IP:
        {
            ip = (struct iphdr *)(eth + 1);
            printf("Skip non IP packet\n");
            sip = ntohl(ip->saddr);
            dip = ntohl(ip->daddr);
            sip_val[3] = sip & 0xffLU; // 1
            sip_val[2] = sip >> 8  & 0xff00U; // 0
            sip_val[1] = sip >> 16 & 0xffU; // 168
            sip_val[0] = sip >> 24 & 0xffU; // 192
            dip_val[3] = dip & 0xffLU;
            dip_val[2] = dip >> 8  & 0xff00U;
            dip_val[1] = dip >> 16 & 0xffU;
            dip_val[0] = dip >> 24 & 0xffU;
            ip_proto = ip->protocol;
            switch (ip_proto)
            {
            case IPPROTO_TCP:
                /* code */
                tcp = (struct tcphdr*)(ip + 1);
                sport = ntohs(tcp->source);
                dport = ntohs(tcp->dest);
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr*)(ip + 1);
                sport = ntohs(udp->source);
                dport = ntohs(udp->dest);
                break;
            case IPPROTO_ICMP:
                icmp = (struct icmphdr*)(ip + 1);
                break;
            default:
                sport = dport = 0;
                break;
            }
            printf("PKT: ether_type:0x%02x ip_proto:0x%02x sip: 0x%02x, dip:0x%02x "
                , ether_type, ip_proto, sip, dip
            );
            printf("%u.%u.%u.%u:%d->%u.%u.%u.%u:%d"
            , sip_val[0], sip_val[1], sip_val[2], sip_val[3], sport
            ,  dip_val[0], dip_val[1], dip_val[2], dip_val[3], dport
            );
            printf("\n");
        }
        break;
    case ETH_P_IPV6:
        {
            ipv6 = (struct ip6_hdr *)(eth + 1);
            switch (ipv6->ip6_nxt)
            {
            case IPPROTO_TCP:
                /* code */
                tcp = (struct tcphdr*)(ip + 1);
                sport = ntohs(tcp->source);
                dport = ntohs(tcp->dest);
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr*)(ip + 1);
                sport = ntohs(udp->source);
                dport = ntohs(udp->dest);
                break;
            case IPPROTO_ICMP:
                icmp = (struct icmphdr*)(ip + 1);
                break;
            default:
                sport = dport = 0;
                break;
            }
        };
        break;
    case ETH_P_ARP:
        {
            arp = (struct arphdr *)(eth + 1);
        };
        break;
    case ETH_P_8021Q:
        {
            vlan = (struct vlanhdr *)(eth + 1);
        };
        break;
    default:
        break;
    }
lbl_end:

    // update_index_common(&full_index, INDEX_TYPE_ETHER   , (const uint8_t *)eth   , NULL, sizeof(struct ethhdr)    , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_VLAN    , (const uint8_t *)vlan  , NULL, sizeof(struct vlanhdr)   , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_ARP     , (const uint8_t *)arp   , NULL, sizeof(struct arphdr)    , pkt_id);
    printf("Real ip mem: ");
    dump(ip, sizeof(struct iphdr));
    update_index_common(&full_index, INDEX_TYPE_IPV4    , (const uint8_t *)ip    , NULL, sizeof(struct iphdr)     , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_IPV6    , (const uint8_t *)ipv6  , NULL, sizeof(struct ip6_hdr)   , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_TCP     , (const uint8_t *)tcp   , NULL, sizeof(struct tcphdr)    , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_UDP     , (const uint8_t *)udp   , NULL, sizeof(struct udphdr)    , pkt_id);
    // update_index_common(&full_index, INDEX_TYPE_ICMP    , (const uint8_t *)icmp  , NULL, sizeof(struct icmphdr)   , pkt_id);

    /* 写包和offset的 对应文件 */
    PktIdOffsetMapperNode m = {
        .offset = offset,
        .timestamp = nano_sec
    };
    int r = write(g_mapper_fd, &m, sizeof(PktIdOffsetMapperNode));
    if (r != sizeof(PktIdOffsetMapperNode)) {
        printf("Write fail, fd: %d, error: %s\n", g_mapper_fd, strerror(errno));
        return;
    }

    if (nano_sec < g_mapper_header.start_timestamp || g_mapper_header.start_timestamp == 0) {
        g_mapper_header.start_timestamp = nano_sec;
    }
    if (nano_sec > g_mapper_header.end_timestamp || g_mapper_header.end_timestamp == 0) {
        g_mapper_header.end_timestamp = nano_sec;
    }
    g_mapper_header.cnt++;
    return;
}

void show_usage(){
    printf("Usage: $PROG your_pcap_file_path\n");
}


void dump_mapper_info(PktIdOffsetMapperHeader *h, char *prefix) {
    printf("%s mapper info(%d bytes), magic:0x%02x cnt:%lu, start_ts:%lu end_ts:%lu name:%s\n"
        , prefix ? prefix : ""
        , sizeof(PktIdOffsetMapperHeader)
        , h->magic
        , h->cnt
        , h->start_timestamp
        , h->end_timestamp
        , h->name
    );
}

#define INDEX_PKT_ID_MAMPPER "pkg_id_map.idx"
#define INDEX_BPF "pkg_bpf.idx"

void dump_files() {
    PktIdOffsetMapperNode m = {0};
    PktIdOffsetMapperHeader h = {0};
    ssize_t sz;
    int fd;
    uint64_t i = 0;
    int offset = 0;
    if ((fd = open(INDEX_PKT_ID_MAMPPER, O_RDONLY)) < 0) {
        printf("Cant read %s fail\n", INDEX_PKT_ID_MAMPPER);
        return ;
    }
    /* read header info */
    sz = read(fd, &h, sizeof(PktIdOffsetMapperHeader));
    if (sz <= 0) {
        printf("Read mapper fail\n");
        goto lbl_clean;
    }
    dump_mapper_info(&h, "Read");
    if (h.magic != MAPPER_MAGIC) {
        printf("Incorrect mapper magic version, skip\n");
        goto lbl_clean;
    }
    while (1) {
        sz = read(fd, &m, sizeof(PktIdOffsetMapperNode));
        if (sz <= 0) {
            printf("Read INDEX_PKT_ID_MAMPPER over\n");
            break;
        }
        // printf("pkt_id: %lu, pcap offset: %lu\n", i, m.offset);
        i++;
        offset += sz;
    }
lbl_clean:
    close(fd);
    printf("Dump over\n");
}


void open_files() {
    dump_files();
    printf("Opening files\n");
    g_mapper_fd = open(INDEX_PKT_ID_MAMPPER, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (g_mapper_fd < 0) {
        printf("open INDEX_PKT_ID_MAMPPER fail\n");
        goto lbl_err;
    }
    printf("Seeking header\n");
    lseek(g_mapper_fd, sizeof(PktIdOffsetMapperHeader), SEEK_SET);
    g_mapper_header.magic = MAPPER_MAGIC;
    snprintf(g_mapper_header.name, MAPPER_NAME_SIZE - 1, INDEX_PKT_ID_MAMPPER);
    printf("Opened files over\n");

    return ;
lbl_err:
    exit(4);
}

void close_files() {
    dump_mapper_info(&g_mapper_header, "Writing");
    lseek(g_mapper_fd, 0, SEEK_SET);
    write(g_mapper_fd, &g_mapper_header, sizeof(PktIdOffsetMapperHeader));
    close(g_mapper_fd);
}

typedef struct _MmapObj {
    int fd;
    off_t len;
    char *addr;
} MmapObj;

int MmapRead(char *fp, MmapObj *obj) {
    int fd;
    off_t len;
    char *addr;
    if (!obj) {
        return 1;
    }
    fd = open(fp, O_RDONLY);
    if (fd < 0){
        return 2;
    }
    len = lseek(fd, 0, SEEK_END);
    addr = (char *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (!addr) {
        close(fd);
    }
    obj->fd = fd;
    obj->addr =addr;
    obj->len = len;
    return 0;
}

int MmapWrite(char *fp, MmapObj *obj, uint64_t max_bytes) {
    int fd;
    off_t len;
    char *addr;
    if (!obj) {
        return 1;
    }
    fd = open(fp, O_CREAT|O_RDWR|O_TRUNC, 0644);
    if (fd < 0){
        return 2;
    }
    len = max_bytes;
    // truncate this file to specified size to avoid sigbus error
    ftruncate(fd, len);
    addr = (char *)mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (!addr) {
        close(fd);
    }
    obj->fd = fd;
    obj->addr =addr;
    obj->len = len;
    return 0;
}


void MmapClear(MmapObj *obj) {
    if (!obj)
        return;
    if (obj->fd > 0) {
        close(obj->fd);
    }
    if (obj->addr)
        munmap((void *)obj->addr, obj->len);
    memset(obj, 0, sizeof(MmapObj));
    obj->fd = -1;
}


int FullIndexFlip(FullIndex *target) {
    printf("FullIndexFlip\n");
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    if (!target)
        return 1;
    i = 0;
    while (i < sz) {
        printf("FullIndexFlip %d\n", i);
        BitmapChunk *bc_left = ((BitmapChunk*)target) + i;
        if (bc_left->r) {
            roaring_bitmap_flip_inplace(bc_left->r, MAPPER_MIN_ID, MAPPER_MAX_ID);
            roaring_bitmap_flip_inplace(bc_left->r0, MAPPER_MIN_ID, MAPPER_MAX_ID);
        }
        i++;
    }
    return 0;
}

/*
create/init a empty full index
*/
void FullIndexCreate(FullIndex *idx) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        bc->r = roaring_bitmap_create();
        bc->ck.len = 0;
        bc->ck.data = NULL;
        bc->r0 = roaring_bitmap_create();
        bc->ck0.len = 0;
        bc->ck0.data = NULL;
        i++;
    }
}
#if 0
/* create a full index and set all bit */
void FullIndexCreateWithAll(FullIndex *idx) {
    // int i;
    // int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    // i = 0;
    // while (i < sz) {
    //     BitmapChunk *bc = ((BitmapChunk*)idx) + i;
    //     bc->r = roaring_bitmap_create();
    //     roaring_bitmap_add_range_closed(bc->r, MAPPER_MIN_ID, MAPPER_MAX_ID);
    //     bc->ck.len = 0;
    //     bc->ck.data = NULL;
    //     i++;
    // }
    FullIndexCreate(idx);
    FullIndexFlip(idx);
}
#endif
void FullIndexFree(FullIndex *idx) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        if (bc->r) {
            roaring_bitmap_free(bc->r);
            bc->r = NULL;
        }
        bc->ck.len = 0;
        /* WARN: 这里不会释放data, 默认data为外部数据 */
        bc->ck.data = 0;

        if (bc->r0) {
            roaring_bitmap_free(bc->r0);
            bc->r0 = NULL;
        }
        bc->ck0.len = 0;
        /* WARN: 这里不会释放data, 默认data为外部数据 */
        bc->ck0.data = 0;

        i++;
    }
}

void FullIndexPrint(FullIndex *idx) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    int64_t card = 0;
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        card = roaring_bitmap_get_cardinality(bc->r);
        if (card > 0  && card < 10000) {
            printf("%lu/%lu card:%lu data: ", i, sz, card);
            roaring_bitmap_printf(bc->r);
            printf("\n");
        }
        card = roaring_bitmap_get_cardinality(bc->r0);
        if (card > 0  && card < 10000) {
            printf("%lu/%lu card0:%lu data: ", i, sz, card);
            roaring_bitmap_printf(bc->r0);
            printf("\n");
        }
        i++;
    }
}

/*
serialize FullIndex to buf, format is:
len|buf|len|buf|...
out_buf: out memeory for dump, if NULL, will only return size
out_buf_len: out memory size for write
*/
void FullIndexDump(FullIndex *idx, unsigned char *out_buf, uint64_t *out_buf_len) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    uint64_t need_buf_sz = 0;
    size_t offset = 0;
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        if (compress_bitmap) {
            roaring_bitmap_run_optimize(bc->r);
            roaring_bitmap_run_optimize(bc->r0);
        }
        size_t bs = roaring_bitmap_portable_size_in_bytes(bc->r);
        need_buf_sz += bs + sizeof( typeof(((Chunk *)0)->len ));
        bc->ck.len = bs; // 设置需要的长度到ck中

        size_t bs0 = roaring_bitmap_portable_size_in_bytes(bc->r0);
        need_buf_sz += bs0 + sizeof( typeof(((Chunk *)0)->len ));
        bc->ck0.len = bs0; // 设置需要的长度到ck中

        i++;
    }
    if (!out_buf) {
        /* 外部buf为空, 外部只是想获取大小 */
        *out_buf_len = need_buf_sz;
        return;
    }
    if (need_buf_sz < *out_buf_len) {
        // out buf is not enouth
        printf("out buf is not enough, need: %lu total: %lu\n", need_buf_sz, *out_buf_len);
        return;
    }
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        unsigned char *buf = out_buf + offset;
        uint64_t used_sz = bc->ck.len;
        memcpy(buf, &bc->ck.len, sizeof(bc->ck.len));
        buf += sizeof(bc->ck.len);
        offset += sizeof(bc->ck.len);
        bc->ck.data = buf;
        used_sz = roaring_bitmap_portable_serialize(bc->r, buf);
        if (used_sz != bc->ck.len) {
            printf("May error!!! %lu!=%lu\n", used_sz, bc->ck.len);
        }
        offset += used_sz;
        bc->ck.len = used_sz;
        bc->ck.data = buf;

        /* ============= */
        buf = out_buf + offset;
        used_sz = bc->ck0.len;
        memcpy(buf, &bc->ck0.len, sizeof(bc->ck0.len));
        buf += sizeof(bc->ck0.len);
        offset += sizeof(bc->ck0.len);
        bc->ck0.data = buf;
        used_sz = roaring_bitmap_portable_serialize(bc->r0, buf);
        if (used_sz != bc->ck0.len) {
            printf("May error!!! %lu!=%lu\n", used_sz, bc->ck0.len);
        }
        offset += used_sz;
        bc->ck0.len = used_sz;
        bc->ck0.data = buf;

        i++;
    }
}

/*
load index to idx, if bitmap in idx is null, will create one, or union it

return 0 is ok
*/
int FullIndexLoad(FullIndex *idx, char *fp) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    MmapObj mobj = {0};
    if (0 != MmapRead(fp, &mobj)) {
        return 1;
    }
    Chunk ck = {0};
    int offset = 0;
    i = 0;
    while (i < sz) {
        BitmapChunk *bc = ((BitmapChunk*)idx) + i;
        unsigned char *buf = mobj.addr + offset;
        ck.len = *(typeof(ck.len) *)buf;
        ck.data = sizeof(ck.len) + buf;
        buf += sizeof(ck.len) + ck.len;
        /* next offset */
        offset += sizeof(ck.len) + ck.len;
        if (!ck.len) {
            // 对于0大小的, 
            bc->r = roaring_bitmap_create();
            i++;
            continue;
        }
        roaring_bitmap_t *r = roaring_bitmap_portable_deserialize_safe(ck.data, ck.len);
        if (bc->r)
            roaring_bitmap_or_inplace(bc->r, r); // 并集
        else
            bc->r = r;


        ck.len = *(typeof(ck.len) *)buf;
        ck.data = sizeof(ck.len) + buf;
        buf += sizeof(ck.len) + ck.len;
        /* next offset */
        offset += sizeof(ck.len) + ck.len;
        if (!ck.len) {
            // 对于0大小的, 
            bc->r0 = roaring_bitmap_create();
            i++;
            continue;
        }
        roaring_bitmap_t *r0 = roaring_bitmap_portable_deserialize_safe(ck.data, ck.len);
        if (bc->r0)
            roaring_bitmap_or_inplace(bc->r0, r0); // 并集
        else
            bc->r0 = r0;
        
        i++;
    }
    MmapClear(&mobj);
    return 0;
}
/*
compare two index
return: diff bitmap cnt, 0 is equal, 
*/
int FullIndexCmp(FullIndex *idx, FullIndex *idx2) {
    int i;
    int diff_cnt = 0;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    i = 0;
    while (i < sz) {
        BitmapChunk *bc_left = ((BitmapChunk*)idx) + i;
        BitmapChunk *bc_right = ((BitmapChunk*)idx2) + i;
        if (bc_left->r && bc_right->r) {
            // 均存在
            if (!roaring_bitmap_equals(bc_left->r, bc_right->r)) {
                diff_cnt++;
                goto lbl_next;
            }

        } else {
            // 仅一个存在
            if (bc_left->r || bc_right->r) {
                diff_cnt++;
                goto lbl_next;
            }
        }

        if (bc_left->r0 && bc_right->r0) {
            // 均存在
            if (!roaring_bitmap_equals(bc_left->r0, bc_right->r0)) {
                diff_cnt++;
                goto lbl_next;
            }

        } else {
            // 仅一个存在
            if (bc_left->r0 || bc_right->r0) {
                diff_cnt++;
                goto lbl_next;
            }
        }

lbl_next:
        i++;
    }
    return diff_cnt + (sz - i);
}

int FullIndexAnd(FullIndex *target, FullIndex *tmp) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    BitmapChunk *target_self = NULL;
    BitmapChunk *tmp_self = NULL;;
    bool target_exists;
    bool tmp_exists;
    i = 1;
    if (!target || !tmp)
        return 1;
    target_self = target->self;
    tmp_self = tmp->self;
    
    printf("    Before AND left_card:%lu left_card0:%lu right_card:%lu right_card0:%lu\n"
        , roaring_bitmap_get_cardinality(target_self->r)
        , roaring_bitmap_get_cardinality(target_self->r0)
        , roaring_bitmap_get_cardinality(tmp_self->r)
        , roaring_bitmap_get_cardinality(tmp_self->r0)
    );


    while (i < sz) {
        int can_show = 0;
        BitmapChunk *bc_left = ((BitmapChunk*)target) + i;
        BitmapChunk *bc_right = ((BitmapChunk*)tmp) + i;
        target_exists = roaring_bitmap_contains(target_self->r, i);
        tmp_exists = roaring_bitmap_contains(tmp_self->r, i);
        if (target_exists && tmp_exists) {
            can_show++;
            printf("Try AND %d/%d target_exists: %d, tmp_exists: %d bc_left:%p bc_right:%p left_card:%lu left_card0:%lu right_card:%lu right_card0:%lu\n"
                , i, sz, target_exists, tmp_exists
                , bc_left
                , bc_right
                , roaring_bitmap_get_cardinality(bc_left->r)
                , roaring_bitmap_get_cardinality(bc_left->r0)
                , roaring_bitmap_get_cardinality(bc_right->r)
                , roaring_bitmap_get_cardinality(bc_right->r0)
            );
            if (target_exists && tmp_exists) {
                /* both exists, AND it */
                if (bc_left->r && bc_right->r) {
                    printf("Adding index\n");
                    roaring_bitmap_and_inplace(bc_left->r, bc_right->r);
                } else {
                    /* ERROR */
                    printf("Internal Error, %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
                }
            } else {
                if (tmp_exists) {
                    printf("Oring index\n");
                    /* only in tmp, and target is emtpy, copy tmp to target*/
                    roaring_bitmap_or_inplace(bc_left->r, bc_right->r);
                    /* OR bit to target self */
                    roaring_bitmap_add(target_self->r, i);
                }
            }
        }

        target_exists = roaring_bitmap_contains(target_self->r0, i);
        tmp_exists = roaring_bitmap_contains(tmp_self->r0, i);
        if (target_exists && tmp_exists) {
            can_show++;
            printf("Try AND %d/%d target_exists: %d, tmp_exists: %d left_card:%lu left_card0:%lu right_card:%lu right_card0:%lu\n"
                , i, sz, target_exists, tmp_exists
                , roaring_bitmap_get_cardinality(bc_left->r)
                , roaring_bitmap_get_cardinality(bc_left->r0)
                , roaring_bitmap_get_cardinality(bc_right->r)
                , roaring_bitmap_get_cardinality(bc_right->r0)
            );
            if (target_exists && tmp_exists) {
                /* both exists, AND it */
                if (bc_left->r0 && bc_right->r0) {
                    printf("Adding index\n");
                    roaring_bitmap_and_inplace(bc_left->r0, bc_right->r0);
                } else {
                    /* ERROR */
                    printf("Internal Error, %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
                }
            } else {
                if (tmp_exists) {
                    printf("Oring index\n");
                    /* only in tmp, and target is emtpy, copy tmp to target*/
                    roaring_bitmap_or_inplace(bc_left->r0, bc_right->r0);
                    /* OR bit to target self */
                    roaring_bitmap_add(target_self->r0, i);
                }
            }
        }
        if (can_show)
            printf("    After AND %d/%d left_card:%lu left_card0:%lu right_card:%lu right_card0:%lu\n"
                , i, sz, target_exists, tmp_exists
                , roaring_bitmap_get_cardinality(bc_left->r)
                , roaring_bitmap_get_cardinality(bc_left->r0)
                , roaring_bitmap_get_cardinality(bc_right->r)
                , roaring_bitmap_get_cardinality(bc_right->r0)
            );
        i++;
    }
    return 0;
}

int FullIndexOr(FullIndex *target, FullIndex *tmp) {
    int i;
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    BitmapChunk *target_self = NULL;
    BitmapChunk *tmp_self = NULL;;
    bool target_exists;
    bool tmp_exists;
    i = 1;
    if (!target || !tmp)
        return 1;
    target_self = target->self;
    tmp_self = tmp->self;
    while (i < sz) {
        target_exists = roaring_bitmap_contains(target_self->r, i);
        tmp_exists = roaring_bitmap_contains(tmp_self->r, i);
        if (target_exists || tmp_exists) {
            BitmapChunk *bc_left = ((BitmapChunk*)target) + i;
            BitmapChunk *bc_right = ((BitmapChunk*)tmp) + i;
            if (tmp_exists) {
                /* if in tmp, OR tmp to target*/
                roaring_bitmap_or_inplace(bc_left->r, bc_right->r);
            }
        }

        target_exists = roaring_bitmap_contains(target_self->r0, i);
        tmp_exists = roaring_bitmap_contains(tmp_self->r0, i);
        if (target_exists || tmp_exists) {
            BitmapChunk *bc_left = ((BitmapChunk*)target) + i;
            BitmapChunk *bc_right = ((BitmapChunk*)tmp) + i;
            if (tmp_exists) {
                /* if in tmp, OR tmp to target*/
                roaring_bitmap_or_inplace(bc_left->r0, bc_right->r0);
            }
        }

        i++;
    }
    return 0;
}

roaring_bitmap_t * FullIndex2Bitmap(FullIndex *index) {
    int sz = sizeof(FullIndex) / sizeof(BitmapChunk);
    int i;
    uint64_t condition_card;
    BitmapChunk *index_self = NULL;
    
    roaring_bitmap_t* ret = roaring_bitmap_create();
    roaring_bitmap_t* ret0 = NULL;
    if (!index)
        return ret;
    index_self = index->self;
    
    roaring_bitmap_flip_inplace(ret, MAPPER_MIN_ID, MAPPER_MAX_ID);

    condition_card = roaring_bitmap_get_cardinality(ret);
    
    condition_card = roaring_bitmap_get_cardinality(index_self->r);
    if (!condition_card) {
        printf("No andy card, return all bit set bitmap\n");
        /* no any condition */
        return ret;
    } else {
        printf("index card is :%lu\n", condition_card);
    }
    printf("orign index r: ");
    roaring_bitmap_printf(index_self->r);
    printf("\norign index r0: ");
    roaring_bitmap_printf(index_self->r0);
    printf("\n");
    ret0 = roaring_bitmap_create();
    roaring_bitmap_flip_inplace(ret0, MAPPER_MIN_ID, MAPPER_MAX_ID);
    printf("orig ret card is :%lu ret0 card is :%lu\n", roaring_bitmap_get_cardinality(ret), roaring_bitmap_get_cardinality(ret0));

    i = 1;
    /* foreach every BitmapChunk */
    while (i < sz) {
        BitmapChunk *bc_left = ((BitmapChunk*)index) + i;
        
        bool index_exists = roaring_bitmap_contains(index_self->r, i);
        bool index0_exists = roaring_bitmap_contains(index_self->r0,  i);
        if (!index_exists && !index0_exists) {
            i++;
            continue;
        }
        printf("Checking index: %d ", i);
        if (index_exists && bc_left->r) {
            if (index_exists) {
                printf("%d/%d index_exists: %d, index:%p bc_left:%p r:%p rcard:%lu\n", i, sz, index_exists, index, bc_left, bc_left->r, roaring_bitmap_get_cardinality(bc_left->r));
                // roaring_bitmap_printf(bc_left->r);
                printf("\n");
            }
            roaring_bitmap_and_inplace(ret, bc_left->r);
        }

        if (index0_exists && bc_left->r0) {
            if (index0_exists) {
                printf("%d/%d index0_exists: %d, index:%p bc_left:%p r0:%p r0card:%lu\n", i, sz, index0_exists, index, bc_left, bc_left->r0, roaring_bitmap_get_cardinality(bc_left->r0));
                // roaring_bitmap_printf(bc_left->r);
                printf("\n");
            }
            roaring_bitmap_and_inplace(ret0, bc_left->r0);
        }
        condition_card = MAX(roaring_bitmap_get_cardinality(ret0), roaring_bitmap_get_cardinality(ret));
        printf("after loop %d, ret0 card is :%lu ret card is :%lu\n", i, roaring_bitmap_get_cardinality(ret0), roaring_bitmap_get_cardinality(ret));
        if (condition_card < 10000 && condition_card > 0) {
            if (index_exists) {
                printf("bc_left->r is: ");
                roaring_bitmap_printf(bc_left->r);
                printf("\n");
            }
            if (index0_exists) {
                printf("bc_left->r0 is: ");
                roaring_bitmap_printf(bc_left->r0);
                printf("\n");
            }
            if (index_exists || index0_exists) {
                printf("ret is: ");
                roaring_bitmap_printf(ret);
                printf("\n");
            }
        } else {
            printf("skip too long/short bc print\n");
        }
        i++;
    }
    condition_card = roaring_bitmap_get_cardinality(ret);
    printf("ret card is :%lu\n", condition_card);
    if (condition_card < 10000)
        roaring_bitmap_printf(ret);
    printf("\n");

    condition_card = roaring_bitmap_get_cardinality(ret0);
    printf("ret0 card is :%lu\n", condition_card);
    if (condition_card < 10000)
        roaring_bitmap_printf(ret0);
    printf("\n");
    
    roaring_bitmap_and_inplace(ret, ret0);
    roaring_bitmap_free(ret0);
    return ret;
}

/*
write index to file
return 0 is ok
*/
int FullIndexWrite(FullIndex *idx, char *fp) {
    int i;
    MmapObj mobj = {0};
    uint64_t sz = 0;
    if (!idx || !fp) {
        return 1;
    }
    FullIndexDump(idx, NULL, &sz);
    printf("Dump need size: %lu, target fp:%s\n", sz, fp);
    if (0 != MmapWrite(fp, &mobj, sz)) {
        printf("Cant open %s for dump\n", fp);
        return 2;
    }
    FullIndexDump(idx, mobj.addr, &sz);
    printf("Dump over\n");
    MmapClear(&mobj);
    return 0;
}

void dump(void *buf, int len) {
    int i = 0;
    unsigned char c;
    while( i < len) {
        c = ((uint8_t *)buf)[i];
        printf("%02x", c);
        i++;
    }
    printf("\n");
}

void test_find_pkt() {
    struct iphdr ip = {0};
    struct iphdr ip_mask = {0};
    uint64_t card1 = 0;
    const char *sip = "192.168.160.190";
    unsigned char buf[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, sip, buf) <= 0) {
        printf("cant parse ip %s \n", sip);
        return;
    }
    memcpy(&ip.saddr, buf, sizeof(ip.saddr));
    memset(&ip_mask.saddr, 0xff, sizeof(ip_mask.saddr));
    ip.check =htons(0x1ff2);
    printf("ip mem is:  ");
    dump(&ip, sizeof(ip));
    printf("ip mask is: ");
    dump(&ip_mask, sizeof(ip_mask));
    /*
    1. create temp index
    2. compute and between index with loaded index
    3. iter bitmap and get pcap by offset
    */
    FullIndex index = {0};
    // printf("  FullIndexCreateWithAll\n");
    FullIndexCreate(&index);
    // printf("  FullIndexCreateWithAll over\n");

    roaring_bitmap_t *ra2 = FullIndex2Bitmap(&index);
    roaring_bitmap_add_range(ra2, MAPPER_MIN_ID, MAPPER_MAX_ID);
    // roaring_bitmap_flip_inplace(ra2, MAPPER_MIN_ID, MAPPER_MAX_ID);
    card1 = roaring_bitmap_get_cardinality(ra2);
    printf("card1: %u\n", card1);
    printf("tag01 full_index_loaded\n");
    FullIndexPrint(&full_index_loaded);
    printf("Building search full index\n");
    update_index_common_fast(&index, &full_index_loaded, INDEX_TYPE_IPV4, (const uint8_t *)&ip, (const uint8_t *)&ip_mask, sizeof(ip));
    // update_index_common_fast(&index, &full_index_loaded, INDEX_TYPE_IPV4, (const uint8_t *)&ip, NULL, sizeof(ip));
    printf("tag01 index\n");
    FullIndexPrint(&index);
    
    FullIndexAnd(&index, &full_index_loaded);
    printf("tag02\n");
    roaring_bitmap_t *ra = FullIndex2Bitmap(&index);
    printf("tag03\n");

    card1 = roaring_bitmap_get_cardinality(ra);
    printf("card1.1: %u\n", card1);
    if (card1 < 1000) {
        uint32_t *arr1 = (uint32_t *) malloc(card1 * sizeof(uint32_t));
        printf("tag04\n");

        roaring_bitmap_to_uint32_array(ra, arr1);
        int i = 0;
        printf("tag05\n");
        while(i < card1) {
            printf("pkt id:%u\n", arr1[i]);
            i++;
        }
    } else {
        printf("skip too much bits\n");
    }
    if (can_bye) {
        printf("Bye\n");
        exit (0);
    }
}

int main(int argc, char **argv) {
    char errbuf[256] = {0};
    char *pcap_file = NULL;
    pcap_t *handle;
    int fd;
    struct pcap_pkthdr header; // same as pcap_pkthdr
    uint64_t pkt_id = 0;
    /* https://wiki.wireshark.org/Development/LibpcapFileFormat */
    uint64_t offset = sizeof(struct pcap_file_header);
    const u_char *packet;
    if (argc != 2){
        if (argc == 3) {
            can_bye = 1;
        } else {
            show_usage();
            exit(1);
        }
    }
    pcap_file = argv[1];
    handle = pcap_open_offline_with_tstamp_precision(pcap_file, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!handle) {
        printf("Cant open pcap file: %s, error: %s\n", pcap_file, errbuf);
        exit(2);
    }
    open_files();
    FullIndexCreate(&full_index);
    FullIndexCreate(&full_index_loaded);
    printf("try load full index\n");
    FullIndexLoad(&full_index_loaded, INDEX_BPF);
    printf("load full over\n");
    test_find_pkt();

    while (1) {
        int cur_pos;
        uint64_t nano_sec;

        packet = pcap_next(handle, &header);
        if (!packet) {
            printf("Over\n");
            break;
        }
        nano_sec = header.ts.tv_sec * 1000000000 + header.ts.tv_usec;
        packet_process(pkt_id, offset, header.caplen, packet, nano_sec);
        /* next packet offset */
        offset += sizeof(struct pcap_pkthdr) + header.caplen;
        pkt_id++;
    }
    printf("Current pcap diff cnt: %d\n", FullIndexCmp(&full_index, &full_index_loaded));
    FullIndexWrite(&full_index, INDEX_BPF);
    printf("New created full index:\n");
    FullIndexPrint(&full_index);

    pcap_close(handle);
    close_files();
}
