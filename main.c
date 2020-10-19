#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/mman.h> // mmap
#include <roaring/roaring.h>
/*
headers
*/
#include <stdint.h>
/* 
sample index type 
    index_key: XXX
    index_type: 256/65536
    index_bpf_name: 
    index_plugin: get_value_func
    index_data: 
*/
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
Mapper format:
PktIdOffsetMapperHeader
PktIdOffsetMapperNode
PktIdOffsetMapperNode
PktIdOffsetMapperNode
...

*/

#define MAPPER_MAGIC 0x6e616974676e6570U // "pengtian"
#define MAPPER_NAME_SIZE 256 
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
    roaring_bitmap_t *r;
    Chunk ck;
} BitmapChunk;

/*
0~255       => sip0 bitmap
256~511     => sip1 bitmap
512~767     => sip2 bitmap
768~1023    => sip3 bitmap
1024 + 0~255       => dip0 bitmap
1024 + 256~511     => dip1 bitmap
1024 + 512~767     => dip2 bitmap
1024 + 768~1023    => dip3 bitmap
2048 + 0~65535      => sport bitmap
2048 + 65536 + 0~65535 => dport bitmap
2048+65536*2 + 0~255 => ip protocol bitmap
*/
/* this struct should be aligned, all index is little endian */
typedef struct _FullIndex {
    /* 00:11:22:33:44:55 */
    BitmapChunk mac0[256];
    BitmapChunk mac1[256];
    BitmapChunk mac2[256];
    BitmapChunk mac3[256];
    BitmapChunk mac4[256];
    BitmapChunk mac5[256];
    /* 0x0800 */
    BitmapChunk ether_type[65536];
    /* 192.168.0.1 */
    BitmapChunk sip0[256];
    BitmapChunk sip1[256];
    BitmapChunk sip2[256];
    BitmapChunk sip3[256];
    BitmapChunk dip0[256];
    BitmapChunk dip1[256];
    BitmapChunk dip2[256];
    BitmapChunk dip3[256];
    /* IPPROTO_XXX */
    BitmapChunk ip_proto[256];
    BitmapChunk sport[65536];
    BitmapChunk dport[65536];
} FullIndex;

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
void packet_process(uint64_t pkt_id, uint64_t offset, uint64_t sz, const unsigned char *data, uint64_t nano_sec) {
    printf("TODO: handle packet, pkt_id: %lu offset: %lu fake pcap_hdr_sz: %lu real pcap_hdr_sz:%lu timeval: %lu data sz: %lu\n"
        , pkt_id, offset, sizeof(struct pcap_pkthdr), sizeof(struct timeval), sz
    );
    /* assume data is ether*/
    const struct ethhdr *eth;
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    const struct udphdr *udp;

    uint8_t ip_proto = 0;
    uint16_t ether_type = 0;
    uint64_t sip = 0;
    uint64_t dip = 0;
    uint8_t sip_val[4];
    uint8_t dip_val[4];
    uint16_t sport, dport;

    eth = (struct ethhdr *)data;

    ether_type = ntohs(eth->h_proto);
    if (ether_type != ETH_P_IP) {
	printf("Skip non IP packet\n");
        goto lbl_end;
    }
    ip = (struct iphdr *)(eth + 1);

    /* 写包和offset的 对应文件 */
    PktIdOffsetMapperNode m = {
        .offset = offset,
        .timestamp = nano_sec
    };
    int r = write(g_mapper_fd, &m, sizeof(PktIdOffsetMapperNode));
    if (r != sizeof(PktIdOffsetMapperNode)) {
        printf("Write fail, fd: %d, error: %s\n", g_mapper_fd, strerror(errno));
        goto lbl_end;
    }

    /* handling sip0 index */
    
    // if (0 != sip0_index.func.get((void *)container_of(ip, struct iphdr, saddr), 4, &sip, NULL)) {
    //     printf("get sip0 index fail\n");
    //     goto lbl_end;
    // }
    
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
    // 更新index信息, 遍历完成后会序列化
    roaring_bitmap_add(full_index.ether_type[ether_type].r, pkt_id);
    roaring_bitmap_add(full_index.ip_proto[ip_proto].r, pkt_id);
    roaring_bitmap_add(full_index.sip0[sip_val[0]].r,   pkt_id);
    roaring_bitmap_add(full_index.sip1[sip_val[1]].r,   pkt_id);
    roaring_bitmap_add(full_index.sip2[sip_val[2]].r,   pkt_id);
    roaring_bitmap_add(full_index.sip3[sip_val[3]].r,   pkt_id);
    roaring_bitmap_add(full_index.dip0[dip_val[0]].r,   pkt_id);
    roaring_bitmap_add(full_index.dip1[dip_val[1]].r,   pkt_id);
    roaring_bitmap_add(full_index.dip2[dip_val[2]].r,   pkt_id);
    roaring_bitmap_add(full_index.dip3[dip_val[3]].r,   pkt_id);
    roaring_bitmap_add(full_index.sport[sport].r,       pkt_id);
    roaring_bitmap_add(full_index.dport[dport].r,       pkt_id);

    if (nano_sec < g_mapper_header.start_timestamp || g_mapper_header.start_timestamp == 0) {
        g_mapper_header.start_timestamp = nano_sec;
    }
    if (nano_sec > g_mapper_header.end_timestamp || g_mapper_header.end_timestamp == 0) {
        g_mapper_header.end_timestamp = nano_sec;
    }
    g_mapper_header.cnt++;

lbl_end:
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
        i++;
    }
}

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
        if (compress_bitmap)
            roaring_bitmap_run_optimize(bc->r);
        size_t bs = roaring_bitmap_portable_size_in_bytes(bc->r);
        need_buf_sz += bs + sizeof( typeof(((Chunk *)0)->len ));
        bc->ck.len = bs; // 设置需要的长度到ck中
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
        // printf("%d Will write bitmap to buf, %lu+%lu @%lu\n", i, sizeof( typeof(((Chunk *)0)->len )), used_sz, offset);
        if (used_sz != bc->ck.len) {
            printf("May errro!!! %lu!=%lu\n", used_sz, bc->ck.len);
        }
        offset += used_sz;
        bc->ck.len = used_sz;
        bc->ck.data = buf;
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
        ck.data = buf + sizeof(ck.len);
        /* next offset */
        offset += sizeof(ck.len) + ck.len;
        if (!ck.len) {
            // 对于0大小的, 
            bc->r = roaring_bitmap_create();
            i++;
            continue;
        }
        // printf("Deserialize bitmap, data len: %lu@%lu\n", ck.len, buf - (unsigned char*)mobj.addr);
        roaring_bitmap_t *r = roaring_bitmap_portable_deserialize_safe(ck.data, ck.len);
        if (bc->r)
            roaring_bitmap_or_inplace(bc->r, r); // 并集
        else
            bc->r = r;
        i++;
    }
    MmapClear(&mobj);
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
            if (!roaring_bitmap_equals(bc_left->r, bc_right->r))
                diff_cnt++;
        } else {
            // 仅一个存在
            if (bc_left->r || bc_right->r)
                diff_cnt++;
        }
        i++;
    }
    return diff_cnt;
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
        show_usage();
        exit(1);
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
    FullIndexLoad(&full_index_loaded, INDEX_BPF);
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
    pcap_close(handle);
    close_files();
}
