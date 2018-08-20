#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

struct filter_t {
    char *bytes;
    int len;
};

int
parse_filters(int argc, char **argv, struct filter_t **filters_ret)
{
    int num_filters = (argc)/2;
    if (num_filters <= 0) {
        fprintf(stderr, "Missing filter\n");
        return 0;
    }
    if (argc%2 == 1) {
        fprintf(stderr, "Invalid number of filter words\n");
        return 0;
    }
    struct filter_t *filters = malloc(num_filters * sizeof(struct filter_t));
    int i;
    int f = 0;
    for(i=0; i < argc; i=i+2) {
        char *op = argv[i];
        char *arg = argv[i+1];
        //printf("Filter %d: %s:%s\n", i, op, arg);
        if (0==strcmp(op, "body")) {
            filters[f].bytes = arg;
            filters[f].len = strlen(arg);
        } else {
            fprintf(stderr, "Invalid filter: %s\n", op);
            return 0;
        }
        f++;
    }
    *filters_ret = filters;
    return num_filters;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    pcap_t *op;
    pcap_dumper_t *pcap_dumper;

    struct pcap_pkthdr hdr;
    const u_char *packet;

    int i;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s in.pcap out.pcap [filters]\n", argv[0]);
        return 1;
    }
    char *infn = argv[1];
    char *outfn = argv[2];

    struct filter_t *filters;
    int num_filters = parse_filters(argc-3, argv+3, &filters);
    if(num_filters == 0) {
        return 1;
    }
    #if 0
    printf("filters: %d\n", num_filters);
    for(int f=0; f< num_filters; f++) {
        fprintf(stderr, "Filter %d = %s\n", f, filters[f].bytes);
    }
    #endif

    p = pcap_open_offline(infn, errbuf);
    if (p == NULL) {
        printf("pcap_open_live: %s\n", errbuf);
        return 1;
    }

    op = pcap_open_dead(pcap_datalink(p), 65536);
    pcap_dumper = pcap_dump_open(op, outfn);

    int pkt_num = 0;
    while (1) {
        next:
        packet = pcap_next(p, &hdr);
        pkt_num++;
        if(packet==NULL)
            break;
        if (hdr.len) {
            for(int f=0; f< num_filters; f++) {
                if(memmem(packet, hdr.len, filters[f].bytes, filters[f].len) == NULL)
                    goto next;
            }
            printf("Packet %d matches\n", pkt_num);
            pcap_dump((u_char*)pcap_dumper, &hdr, packet);
        }
    }
}
