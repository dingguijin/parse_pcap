#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_pcap.h"
int main(int argc, char** argv) {
    char pcap_file[] = "/Users/dingguijin/send_to_me.pcap";
    // parse_pcap_file(pcap_file, NULL, -1);
    // parse_pcap_file(pcap_file, NULL, 0);
    FILE* fp = fopen(pcap_file, "rb");
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    printf("file size: %d\n", sz);
    unsigned char* pcap_data = (unsigned char*)malloc(sz);
    fseek(fp, 0L, SEEK_SET);
    fread(pcap_data, sz, 1, fp); 
    fclose(fp);
    
    parse_pcap_data(pcap_data, sz, NULL, 0);
    return 0;
}
