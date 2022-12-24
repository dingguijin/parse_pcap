#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_pcap.h"


void test_data(const char* pcap_file) {
    FILE* fp = fopen(pcap_file, "rb");
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    printf("file size: %d\n", sz);
    unsigned char* pcap_data = (unsigned char*)malloc(sz);
    fseek(fp, 0L, SEEK_SET);
    fread(pcap_data, sz, 1, fp); 
    fclose(fp);
    
    parse_pcap_data(pcap_data, sz, NULL, 0);
}

void test_section(const char* pcap_file) {
    psml_packet_array_t* array = parse_pcap_section(pcap_file);
    printf("get array size: %d\n", array->array_size);
    for(int i = 0; i < array->array_size; i++) {
        printf("packet->info: [%s]\n", array->array[i]->info);
    }
}

void test_pcap(const char* pcap_file) {
    field_t* field = parse_pcap_file(pcap_file, NULL, -1);
    printf("field tag[%s], size [%d]\n", field->tag, field->array_size);
    for (int i = 0; i < field->array_size; i++) {
        field_t* fs = field->array[i];
        printf("field tag[%s], size[%d]\n", fs->tag, fs->array_size);
    }
}

int main(int argc, char** argv) {
    // char pcap_file[] = "/Users/dingguijin/send_to_me.pcap";
    char pcap_file[] = "/Users/dingguijin/projects/parser_pcap/TLS.pcapng";
    // parse_pcap_file(pcap_file, NULL, 0);
    test_pcap(pcap_file);
    return 0;
}
