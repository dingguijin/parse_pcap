#ifndef __PARSE_PCAP_H__
#define __PARSE_PCAP_H__

typedef struct {
    char* name;
    int pos;
    char* show;
    char* showname;
    char* value;
    int size;
    char* unmaskedvalue;
} field_data_t;

typedef struct field_struct {
    field_data_t* field;
    struct field_struct** array;
    int array_size;
    char* tag;

// not for customer, internal use only
    struct field_struct* current;
    struct field_struct* next;
} field_t;

#ifdef __cplusplus
extern "C" {
#endif

    // pcap_file_path is pcap file absolute file path
    // wireshark_display_filter, like "tcp.flags.syn==1 && tcp.flags.ack==1", pass to tshark after "-Y"
    // pkt_no = -1 means return all parsed packets data
    // pkt_no >= 0 means return the pkt_no indexed packet data
    // any error return NULL
    field_t* parse_pcap_file(const char* pcap_file_path, const char* wireshark_display_filter, int pkt_no);


    // a convenient interface for pcap data
    // pcap_file_data is pcap data in memory as byte data (unsigned char)
    // len is pcap data len in memory as byte data (unsigned char)
    // pkt_no = -1 means return all parsed packets data
    // pkt_no >= 0 means return the pkt_no indexed packet data
    // any error return NULL
    field_t* parse_pcap_data(const unsigned char* pcap_file_data, int len, const char* wireshark_display_filter, int pkt_no);

#ifdef __cplusplus
}
#endif

#endif // __PARSE_PCAP_H__
