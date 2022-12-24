#ifndef __PARSE_PCAP_H__
#define __PARSE_PCAP_H__

typedef struct psml_packet {
    char* number;
    char* time;
    char *source;
    char *destination;
    char *protocol;
    char* length;
    char *info;

    // internal use only
    struct psml_packet* next;
} psml_packet_t;

typedef struct {
   psml_packet_t** array;
   int array_size;

   // internal use only
   psml_packet_t* head;
   psml_packet_t* current;
   int state;
} psml_packet_array_t;

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

    // pcap_file_path is pcap file path
    // return psml_packet_array_t that include array pointer and array size
    // any error return NULL
    psml_packet_array_t* parse_pcap_section(const char* pcap_file_path);

    // pcap_file_path is pcap file absolute file path
    // wireshark_display_filter, like "tcp.flags.syn==1 && tcp.flags.ack==1", pass to tshark after "-Y"
    // pkt_no = -1 means return all parsed packets data
    // pkt_no >= 0 means return the pkt_no indexed packet data
    // any error return NULL
    // DLLEXPORT
    field_t* parse_pcap_file(const char* pcap_file_path, const char* wireshark_display_filter, int pkt_no);


    // a convenient interface for pcap data
    // pcap_file_data is pcap data in memory as byte data (unsigned char)
    // len is pcap data len in memory as byte data (unsigned char)
    // pkt_no = -1 means return all parsed packets data
    // pkt_no >= 0 means return the pkt_no indexed packet data
    // any error return NULL
    // DLLEXPORT
    field_t* parse_pcap_data(const unsigned char* pcap_file_data, int len, const char* wireshark_display_filter, int pkt_no);

#ifdef __cplusplus
}
#endif

#endif // __PARSE_PCAP_H__
