#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_pcap.h"
int main(int argc, char** argv) {
    char pcap_file[] = "~/send_to_me.pcap";
    parse_pcap_file(pcap_file, NULL, -1);
    return 0;
}
