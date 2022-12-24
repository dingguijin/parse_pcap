#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if defined(__clang__) && defined(__APPLE__)
#include <unistd.h>
#endif
#include <time.h>
#if defined(_MSC_VER) || defined(__MINGW32__)
#include <windows.h>
#endif
#if defined (__GNUC__) && defined (__linux__)
#include <unistd.h>
#endif

#include "parse_pcap.h"
#include "parse_xml.h"

typedef enum {
    SECTION_NULL = 0,
    SECTION_NUMBER = 1,
    SECTION_TIME = 2,
    SECTION_SOURCE = 3,
    SECTION_DESTINATION = 4,
    SECTION_PROTOCOL = 5,
    SECTION_LENGTH = 6,
    SECTION_INFO = 7
} section_state_t;


static int is_open_packet_tag(char* tag) {
    if (strcmp(tag, "packet") == 0) {
        return 1;
    }
    return 0;
}

static int is_close_psml_tag(char* tag) {
    if (strcmp(tag, "/psml") == 0) {
        return 1;
    }
    return 0;
}

static int is_section_line(char* tag) {
    if (strcmp(tag, "section") == 0) {
        return 1;
    }
    return 0;
}

static char* get_section_text(char* line) {
    if (strlen(line) <= strlen("<section></section>")) {
        return strdup("\0");
    }
    if (strstr(line, "<section>") != line) {
        return strdup("\0");
    }
    char tmp[2048];
    strcpy(tmp, &line[strlen("<section>")]);
    tmp[strlen(tmp) - strlen("</section>")] = '\0';
    char* xml_string = escape_xml_string(tmp);
    if (!xml_string || strlen(xml_string) == 0) {
        return strdup("\0");
    }
    return strdup(xml_string);
}

static void parse_section_line(psml_packet_array_t* array, char* buf) {
    if (!array->current) {
        return;
    }
    psml_packet_t* packet = array->current;
    section_state_t* state = (section_state_t*)&array->state;
    if (*state == SECTION_NULL) {
        *state = SECTION_NUMBER;
    }
    if (*state == SECTION_NUMBER) {
        packet->number = get_section_text(buf);
        *state = SECTION_TIME;
        return;
    }
    if (*state == SECTION_TIME) {
        packet->time = get_section_text(buf);
        *state = SECTION_SOURCE;
        return;
    }
    if (*state == SECTION_SOURCE) {
        packet->source = get_section_text(buf);
        *state = SECTION_DESTINATION;
        return;
    }
    if (*state == SECTION_DESTINATION) {
        packet->destination = get_section_text(buf);
        *state = SECTION_PROTOCOL;
        return;
    }
    if (*state == SECTION_PROTOCOL) {
        packet->protocol = get_section_text(buf);
        *state = SECTION_LENGTH;
        return;
    }
    if (*state == SECTION_LENGTH) {
        packet->length = get_section_text(buf);
        *state = SECTION_INFO;
        return;
    }
    if (*state == SECTION_INFO) {
        packet->info = get_section_text(buf);
        *state = SECTION_NULL;
        return;
    }
    return;
}

static psml_packet_t* on_packet_open(psml_packet_array_t* array) {
    psml_packet_t* psml_packet = (psml_packet_t*)malloc(sizeof(psml_packet_t));
    memset(psml_packet, 0, sizeof(psml_packet_t));
    if (array->current) {
        array->current->next = psml_packet;
    }
    if (!array->head) {
        array->head = psml_packet;
    }

    array->current = psml_packet;
    array->array_size++;
    return psml_packet;
}

static void on_psml_close(psml_packet_array_t* array) {
    psml_packet_t* packet = array->head;
    int array_index = 0;

    if (array->array_size == 0) {
        return;
    }

    array->array = (psml_packet_t**)malloc(array->array_size * sizeof(psml_packet_t*));
    while(packet) {
        array->array[array_index++] = packet;
        packet = packet->next;
    }
    return;
}

psml_packet_array_t* parse_pcap_section(const char* pcap_file_path)
{
    if (!pcap_file_path) {
        return NULL;
    }
    if (strlen(pcap_file_path) == 0) {
        return NULL;
    }
    char final_cmd[_MAX_PATH_LEN];
    memset(final_cmd, 0, sizeof(final_cmd));
    if (NULL == get_psml_final_cmd(pcap_file_path, final_cmd)) {
        return NULL;
    }
    
#if defined(__clang__) && defined (__APPLE__)
    FILE* _std = popen(final_cmd, "r");
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
    AllocConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    FILE* _std = _popen(final_cmd, "r");
#endif

#if defined(__GNUC__) && defined (__linux__)
    FILE* _std = popen(final_cmd, "r");
#endif

    char buf[LINE_LEN];
    char mbuf[LINE_LEN];
    char tag[TAG_LEN];

    memset(tag, 0, sizeof(tag));
    memset(mbuf, 0, sizeof(mbuf));

    section_state_t section_state  = SECTION_NULL;
    psml_packet_array_t* packet_array = (psml_packet_array_t*)malloc(sizeof(psml_packet_array_t));

    packet_array->array_size = 0;
    packet_array->array = NULL;
    packet_array->current = NULL;
    packet_array->head = NULL;
    packet_array->state = (int)section_state;
    
    while(1) {
        const char* get = fgets(buf, sizeof(buf), _std);
        if (get == NULL) {
            break;
        }
        
        if (strlen(buf) == 0) {
            continue;
        }

        char* rbuf = remove_spaces(buf);
        if (strlen(rbuf) == 0) {
            continue;
        }
        
        if (need_next_line(rbuf)) {
            strcat(mbuf, rbuf);
            continue;
        }
        strcat(mbuf, rbuf);
        strcpy(rbuf, mbuf);
        mbuf[0] = '\0';
        
        memset(tag, 0, sizeof(tag));
        get_tag(rbuf, tag);

        if (is_open_packet_tag(tag)) {
            on_packet_open(packet_array);
            continue;
        }
        
        if (is_close_psml_tag(tag)) {
            on_psml_close(packet_array);
            continue;
        }

        if (is_section_line(tag)) {
            parse_section_line(packet_array, rbuf);
            continue;
        }
    }

    fclose(_std);
    return packet_array;
}
