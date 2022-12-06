#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "parse_pcap.h"
#include "parse_xml.h"

static char* get_final_cmd(const char* file_path, const char* filter, char* final_cmd)
{
    char tshark_cmd[1024] = {0};
#ifdef _MSC_VER
    char dll_path[MAX_PATH];
    HMODULE hm = NULL;

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCSTR) &parse_pcap_file, &hm) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);
        return NULL;
    }
    if (GetModuleFileName(hm, dll_path, sizeof(path)) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleFileName failed, error = %d\n", ret);
        return NULL;
    }
    while(len--) {
        if(dll_path[len] == '\\') {
            dll_path[len] = '\0';
            break;
        }
        if(dll_path[len] == '/') {
            dll_path[len] = '\0';
            break;
        }
    }
    sprintf(tshark_cmd, "%s\\tshark.exe", dll_path);
#endif // _MSC_VER

#ifdef __clang__
    strcpy(tshark_cmd, "/Users/dingguijin/projects/wireshark/wireshark/build/run/Wireshark.app/Contents/MacOS/tshark");
#endif

    // const char* cmd_args = "-Y \"tcp.flags.syn==1 && tcp.flags.ack==1\" -T pdml -V -n -r";
    char wireshark_filter[1024] = {0};
    const char* cmd_args = "-T pdml -Vn -r";
    if (filter != NULL) {
        sprintf(wireshark_filter, "-Y \"%s\"", filter);
    }
    sprintf(final_cmd, "%s %s %s %s", tshark_cmd, wireshark_filter, cmd_args, file_path);
    return final_cmd;
}

typedef struct attr_pair {
    char* attr_name;
    char* attr_value;
    struct attr_pair* next;
} attr_pair_t;

static attr_pair_t* get_attr_pair(char* line) {
    attr_pair_t* head = NULL;
    attr_pair_t* current = NULL;

    int len = strlen(line);
    int status = 0;
    int j = 0;
    char attr_name[256];
    char attr_value[256* 1024];
    
    for (int i = 0; i < len; i++) {
        if (line[i] == ' ' && status == 0) {
            j = 0;
            status = 1;
            continue;
        }

        if (status == 1) {
            if (line[i] != ' ' && line[i] != '=') {
                attr_name[j++] = line[i];
            }
            if (line[i] == '=') {
                attr_name[j] = '\0';
                status = 2;
            }
            continue;
        }

        if (status == 2) {
            if (line[i] == '"') {
                j = 0;
                status = 3;
            }
            continue;
        }

        if (status == 3) {
            if (line[i] != '"') {
                attr_value[j++] = line[i];
            } else {
                attr_value[j] = '\0';
                status = 0;
                if (!current) {                    
                    current = (attr_pair_t*)malloc(sizeof(attr_pair_t));
                    head = current;
                } else {
                    attr_pair_t* ap = (attr_pair_t*)malloc(sizeof(attr_pair_t));
                    current->next = ap;
                    current = ap;
                }
                current->attr_name = strdup(attr_name);
                current->attr_value = strdup(attr_value);
                current->next = NULL;
                // printf("attr_name: [%s], attr_value: [%s] \n", attr_name, attr_value);
            }
            continue;
        }        
    }
    return head;
}

static void parse_pdml(attr_pair_t* attr_pair_list, field_data_t* field) {
    attr_pair_t* current = attr_pair_list;
    while(current) {
        if (strcmp(current->attr_name, "version") == 0) {
            field->pos = strtol(current->attr_value, (char**)NULL, 10);
            free(current->attr_name);
            free(current->attr_value);
        }
        if (strcmp(current->attr_name, "creator") == 0) {
            field->name = current->attr_value;
            free(current->attr_name);
        }
        if (strcmp(current->attr_name, "time") == 0) {
            field->show = current->attr_value;
            free(current->attr_name);
        }
        if (strcmp(current->attr_name, "capture_file") == 0) {
            field->showname = current->attr_value;
            free(current->attr_name);
        }
        attr_pair_t* to_free = current;
        current = current->next;
        free(to_free);
    }
}

static void parse_packet(attr_pair_t* attr_pair_list, field_data_t* field) {
}

static void parse_proto(attr_pair_t* attr_pair_list, field_data_t* field) {
    attr_pair_t* current = attr_pair_list;
    while(current) {
        if (strcmp(current->attr_name, "name") == 0) {
            field->name = current->attr_value;
        }
        if (strcmp(current->attr_name, "pos") == 0) {
            field->pos = strtol(current->attr_value, (char**)NULL, 10);
            free(current->attr_value);
        }
        if (strcmp(current->attr_name, "showname") == 0) {
            field->showname = current->attr_value;
        }
        if (strcmp(current->attr_name, "size") == 0) {
            field->size = strtol(current->attr_value, (char**)NULL, 10);
            free(current->attr_value);
        }
        free(current->attr_name);
        attr_pair_t* to_free = current;
        current = current->next;
        free(to_free);
    }
    printf("ZZZZZZZZ PROTO [%s]\n", field->showname);
}

static void parse_field(attr_pair_t* attr_pair_list, field_data_t* field) {
    attr_pair_t* current = attr_pair_list;
    while(current) {
        if (strcmp(current->attr_name, "name") == 0) {
            field->name = current->attr_value;
        }
        if (strcmp(current->attr_name, "pos") == 0) {
            field->pos = strtol(current->attr_value, (char**)NULL, 10);
            free(current->attr_value);
        }
        if (strcmp(current->attr_name, "showname") == 0) {
            field->showname = current->attr_value;
        }
        if (strcmp(current->attr_name, "size") == 0) {
            field->size = strtol(current->attr_value, (char**)NULL, 10);
            free(current->attr_value);
        }
        if (strcmp(current->attr_name, "value") == 0) {
            field->value = current->attr_value;
        }
        free(current->attr_name);
        attr_pair_t* to_free = current;
        current = current->next;
        free(to_free);
    }
    printf("ZZZZZZZZ FIELD [%s]\n", field->showname);
}

static void parse_line(const char* tag, char* line, field_data_t* field) {
    attr_pair_t* head = get_attr_pair(line);
    if (!head) {
        return;
    }
    if (strcmp(tag, "pdml") == 0) {
        return parse_pdml(head, field);
    }
    if (strcmp(tag, "packet") == 0) {
        return parse_packet(head, field);
    }
    if (strcmp(tag, "proto") == 0) {
        return parse_proto(head, field);
    }
    if (strcmp(tag, "field") == 0) {
        return parse_field(head, field);
    }
    printf("unknown tag [%s] \n", tag);
    return;
}

static field_t* on_tag_open(const char* tag, char* buf, field_t* parent) {
    
    field_data_t* field_data = (field_data_t*)malloc(sizeof(field_data_t));
    memset(field_data, 0, sizeof(field_data_t));
    parse_line(tag, buf, field_data);
    
    if (strcmp(tag, "pdml") == 0) {
        parent->tag = strdup(tag);
        parent->field = field_data;
        parent->array_size = 0;
        return parent;
    }

    field_t* field = (field_t*)malloc(sizeof(field_t));
    memset(field, 0, sizeof(field_t));
    field->field = field_data;
    field->tag = strdup(tag);
    field->next = NULL;

    if (parent->current) {
        parent->current->next = field;
    } else {
        parent->array = (field_t**)field;
    }    
    parent->current = field;
    parent->array_size++;
    return field;
}

static void on_tag_close(field_t* parent) {
    if (!parent->array) {
        return;
    }
    if (!parent->array_size) {
        return;
    }

    field_t* head = (field_t*) parent->array;
    field_t* current = head;
    int i = 0;

    //printf("array size [%d] \n", parent->array_size);
    parent->array = (field_t**)malloc(sizeof(field_t*)* parent->array_size);
    while(current) {
        parent->array[i++] = current;
        current = current->next;
    }
    return;
}

static int open_explicit_packet(const char* tag, int pkt_no, int* pkt_status) {
    if (pkt_no < 0) {
        return 1;
    }
    if (strcmp(tag, "pdml") == 0) {
        return 1;
    }

    if (strcmp(tag, "packet") == 0) {
        *pkt_status = *pkt_status + 1;
    }

    if (*pkt_status == pkt_no + 1) {
        return 1;
    }

    return 0;
}

static int close_explicit_packet(const char* tag, int pkt_no, int pkt_status) {
    if (pkt_no < 0) {
        return 1;
    }
    if (strcmp(tag, "pdml") == 0) {
        return 1;
    }
    if (pkt_status == pkt_no + 1) {
        return 1;
    }
    return 0;
}

field_t* parse_pcap_file(const char* pcap_file_path, const char* wireshark_display_filter, int pkt_no)
{
    char final_cmd[1024];    
    if (NULL == get_final_cmd(pcap_file_path, wireshark_display_filter, final_cmd)) {
        return NULL;
    }
    
    FILE* std = popen(final_cmd, "r");
    int field_stack_index = 0;
    field_t* field_stack[STACK_DEEP];
    field_t* root = (field_t*)malloc(sizeof(field_t));
    memset(root, 0, sizeof(field_t));
    memset(field_stack, 0, sizeof(field_stack));
    field_stack[field_stack_index] = root;

    char buf[LINE_LEN];
    char mbuf[LINE_LEN];
    char tag[TAG_LEN];

    memset(tag, 0, sizeof(tag));
    memset(mbuf, 0, sizeof(mbuf));

    int pkt_status = 0;
    
    while(1) {
        const char* get = fgets(buf, sizeof(buf), std);
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
        if (!is_accept_tag(tag)) {
            continue;
        }

        if (is_open_tag(tag)) {        
            if (open_explicit_packet(tag, pkt_no, &pkt_status)) {
                field_t* parent = field_stack[field_stack_index];
                field_t* field = on_tag_open(tag, rbuf, parent);
                if (field && !is_xml_in_one_line(rbuf)) {
                    field_stack_index += 1;
                    field_stack[field_stack_index] = field;
                }
                printf("%s\n", rbuf);
            }
            // printf("OPEN [%s] index: [%d] \n", tag, field_stack_index);
            continue;
            
        }
        
        if (is_close_tag(tag)) {
            if (close_explicit_packet(tag, pkt_no, pkt_status)) {
                on_tag_close(field_stack[field_stack_index]);
                field_stack_index -= 1;
                printf("%s\n", rbuf);
            }
            // printf("CLOSE [%s] index: [%d] \n", tag, field_stack_index);
        }
    }
    
    fclose(std);

    return NULL;
}


static char* get_temp_file(int len) {
    char temp[1024];
    memset(temp, 0, sizeof(temp));

#ifdef _MSC_VER
    char dll_path[MAX_PATH];
    HMODULE hm = NULL;

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCSTR) &parse_pcap_file, &hm) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);
        return NULL;
    }
    if (GetModuleFileName(hm, dll_path, sizeof(path)) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleFileName failed, error = %d\n", ret);
        return NULL;
    }
    while(len--) {
        if(dll_path[len] == '\\') {
            dll_path[len] = '\0';
            break;
        }
        if(dll_path[len] == '/') {
            dll_path[len] = '\0';
            break;
        }
    }
    time_t t;
    sprintf(temp, "%s\\%d.pcap", dll_path, time(&t));
#endif

#ifdef __clang__
    time_t t;
    char cwd[1024];
    char* x = getcwd(cwd, sizeof(cwd));    
    sprintf(temp, "%s/%ld_%d.pcap",x, time(&t), len);
#endif

    return strdup(temp);
}

field_t* parse_pcap_data(const unsigned char* pcap_file_data, int len,
                         const char* wireshark_display_filter, int pkt_no) {

    char* temp_file_path = get_temp_file(len);
    FILE* f = fopen(temp_file_path, "wb");
    fwrite(pcap_file_data, len, 1, f);
    fclose(f);

    field_t* field = parse_pcap_file(temp_file_path, wireshark_display_filter, pkt_no);

    unlink(temp_file_path);
    free(temp_file_path);
    return field;
}
