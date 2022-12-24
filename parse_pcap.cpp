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
#if defined (__GNUC__)
#include <unistd.h>
#endif

#include "parse_pcap.h"
#include "parse_xml.h"

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
    return;
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
        if (strcmp(current->attr_name, "show") == 0) {
            field->show = current->attr_value;
        }
        if (strcmp(current->attr_name, "hide") == 0) {
            field->hide = current->attr_value;
        }
        free(current->attr_name);
        attr_pair_t* to_free = current;
        current = current->next;
        free(to_free);
    }
}

static void parse_line(const char* tag, char* line, field_data_t* field) {
    attr_pair_t* head = get_attr_pair(line);
    if (!head) {
        return;
    }
    if (strcmp(tag, "pdml") == 0) {
        parse_pdml(head, field);
	return;
    }
    if (strcmp(tag, "packet") == 0) {
        parse_packet(head, field);
	return;
    }
    if (strcmp(tag, "proto") == 0) {
        parse_proto(head, field);
	return;
    }
    if (strcmp(tag, "field") == 0) {
        parse_field(head, field);
	return;
    }
    // printf("unknown tag [%s] \n", tag);
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

static int break_explicit_packet(const char* tag, int pkt_no) {
    if (pkt_no < 0) {
        return 0;
    }
    if (strcmp(tag, "/packet") == 0) {
        return 1;
    }
    return 0;
}

field_t* parse_pcap_file(const char* pcap_file_path, const char* wireshark_display_filter, int pkt_no)
{
    if (!pcap_file_path) {
        return NULL;
    }
    if (strlen(pcap_file_path) == 0) {
        return NULL;
    }
    char final_cmd[_MAX_PATH_LEN];
    memset(final_cmd, 0, sizeof(final_cmd));
    if (NULL == get_final_cmd(pcap_file_path, wireshark_display_filter, final_cmd)) {
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

    int stack_healthy = 0;
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
        if (!is_accept_tag(tag)) {
            continue;
        }

        if (is_open_tag(tag)) {        
            if (open_explicit_packet(tag, pkt_no, &pkt_status)) {
                field_t* parent = field_stack[field_stack_index];
                field_t* field = on_tag_open(tag, rbuf, parent);
                if (field && !is_xml_in_one_line(rbuf)) {
                    if (field_stack_index + 1 < STACK_DEEP) {
                        field_stack_index += 1;
                        field_stack[field_stack_index] = field;
                    } else {
                        stack_healthy++;
                    }
                }
                //printf("%s\n", rbuf);
            }
            // printf("OPEN [%s] index: [%d] \n", tag, field_stack_index);
            continue;
            
        }
        
        if (is_close_tag(tag)) {
            if (close_explicit_packet(tag, pkt_no, pkt_status)) {
                on_tag_close(field_stack[field_stack_index]);
                if (stack_healthy > 0) {
                    stack_healthy--;
                } else {
                    field_stack_index -= 1;
                }
                if (break_explicit_packet(tag, pkt_no)) {
                    on_tag_close(field_stack[0]);
                    break;
                }
                //printf("%s\n", rbuf);
            }
            // printf("CLOSE [%s] index: [%d] \n", tag, field_stack_index);
        }
    }

    fclose(_std);
    if (root->array_size == 0) {
	    free(root);
	    return NULL;
    }
    return root;
}


static char* get_temp_file(int len) {
    char temp[_MAX_PATH_LEN];
    memset(temp, 0, sizeof(temp));
    time_t t;

#if defined(_MSC_VER) || defined(__MINGW32__)
    char dll_path[_MAX_PATH_LEN];
    if (!get_dll_dir(dll_path)) {
	    return NULL;
    }
    sprintf(temp, "%s/%ld_%d.pcap", dll_path, (long)time(&t), len);
#endif

#if defined(__clang__) && defined(__APPLE__)
    char cwd[_MAX_PATH_LEN];
    char* x = getcwd(cwd, sizeof(cwd));    
    sprintf(temp, "%s/%ld_%d.pcap", x, time(&t), len);
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

void free_field_data(field_data_t* field_data) {
    if (!field_data) {
        return;
    }

    //    qDebug() << "name: " << field_data->name << ", showname: " << field_data->showname << ", value: " << field_data->value << ", unmaskedvalue: " << field_data->unmaskedvalue;
    free(field_data->name);
    free(field_data->show);
    free(field_data->showname);
    free(field_data->unmaskedvalue);
    free(field_data->value);

    return;
}

void recursive_free_field(field_t* field) {
    if(field->array_size == 0) {
//        qDebug() << field->tag << ", size: " << field->array_size;
        free_field_data(field->field);
        free(field->field);
        free(field);
        return;
    } else {
        for (int i = 0; i < field->array_size; i++) {
            recursive_free_field(field->array[i]);
        }
        free(field->tag);
        free(field->array);
        free_field_data(field->field);
        free(field);
    }
    return;
}
