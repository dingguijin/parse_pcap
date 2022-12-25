#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <windows.h>
#include <qdebug.h>
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
    char* attr_name = (char*)malloc(LINE_LEN);
    char* attr_value = (char*)malloc(LINE_LEN);
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
    free(attr_name);
    free(attr_value);
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
    }

    if (!parent->head) {
        parent->head = field;
    }

    parent->current = field;
    parent->array_size++;
    return field;
}

static void on_tag_close(field_t* parent) {
    if (!parent->array_size) {
        return;
    }
    field_t* head = parent->head;
    field_t* current = head;
    int i = 0;
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

char* read_cmd_file(FILE* _std, char** _buf, int* _size) {
    char *buf = (char*) malloc(LINE_LEN);
    char *total_buf = NULL;
    int total_size = 0;
    *_size = 0;
    *_buf = NULL;

    while(1) {
        memset(buf, 0, LINE_LEN);
        size_t r = fread(buf, 1, LINE_LEN, _std);
        if (r == 0) {
            break;
        }
        char* tmp = (char* )malloc(total_size + r);
        if (total_size && total_buf) {
            memcpy(tmp, total_buf, total_size);
            memcpy(&tmp[total_size], buf, r);
            total_size += r;
            free(total_buf);
            total_buf = tmp;
        } else {
            total_buf = tmp;
            memcpy(tmp, buf, r);
            total_size = r;
        }

        //qDebug() <<"[" << total_size << "]" << "[" << total_buf[total_size-1] <<"]";
    }
    free(buf);
    *_buf = total_buf;
    *_size = total_size;
    return total_buf;
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
    
#if defined(_MSC_VER) || defined(__MINGW32__)
    AllocConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    FILE* _std = popen(final_cmd, "rb");
#endif

    char* total_buf = NULL;
    int total_size = 0;
    total_buf = read_cmd_file(_std, &total_buf, &total_size);
    fclose(_std);
    if (total_size == 0) {
        return NULL;
    }

    int stack_healthy = 0;
    int field_stack_index = 0;
    field_t* field_stack[STACK_DEEP];
    field_t* root = (field_t*)malloc(sizeof(field_t));
    memset(root, 0, sizeof(field_t));
    memset(field_stack, 0, sizeof(field_stack));

    field_stack[field_stack_index] = root;
    char tag[TAG_LEN];
    int pkt_status = 0;

    total_buf[total_size-1] = '\0';
    char* tofree = strdup(total_buf);
    char* token = NULL;


    int j = 0;
    int new_line = 0;
    char* mbuf = (char*)malloc(LINE_LEN*16);
    memset(mbuf, 0, LINE_LEN*16);
    for(token = strtok(total_buf, "\n"); token; token=strtok(NULL, "\n")) {
        j++;
        if (strlen(token) == 0) {
            continue;
        }
        char* buf = remove_spaces(token);
        if (strlen(buf) == 0) {
            free(buf);
            continue;
        }
        
        if (need_next_line(buf)) {
            buf[strlen(buf) - 1] = '\0';
            strcat(mbuf, buf);
            new_line = 1;
            free(buf);
            continue;
        } else {
            if (new_line == 1) {
                new_line = 0;
                strcat(mbuf, buf);
            } else {
                strcpy(mbuf, buf);
            }
            free(buf);
        }
        // qDebug() << "[" << mbuf << "]";

        memset(tag, 0, TAG_LEN);
        get_tag(mbuf, tag);
        if (!is_accept_tag(tag)) {
            continue;
        }
        // qDebug() << "[" << tag << "]" << "[" << j++ << "]";

        if (is_open_tag(tag)) {
            if (open_explicit_packet(tag, pkt_no, &pkt_status)) {
                field_t* parent = field_stack[field_stack_index];
                field_t* field = on_tag_open(tag, mbuf, parent);
                if (field && !is_xml_in_one_line(mbuf)) {
                    if (field_stack_index + 1 < STACK_DEEP) {
                        field_stack_index += 1;
                        field_stack[field_stack_index] = field;
                    } else {
                        stack_healthy++;
                    }
                }
            }
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
            }
        }

        //printf("tag: [%s], stack_field_index = [%d], stack_healthy = [%d]\n", tag, field_stack_index, stack_healthy);
        memset(mbuf, 0, LINE_LEN*16);
    }
    qDebug() << "EOF [" << j << "]";

    free(mbuf);
    free(tofree);

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
