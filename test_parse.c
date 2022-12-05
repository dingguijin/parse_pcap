#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse_pcap.h"

#define TAG_LEN 64
#define LINE_LEN 1024*256
#define STACK_DEEP 16

static const char* accept_tags[] = {"pdml", "packet", "proto", "field"};

static char* get_final_cmd(const char* file_path, char* final_cmd)
{
    const char* cmd = "/Users/dingguijin/projects/wireshark/wireshark/build/run/Wireshark.app/Contents/MacOS/tshark";
    // const char* cmd_args = "-Y \"tcp.flags.syn==1 && tcp.flags.ack==1\" -T pdml -V -n -r";
    const char* cmd_args = "-T pdml -Vn -r";
    sprintf(final_cmd, "%s %s %s", cmd, cmd_args, file_path);
    return final_cmd;
}

static int is_accept_tag(const char* tag) {
    if (tag[0] == '?') {
        return 0;
    }
    if (tag[0] == '!') {
        return 0;
    }
    if (tag[0] == '/') {
        tag = &tag[1];
    }

    int tags_len = sizeof(accept_tags)/sizeof(accept_tags[0]);
    for (int i = 0; i < tags_len; i++) {
        if (strcmp(accept_tags[i], tag) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_open_tag(const char* tag) {
    if (tag[0] == '/') {
        return 0;
    }
    return 1;
}

static int is_close_tag(const char* tag) {
    if (tag[0] == '/') {
        return 1;
    }
    return 0;
}

static int is_general_space(char c) {
    if (c == ' ' ||
        c == '\0' ||
        c == '\n' ||
        c == '\r' ||
        c == '\t') {
        return 1;
    }
    return 0;
}

static char* remove_spaces(char* line) {
    char* new_line = strdup(line);
    int len = strlen(new_line);
    int i = 0;
    
    for (i = 0; i < len; i++) {
        if (is_general_space(new_line[i])) {
            continue;
        } else {
            break;
        }
    }
    strcpy(line, &new_line[i]);
    free(new_line);

    len = strlen(line);
    for (i = len; i > 0; i--) {
        if (is_general_space(line[i])) {
            line[i] = '\0';
            continue;
        } else {
            break;
        }
    }
    return line;
}

static int need_next_line(const char* line) {
    int len = strlen(line);
    if (line[len-1] != '>') {
        return 1;
    }
    return 0;
}

static int is_xml_in_one_line(const char* line) {
    if (0 == strcmp(&line[strlen(line) - 2], "/>")) {
        return 1;
    }
    return 0;
}

static int get_tag(const char* line, char* tag) {
    int tag_status = 0;
    int j = 0;
    
    if (line == NULL) {
        return 0;
    }
    
    unsigned long len = strlen(line);
    if (len == 0) {
        return 0;
    }
    
    for (unsigned long i = 0; i < len; i++) {
        if (tag_status == 0) {
            if (line[i] == '<') {
                tag_status = 1;
                continue;
            }
        }
        if (tag_status == 1) {
            if (line[i] == '>' ||
                line[i] == ' ') {
                return 1;
            } else {
                tag[j++] = line[i];
                continue;
            }
        }
    }
    return 0;
}

typedef struct attr_pair {
    char* attr_name;
    char* attr_value;
    struct attr_pair* next;
} attr_pair_t;

attr_pair_t* get_attr_pair(char* line) {
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

void parse_pdml(attr_pair_t* attr_pair_list, field_data_t* field) {
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

void parse_packet(attr_pair_t* attr_pair_list, field_data_t* field) {
}

void parse_proto(attr_pair_t* attr_pair_list, field_data_t* field) {
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

void parse_field(attr_pair_t* attr_pair_list, field_data_t* field) {
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

void parse_line(const char* tag, char* line, field_data_t* field) {
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

field_t* on_tag_open(const char* tag, char* buf, field_t* parent) {
    
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

void on_tag_close(field_t* parent) {
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

int main(int argc, char** argv) {
    char *pcap_file = "~/send_to_me.pcap";
    char final_cmd[1024];
    
    get_final_cmd(pcap_file, final_cmd);
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

        printf("rbuf [%s]\n", rbuf);
        if (is_open_tag(tag)) {
            field_t* parent = field_stack[field_stack_index];
            field_t* field = on_tag_open(tag, rbuf, parent);
            if (field && !is_xml_in_one_line(rbuf)) {
                field_stack_index += 1;
                field_stack[field_stack_index] = field;
            }
            // printf("OPEN [%s] index: [%d] \n", tag, field_stack_index);
            continue;
        }
        
        if (is_close_tag(tag)) {
            on_tag_close(field_stack[field_stack_index]);
            field_stack_index -= 1;
            // printf("CLOSE [%s] index: [%d] \n", tag, field_stack_index);
        }
    }
    
    fclose(std);
    return 0;
}
