#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char* accept_tags[] = {"pdml", "packet", "proto", "field"};

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

int is_accept_tag(const char* tag) {
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

int is_open_tag(const char* tag) {
    if (tag[0] == '/') {
        return 0;
    }
    return 1;
}

int is_close_tag(const char* tag) {
    if (tag[0] == '/') {
        return 1;
    }
    return 0;
}

int need_next_line(const char* line) {
    int len = strlen(line);
    if (line[len-1] != '>') {
        return 1;
    }
    return 0;
}

int is_xml_in_one_line(const char* line) {
    if (0 == strcmp(&line[strlen(line) - 2], "/>")) {
        return 1;
    }
    return 0;
}

char* remove_spaces(char* line) {
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

char* escape_xml_string(char* str) {
    if (str == NULL) {
        return NULL;
    }
    if (strlen(str) == 0) {
        return NULL;
    }
    
    int j = 0, k = 0;
    char token[8];
    memset(token, 0, sizeof(token));
    
    char *temp = strdup(str);
    int len = strlen(str);
    int status = 0;
    for (int i = 0; i < len; i++) {
        str[k++] = temp[i];
        str[k] = '\0';
        
        if (status == 0) {
            if (temp[i] == '&') {
                status = 1;
            }
            continue;
        }

        if (status == 1) {
            if (temp[i] == '#') {
                status = 2;
            } else {
                status = 0;
            }
            continue;
        }

        if (status == 2) {
            if (temp[i] == 'x') {
                status = 3;
            } else {
                status = 0;
            }
            continue;
        }

        if (status == 3) {
            if (temp[i] != ';') {
                token[j++] = temp[i];
            } else { // == ';'
                k = k - strlen("&#x") - j - 1;
                str[k++] = (char)strtol(token, (char**)NULL, 16);
                str[k] = '\0';
                status = 0;
            }
            continue;
        }
    }
    free(temp);
    return str;
}

int get_tag(const char* line, char* tag) {
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
