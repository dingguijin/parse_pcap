#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parse_xml.h"

static const char* accept_tags[] = {"pdml", "packet", "proto", "field"};

#if defined(_MSC_VER)
static char* get_dll_dir(char* path) {
    char dll_path[_MAX_PATH_LEN];
    HMODULE hm = NULL;

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCSTR) &parse_pcap_file, &hm) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);
        return NULL;
    }
    if (GetModuleFileName(hm, dll_path, sizeof(dll_path)) == 0) {
        int ret = GetLastError();
        fprintf(stderr, "GetModuleFileName failed, error = %d\n", ret);
        return NULL;
    }

    int len = strlen(dll_path);
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
    strcpy(path, dll_path);
    //printf("dll path %s\n", dll_path);
    return path;
}
#endif

#if defined(__MINGW32__)
#include <QCoreApplication>
char* get_dll_dir(char* path) {
    QString app_dir = QCoreApplication::applicationDirPath();
    strcpy(path, app_dir.toStdString().c_str());
    return path;
}
#endif

static char* insert_cat_before_space(char* cmd) {
    char* temp = strdup(cmd);
    int len = strlen(temp);

    if (len == 0) {
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < len; i++) {
        if (temp[i] == ' ') {
            cmd[j++] = '"';
            cmd[j++] = ' ';
            cmd[j++] = '"';
            continue;
        }
        cmd[j++] = temp[i];
    }
    free(temp);
    return cmd;
}

char* get_psml_final_cmd(const char* file_path, char* final_cmd)
{
    char tshark_cmd[_MAX_PATH_LEN] = {0};
#if defined(_MSC_VER) || defined(__MINGW32__)
    char dll_path[_MAX_PATH_LEN] = {0};
    if(!get_dll_dir(dll_path)) {
    return NULL;
    }
    insert_cat_before_space(dll_path);
#ifdef __MINGW32__
    sprintf(tshark_cmd, "%s/tshark.exe", dll_path);
#else
    sprintf(tshark_cmd, "%s\\tshark.exe", dll_path);
#endif
#endif // _MSC_VER || __MINGW32__

#if defined(__clang__) && defined(__APPLE__)
    strcpy(tshark_cmd, "/Users/dingguijin/projects/wireshark/wireshark/build/run/Wireshark.app/Contents/MacOS/tshark");
#endif

    const char* cmd_args = "-T psml -Vn -r";
    sprintf(final_cmd, "%s %s %s", tshark_cmd, cmd_args, file_path);
    return final_cmd;
}

char* get_final_cmd(const char* file_path, const char* filter, char* final_cmd)
{
    char tshark_cmd[_MAX_PATH_LEN] = {0};
#if defined(_MSC_VER) || defined(__MINGW32__)
    char dll_path[_MAX_PATH_LEN] = {0};
    if(!get_dll_dir(dll_path)) {
    return NULL;
    }
    insert_cat_before_space(dll_path);
#ifdef __MINGW32__
    sprintf(tshark_cmd, "%s/tshark.exe", dll_path);
#else
    sprintf(tshark_cmd, "%s\\tshark.exe", dll_path);
#endif
#endif // _MSC_VER || __MINGW32__

#if defined(__clang__) && defined(__APPLE__)
    strcpy(tshark_cmd, "/Users/dingguijin/projects/wireshark/wireshark/build/run/Wireshark.app/Contents/MacOS/tshark");
#endif

    // const char* cmd_args = "-Y \"tcp.flags.syn==1 && tcp.flags.ack==1\" -T pdml -V -n -r";
    char wireshark_filter[_MAX_PATH_LEN] = {0};
    const char* cmd_args = "-T pdml -Vn -r";
    if (filter != NULL) {
        sprintf(wireshark_filter, "-Y \"%s\"", filter);
    }
    sprintf(final_cmd, "%s %s %s %s", tshark_cmd, wireshark_filter, cmd_args, file_path);
    //fprintf(stderr, "final: [%s]", final_cmd);
    return final_cmd;
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
