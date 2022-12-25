#ifndef __PARSE_XML_H__
#define __PARSE_XML_H__

#define TAG_LEN 64
#define LINE_LEN 1024*256
#define STACK_DEEP 128
#define _MAX_PATH_LEN 4096

extern char* get_dll_dir(char*);
extern char* get_final_cmd(const char*, const char*, char*);
extern char* get_psml_final_cmd(const char*, char*);
extern char* remove_spaces(char*);
extern int get_tag(const char*, char*);
extern char* escape_xml_string(char*);
extern int is_xml_in_one_line(const char*);
extern int is_open_tag(const char* tag);
extern int is_close_tag(const char* tag);
extern int need_next_line(const char* line);
extern int is_accept_tag(const char* tag);

#endif // __PARSE_XML_H__
