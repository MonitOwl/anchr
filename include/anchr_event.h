#ifndef ANCHR_EVENT_H
#define ANCHR_EVENT_H

#define MAX_EVENT_NAME_LEN 64
#define MAX_FILE_PATH_LEN 256
#define MAX_CONTAINER_ID_LEN 128
#define EVENT_HASH_SIZE 32

struct anchr_event {
    char event_name[MAX_EVENT_NAME_LEN];
    char file_path[MAX_FILE_PATH_LEN];
    char container_id[MAX_CONTAINER_ID_LEN];
    char dependencies[256];
    unsigned char hash[EVENT_HASH_SIZE];
};

#endif /* ANCHR_EVENT_H */
