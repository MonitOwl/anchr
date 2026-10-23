#ifndef ANCHR_CONTAINER_H
#define ANCHR_CONTAINER_H

#include "anchr_common.h"

/* External declarations for container list state */
extern struct list_head container_list;
extern spinlock_t container_list_lock;
extern atomic_t container_count;

/* Container management functions */
int anchr_container_init(void);
void anchr_container_cleanup(void);
struct container_node *find_container_by_id(const char *container_id);
struct container_node *find_container_by_id_rcu(const char *container_id);
struct container_node *anchr_get_container(struct container_node *container);
void anchr_put_container(struct container_node *container);
struct container_node *create_container_node(const char *container_id);
void cleanup_container_measurements(struct container_node *container);
void cleanup_all_containers(void);

/* Measurement functions */
int add_container_measurement(struct container_node *container,
                              const char *event_name,
                              const char *event_data,
                              const char *dependencies,
                              const u8 *digest,
                              gfp_t flags);

#endif /* ANCHR_CONTAINER_H */
