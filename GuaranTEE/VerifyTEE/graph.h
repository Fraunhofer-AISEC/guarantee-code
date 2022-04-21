/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  graph.h
 *
 *  All Rights Reserved.
 */

#ifndef GRAPH_H
#define GRAPH_H

#include <stdint.h>

typedef struct node node_t;
typedef struct children children_t;

struct node {
    uint64_t id;
    uint64_t visited;
    children_t *children;
};

struct children {
    uint64_t nr_children;
    node_t *child[];
};

#ifdef __cplusplus
extern "C" {
#endif

node_t *new_node(uint64_t id);
node_t *add_child(node_t *node, node_t *child_node);
node_t *get_child(node_t *node, uint64_t child_id);
node_t *find_node(node_t *node, uint64_t id);
void print_dot_graph(node_t *node, int fd);

#ifdef __cplusplus
}
#endif

#endif /* GRAPH_H */
