/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  graph.c
 *
 *  Implements the graph representing the CFG.
 *
 *  All Rights Reserved.
 */

#include "graph.h"
#include <stdlib.h>
#include <string.h>
#include "ocall_wrappers.h"

/*
 * Function: new_node
 *      Creates a new node with given ID
 *
 *      Parameters:
 *          id: Id of the new node
 *
 *      Return value:
 *          Pointer to new node (NULL in case of error)
 */
node_t *new_node(uint64_t id)
{
    node_t *node = (node_t*)malloc(sizeof(node_t));

    if (!node) {
        return NULL;
    }
    node->id = id;
    node->visited = 0;
    node->children = NULL;

    return node;
}

/*
 * Function: add_child
 *      Adds the child node as direct successor to the given node
 *
 *      Parameters:
 *          node: Pointer to the predecessor
 *          child_node: Pointer to the successor
 *
 *      Return value:
 *          Pointer to the original node (NULL in case of error)
 */
node_t *add_child(node_t *node, node_t *child_node)
{
    uint64_t nr_children;
    children_t *new_children;

    if (!node) {
        return NULL;
    }

    if (node->children == NULL) {
        nr_children = 0;
    } else {
        nr_children = node->children->nr_children;
    }

    new_children =
            malloc((nr_children + 1) * sizeof(node_t*) + sizeof(children_t));
    if (new_children == NULL)
        return NULL;

    if (nr_children != 0) {
        for (uint64_t i = 0; i < nr_children; i++) {
            new_children->child[i] = node->children->child[i];
        }
    }

    new_children->nr_children = nr_children + 1;
    new_children->child[nr_children] = child_node;

    free(node->children);
    node->children = new_children;

    return node;
}

/*
 * Function: get_child
 *      Returns the node with the given child ID if it is a direct successor
 *      of node
 *
 *      Parameters:
 *          node: Pointer to the root node
 *          child_id: ID of the child which should be returned
 *
 *      Return value:
 *          Pointer to the child node or NULL if child node not found
 */
node_t *get_child(node_t *node, uint64_t child_id)
{
    if (!node) {
        return NULL;
    }

    if (node->children == NULL) {
        return NULL;
    }

    for (uint64_t i = 0; i < node->children->nr_children; i++) {
        if (node->children->child[i]->id == child_id) {
            return node->children->child[i];
        }
    }

    return NULL;
}

/*
 * Function: clear_visited
 *      Clears the visited flag for each node reachable from the given node
 *
 *      Parameters:
 *          node: Pointer to the root node
 */
void clear_visited(node_t *node)
{
    if (!node) {
        return;
    }

    node->visited = 0;

    if (node->children == NULL) {
        return;
    }

    for (uint64_t i = 0; i < node->children->nr_children; i++) {
        node_t *child = node->children->child[i];

        if (child->visited != 0) {
            clear_visited(child);
        }
    }
}

/*
 * Function: find_node_rec
 *      Parameters:
 *          node: Pointer to the root node
 *          id: ID of the node which is searched for
 *
 *      Return value:
 *          Pointer to the found node or NULL if node not found
 */
node_t *find_node_rec(node_t *node, uint64_t id)
{
    if (!node) {
        return NULL;
    }

    node->visited = 1;

    if (node->id == id) {
        return node;
    }

    if (node->children == NULL) {
        return NULL;
    }

    for (uint64_t i = 0; i < node->children->nr_children; i++) {
        node_t *child = node->children->child[i];

        if (child->visited) {
            continue;
        }

        node_t *found = find_node_rec(child, id);

        if (found != NULL) {
            return found;
        }
    }

    return NULL;
}

/*
 * Function: find_node
 *      Finds a node with given ID in the subgraph of the given node
 *
 *      Parameters:
 *          node: Pointer to the root node
 *          id: ID of the node which is searched for
 *
 *      Return value:
 *          Pointer to the found node or NULL if node not found
 */
node_t *find_node(node_t *node, uint64_t id)
{
    node_t *result;

    result = find_node_rec(node, id);
    clear_visited(node);

    return result;
}

/*
 * Function: to_dot_graph_rec
 *      Parameters:
 *          node: Pointer to the root node
 *          fd: File descriptor for output
 */
void print_dot_graph_rec(node_t *node, int fd)
{
    node->visited = 1;

    if (node->children == NULL) {
        return;
    }

    for (uint64_t i = 0; i < node->children->nr_children; i++) {
        node_t *child = node->children->child[i];

        sgx_dprintf(fd, "_%p [shape=record label=\"{%p|ID=0x%016lx}\"];\n",
                    child, child, child->id);
        sgx_dprintf(fd, "_%p -> _%p;\n", node, child);

        if (child->visited == 0) {
            print_dot_graph_rec(child, fd);
        }
    }
}

/*
 * Function: to_dot_graph
 *      Prints the DOT representation of the graph to the given file descriptor
 *
 *      Parameters:
 *          node: Pointer to the root node
 *          fd: File descriptor for output
 */
void print_dot_graph(node_t *node, int fd)
{
    sgx_dprintf(fd, "digraph validcfg\n{\n");

    if (node) {
        sgx_dprintf(fd, "_%p [shape=record label=\"{%p|ID=0x%016lx}\"];\n",
                    node, node, node->id);
        print_dot_graph_rec(node, fd);
    }

    sgx_dprintf(fd, "}\n");
    clear_visited(node);
}
