/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  Analyzer.cpp
 *
 *  Implements the analyzer which constructs and checks the CFG.
 *
 *  All Rights Reserved.
 */

#include "Analyzer.h"
#include "sgx_thread.h"
#include <map>
#include <queue>
#include "graph.h"
#include "log.h"
#include "queue.h"

volatile int kill_analyzer = 0;

void expand_graph(uint64_t identifier);
void check_graph(uint64_t identifier);

node_t *graph = new_node(START_CFA_CODE);
node_t *current_node = NULL;

log_t *current_log = NULL;
void (*handle_id)(uint64_t) = &expand_graph;

/*
 * Function expand_graph:
 *      Builds the graph from the incoming IDs in the learning phase
 *
 *      Parameters:
 *          identifier: ID which should be learned
 */
void expand_graph(uint64_t identifier)
{
    node_t *child;
    static uint64_t valid_paths = 0;
    static uint64_t learning_completed = 0;

    // Start of request
    if (identifier == START_CFA_CODE) {
        // If all learning requests are processed, switch to verify mode
        if (valid_paths >= NR_LEARNING_REQUESTS) {
            /* Set function pointer to check_graph which verifies the incoming
               IDs against the graph */
            handle_id = &check_graph;
            sgx_printf("End of learning phase. Starting to verify the requests.\n");
            check_graph(identifier);
            return;
        }

        learning_completed = 1;
        valid_paths++;
        current_node = graph;
        return;
    }

    if (!learning_completed) {
        return;
    }

    // End of learning phase
    if (identifier == END_CFA_CODE) {
        learning_completed = 0;
    }

    child = get_child(current_node, identifier);

    if (child) {
        /* ID node is a successor of the current node:
            Move forward in the graph */
        current_node = child;
    } else {
        // ID node is not a successor of the current node
        child = find_node(graph, identifier);
        if (child) {
            /* ID node exists in graph:
                Add ID node as successor of current node */
            if (!add_child(current_node, child)) {
                sgx_printf("An error occurred\n");
            }
            current_node = child;
        } else {
            /* ID node does not exist in graph:
                Create node and add new node as successor of current node */
            child = new_node(identifier);
            if (!child)
                sgx_printf("Out of memory\n");

            current_node = add_child(current_node, child);
            if (!current_node)
                sgx_printf("Out of memory\n");

            current_node = child;
        }
    }
}

/*
 * Function check_graph:
 *      Checks the incoming IDs against the graph build in the learning phase
 *
 *      Parameters:
 *          identifier: ID which should be checked
 */
void check_graph(uint64_t identifier)
{
    node_t *child;
    static uint64_t cfa_active = 0;

    if (cfa_active) {
        if (identifier == END_CFA_CODE)
            cfa_active = 0;

        child = get_child(current_node, identifier);

        if (child)
            current_node = child;
        else
            set_malicious(current_log);

    } else if (identifier == START_CFA_CODE) {
        time_t curr_time = untrusted_time(NULL);
        current_log = create_log(curr_time);
        if (current_log == NULL) {
            sgx_printf("Failed to create a log entry.\n");
            sgx_exit(LOG_ERROR);
        }
        current_node = graph;
        cfa_active = 1;
    }
}

/*
 * Function ecall_print_graph:
 *      Prints the graph to given file descriptor. Must not be called if the
 *      graph is modified concurrently.
 *
 *      Parameters:
 *          fd: File descriptor on which the graph should be printed
 */
extern "C" void ecall_print_graph(int fd)
{
    print_dot_graph(graph, fd);
}

/*
 * Function ecall_print_log:
 *      Prints the attestation log to given file descriptor. Must not be called
 *      if the graph is modified concurrently.
 *
 *      Parameters:
 *          fd: File descriptor on which the log should be printed
 */
extern "C" void ecall_print_log(int fd)
{
    print_log(fd);
}

/*
 * Function ecall_kill_analyzer_thread:
 *      Sets the kill_analyzer flag for the analyzer thread
 */
extern "C" void ecall_kill_analyzer_thread()
{
    __atomic_fetch_add(&kill_analyzer, 1, __ATOMIC_SEQ_CST);
}

/*
 * Function ecall_start_analyzer_thread:
 *      Main entry point for the analyzer thread which manages the learning
 *      phase and the verification phase. The thread pulls the IDs out of the
 *      queue and processes them accordingly.
 */
extern "C" void ecall_start_analyzer_thread()
{
    int available = 0;
    uint64_t id;

    sgx_printf("Start analyzer thread\n");

    while (1) {

        if (__atomic_fetch_add(&kill_analyzer, 0, __ATOMIC_SEQ_CST)) {
            break;
        }

        available = get_id(&id);

        switch (available) {
            case 0: {
                break;
            }
            case 1: {
                if (id != 0) {
                    (*handle_id)(id);
                }
                break;
            }
            default: {
                sgx_printf("Failed to dequeue one element.\n");
                sgx_exit(QUEUE_ERROR);
                break;
            }
        }
    }
}
