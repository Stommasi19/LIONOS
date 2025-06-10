#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <lions/firewall/common.h>
#include <lions/firewall/queue.h>
#include <stdlib.h>

/* Routing internal errors */
typedef enum
{
    ROUTING_ERR_OKAY = 0,      /* No error */
    ROUTING_ERR_FULL,          /* Data structure is full */
    ROUTING_ERR_DUPLICATE,     /* Duplicate entry exists */
    ROUTING_ERR_CLASH,         /* Entry clashes with existing entry */
    ROUTING_ERR_INVALID_CHILD, /* Child node IP does not match parent node IP */
    ROUTING_ERR_INVALID_ID     /* Node does not exist */
} fw_routing_err_t;

static const char *fw_routing_err_str[] = {
    "Ok.",
    "Out of memory error.",
    "Duplicate entry.",
    "Clashing entry.",
    "Invalid child node.",
    "Invalid rule ID."};

/* Routing interfaces */
typedef enum
{
    ROUTING_OUT_EXTERNAL = 0, /* transmit out NIC */
    ROUTING_OUT_INTERNAL      /* transmit within the system */
} fw_routing_out_interfaces_t;

/* PP call parameters for webserver to call routers */
#define FW_ADD_ROUTE 0
#define FW_DEL_ROUTE 1

typedef enum
{
    ROUTER_ARG_ROUTE_ID = 0,
    ROUTER_ARG_IP,
    ROUTER_ARG_SUBNET,
    ROUTER_ARG_NEXT_HOP,
    ROUTER_ARG_NUM_HOPS
} fw_router_args_t;

typedef enum
{
    ROUTER_RET_ERR = 0,
    ROUTER_RET_ROUTE_ID = 1
} fw_router_ret_args_t;

typedef struct routing_entry_node
{
    bool in_use;                               /* If this node is currently in use */
    uint16_t route_id;                         /* Unique route identifier */
    fw_routing_out_interfaces_t out_interface; /* queue subnet traffic should be transmitted through */
    uint16_t num_hops;                         /* minimum number of hops to destination */
    uint32_t ip;                               /* ip address of subnet */
    uint8_t subnet;                            /* number of bits in subnet mask */
    uint32_t next_hop;                         /* ip addr of next hop */
    struct routing_entry_node *prev;           /* pointer to previous node */
    struct routing_entry_node *next;           /* pointer to next node */
} routing_entry_node_t;

typedef struct fw_routing_list
{
    routing_entry_node_t *nodes; /* Array of preallocated nodes */
    routing_entry_node_t *head;  /* Pointer to head node */
    routing_entry_node_t *tail;  /* Pointer to tail node */
    uint16_t next_id;            /*Next unique ID to assign*/
    fw_routing_out_interfaces_t default_out_interface;
    uint16_t capacity; /* max size of list*/
    uint16_t size;     /*current size of list*/
} fw_routing_list_t;

/* Node to track packets awaiting ARP requests */
typedef struct pkt_waiting_node
{
    uint16_t next_ip;
    uint16_t prev_ip;
    uint16_t next_child;
    uint16_t num_children;
    uint32_t ip;
    fw_buff_desc_t buffer;
} pkt_waiting_node_t;

typedef struct pkts_waiting
{
    pkt_waiting_node_t *packets;
    uint16_t capacity;
    uint16_t size;   /* number of nodes in use */
    uint16_t length; /* number of parent nodes */
    uint16_t waiting_head;
    uint16_t waiting_tail;
    uint16_t free_head;
} pkts_waiting_t;

/* Initialise packet waiting structure */
void pkt_waiting_init(pkts_waiting_t *pkts_waiting, void *packets, uint16_t capacity)
{
    pkts_waiting->packets = (pkt_waiting_node_t *)packets;
    pkts_waiting->capacity = capacity;
    for (uint16_t i = 0; i < pkts_waiting->capacity; i++)
    {
        pkt_waiting_node_t *node = pkts_waiting->packets + i;
        /* Free list only maintains next pointers */
        node->next_ip = i + 1;
    }
}

/* Check if the packet waiting queue is full */
bool pkt_waiting_full(pkts_waiting_t *pkts_waiting)
{
    return pkts_waiting->size == pkts_waiting->capacity;
}

/* Find matching ip packet waiting node in packet waiting list */
pkt_waiting_node_t *pkt_waiting_find_node(pkts_waiting_t *pkts_waiting, uint32_t ip)
{
    pkt_waiting_node_t *node = pkts_waiting->packets + pkts_waiting->waiting_head;
    for (uint16_t i = 0; i < pkts_waiting->length; i++)
    {
        if (node->ip == ip)
        {
            return node;
        }
        node = pkts_waiting->packets + node->next_ip;
    }

    return NULL;
}

/* Return the next child node */
pkt_waiting_node_t *pkts_waiting_next_child(pkts_waiting_t *pkts_waiting, pkt_waiting_node_t *node)
{
    return pkts_waiting->packets + node->next_child;
}

/* Add a child node to a parent waiting node */
fw_routing_err_t pkt_waiting_push_child(pkts_waiting_t *pkts_waiting, pkt_waiting_node_t *parent, uint32_t ip, fw_buff_desc_t buffer)
{
    if (pkt_waiting_full(pkts_waiting))
    {
        return ROUTING_ERR_FULL;
    }

    if (parent->ip != ip)
    {
        return ROUTING_ERR_INVALID_CHILD;
    }

    uint16_t new_idx = pkts_waiting->free_head;
    pkt_waiting_node_t *new_node = pkts_waiting->packets + new_idx;

    /* Update values */
    new_node->ip = ip;
    new_node->buffer = buffer;
    new_node->num_children = 0;

    /* Update pointers */
    pkts_waiting->free_head = new_node->next_ip;
    pkt_waiting_node_t *last_child = parent;
    for (uint16_t i = 0; i < parent->num_children; i++)
    {
        last_child = pkts_waiting_next_child(pkts_waiting, last_child);
    }
    last_child->next_child = new_idx;

    /* Update counts */
    parent->num_children++;
    pkts_waiting->size++;

    return ROUTING_ERR_OKAY;
}

/* Add a node to IP packet list */
fw_routing_err_t pkt_waiting_push(pkts_waiting_t *pkts_waiting, uint32_t ip, fw_buff_desc_t buffer)
{
    if (pkt_waiting_full(pkts_waiting))
    {
        return ROUTING_ERR_FULL;
    }

    if (pkt_waiting_find_node(pkts_waiting, ip) != NULL)
    {
        return ROUTING_ERR_DUPLICATE;
    }

    uint16_t new_idx = pkts_waiting->free_head;
    pkt_waiting_node_t *new_node = pkts_waiting->packets + new_idx;

    /* Update values */
    new_node->ip = ip;
    new_node->buffer = buffer;
    new_node->num_children = 0;

    /* Update pointers */
    pkts_waiting->free_head = new_node->next_ip;
    /* If this is not the first node */
    if (pkts_waiting->length)
    {
        uint16_t head_idx = pkts_waiting->waiting_head;
        pkt_waiting_node_t *head_node = pkts_waiting->packets + head_idx;

        new_node->next_ip = head_idx;
        head_node->prev_ip = new_idx;
    }
    else
    {
        pkts_waiting->waiting_tail = new_idx;
    }
    pkts_waiting->waiting_head = new_idx;

    /* Update counts */
    pkts_waiting->length++;
    pkts_waiting->size++;

    return ROUTING_ERR_OKAY;
}

/* Free a node and all child nodes. Must pass a parent node. */
fw_routing_err_t pkts_waiting_free_parent(pkts_waiting_t *pkts_waiting, pkt_waiting_node_t *parent)
{
    /* First free children */
    uint16_t child_idx = parent->next_child;
    pkt_waiting_node_t *child = pkts_waiting_next_child(pkts_waiting, parent);
    for (uint16_t i = 0; i < parent->num_children; i++)
    {

        /* Add to free list */
        child->next_ip = pkts_waiting->free_head;
        pkts_waiting->free_head = child_idx;
        pkts_waiting->size--;

        /* Possibly free next child */
        child_idx = child->next_child;
        child = pkts_waiting_next_child(pkts_waiting, child);
    }

    /* Now free parent */
    pkt_waiting_node_t *prev_node = pkts_waiting->packets + parent->prev_ip;
    pkt_waiting_node_t *next_node = pkts_waiting->packets + parent->next_ip;

    /* Check if node is the head */
    uint16_t parent_idx = (uint16_t)(parent - pkts_waiting->packets);
    if (parent_idx == pkts_waiting->waiting_head)
    {
        pkts_waiting->waiting_head = parent->next_ip;
    }
    else
    {
        prev_node->next_ip = parent->next_ip;
    }

    /* Check if node is the tail */
    if (parent_idx == pkts_waiting->waiting_tail)
    {
        pkts_waiting->waiting_tail = parent->prev_ip;
    }
    else
    {
        next_node->prev_ip = parent->prev_ip;
    }

    /* Only maintain prev pointers for active list */
    parent->next_ip = pkts_waiting->free_head;
    pkts_waiting->free_head = parent_idx;

    /* Update counts */
    pkts_waiting->length--;
    pkts_waiting->size--;

    return ROUTING_ERR_OKAY;
}

static uint16_t fw_routing_find_route(fw_routing_list_t *list,
                                      uint32_t ip,
                                      uint32_t *next_hop,
                                      fw_routing_out_interfaces_t *out_interface)
{
    routing_entry_node_t *match = NULL;
    for (uint16_t i = 0; i < list->capacity; i++)
    {
        routing_entry_node_t *entry = list->nodes + i;
        if (!entry->in_use)
        {
            continue;
        }

        if ((subnet_mask(entry->subnet) & ip) == (subnet_mask(entry->subnet) & entry->ip))
        {
            /* ip is part of subnet */
            if (match == NULL)
            {
                match = entry;
                continue;
            }

            if (entry->subnet > match->subnet ||
                ((entry->subnet == match->subnet) && (entry->next_hop < match->num_hops)))
            {
                match = entry;
                continue;
            }
        }
    }

    if (match)
    {
        *next_hop = match->next_hop;
        *out_interface = match->out_interface;
        return match - list->nodes;
    }

    /* Return the default route */
    *next_hop = ip;
    *out_interface = list->default_out_interface;

    return list->capacity;
}

void fw_routing_list_init(fw_routing_list_t *list, fw_routing_out_interfaces_t default_route, void *buffer, uint16_t capacity)
{
    {
        list->nodes = (routing_entry_node_t *)buffer;
        list->default_out_interface = default_route;
        list->capacity = capacity;
        list->size = 0;
        list->next_id = 0;
        list->head = NULL;
        list->tail = NULL;

        for (uint16_t i = 0; i < capacity; i++)
        {
            routing_entry_node_t *node = &list->nodes[i];
            node->in_use = false;
            node->next = NULL;
            node->prev = NULL;
        }
    }

    for (uint16_t i = 0; i < capacity; i++)
    {
        routing_entry_node_t *node = &list->nodes[i];
        node->in_use = false;
        node->next = NULL;
        node->prev = NULL;
    }
}

routing_entry_node_t *fw_routing_list_add(fw_routing_list_t *list, routing_entry_node_t entry)
{
    if (list->size >= list->capacity)
        return NULL; // list full

    // Find a free node
    routing_entry_node_t *new_node = NULL;
    for (uint16_t i = 0; i < list->capacity; i++)
    {
        if (!list->nodes[i].in_use)
        {
            new_node = &list->nodes[i];
            break;
        }
    }
    if (!new_node)
        return NULL; // no free node found (shouldn't happen)

    // Initialize the new node
    new_node->in_use = true;
    new_node->route_id = list->next_id++;
    new_node->next = NULL;
    new_node->prev = list->tail;

    // Link into the list
    if (list->tail)
        list->tail->next = new_node;
    list->tail = new_node;

    if (!list->head)
        list->head = new_node;

    list->size++;

    return new_node;
}

bool fw_routing_list_remove(fw_routing_list_t *list, uint16_t route_id)
{
    routing_entry_node_t *current = list->head;

    while (current)
    {
        if (current->route_id == route_id)
        {
            // Unlink from list
            if (current->prev)
                current->prev->next = current->next;
            else
                list->head = current->next;

            if (current->next)
                current->next->prev = current->prev;
            else
                list->tail = current->prev;

            // Mark node as free
            current->in_use = false;
            current->next = NULL;
            current->prev = NULL;
            list->size--;

            return true;
        }
        current = current->next;
    }
    return false; // not found
}
