#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

// Message types as defined in rn.lua
enum dht_message_type {
    DHT_LOOKUP = 0,     // Changed from LOOKUP to DHT_LOOKUP
    DHT_REPLY = 1,      // Changed from REPLY to DHT_REPLY
    DHT_STABILIZE = 2,  // Changed from STABILIZE to DHT_STABILIZE
    DHT_NOTIFY = 3,     // Changed from NOTIFY to DHT_NOTIFY
    DHT_JOIN = 4        // Changed from JOIN to DHT_JOIN
};

// DHT message structure matching the specification
struct dht_message {
    uint8_t type;        // Message type
    uint16_t hash_id;    // Hash ID for lookups
    uint16_t node_id;    // Node identifier
    uint32_t ip;         // IPv4 address
    uint16_t port;       // Port number
} __attribute__((packed));

// Node state structure
struct dht_node {
    uint16_t id;                     // This node's ID
    struct sockaddr_in address;      // Node's address
    uint16_t successor_id;           // Next node in the ring
    struct sockaddr_in succ_addr;    // Successor's address
    uint16_t predecessor_id;         // Previous node in the ring
    struct sockaddr_in pred_addr;    // Predecessor's address
    bool initialized;                // Whether node has joined the DHT
};

// Function declarations
void dht_init(struct dht_node *node, const struct sockaddr_in *addr);
void dht_handle_message(struct dht_node *node, const struct dht_message *msg, 
                       const struct sockaddr_in *sender, int udp_sock);
bool dht_join(struct dht_node *node, int sock, const struct sockaddr_in *bootstrap);
void dht_stabilize(struct dht_node *node, int sock);
bool is_responsible(uint16_t hash, uint16_t pred_id, uint16_t node_id);