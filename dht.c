#include "dht.h"
#include "util.h"
#include <string.h>

void dht_init(struct dht_node *node, const struct sockaddr_in *addr) {
    // Initialize node with its own address as both successor and predecessor
    memset(node, 0, sizeof(*node));
    node->address = *addr;
    node->id = pseudo_hash((const unsigned char*)&addr->sin_addr.s_addr, 
                          sizeof(addr->sin_addr.s_addr));
    node->successor_id = node->id;
    node->succ_addr = *addr;
    node->initialized = false;
}

void dht_handle_message(struct dht_node *node, const struct dht_message *msg, 
                       const struct sockaddr_in *sender, int udp_sock) {
    // We'll use these parameters later, marking them as unused for now
    (void)sender;
    (void)udp_sock;
    
    struct dht_message response;
    memset(&response, 0, sizeof(response));  // Initialize response
    
    switch(msg->type) {
        case DHT_JOIN:
            // Handle join request
            response.type = DHT_REPLY;
            response.node_id = node->successor_id;
            // Send response using udp_sock to sender
            sendto(udp_sock, &response, sizeof(response), 0,
                  (const struct sockaddr*)sender, sizeof(*sender));
            break;
            
        case DHT_STABILIZE:
            // Handle stabilize request
            response.type = DHT_REPLY;
            response.node_id = node->predecessor_id;
            sendto(udp_sock, &response, sizeof(response), 0,
                  (const struct sockaddr*)sender, sizeof(*sender));
            break;
            
        case DHT_LOOKUP:
        case DHT_REPLY:
        case DHT_NOTIFY:
            // Handle other message types
            break;
    }
}

bool dht_join(struct dht_node *node, int sock, const struct sockaddr_in *bootstrap) {
    if (bootstrap) {
        // Send join message to bootstrap node
        struct dht_message msg = {
            .type = DHT_JOIN,
            .node_id = node->id,
            .ip = node->address.sin_addr.s_addr,
            .port = node->address.sin_port
        };
        
        sendto(sock, &msg, sizeof(msg), 0, 
               (struct sockaddr*)bootstrap, sizeof(*bootstrap));
        return true;
    }
    return false;
}

void dht_stabilize(struct dht_node *node, int sock) {
    if (node->initialized) {
        // Send stabilize message to successor
        struct dht_message msg = {
            .type = DHT_STABILIZE,
            .node_id = node->id
        };
        sendto(sock, &msg, sizeof(msg), 0, 
               (struct sockaddr*)&node->succ_addr, sizeof(node->succ_addr));
    }
}