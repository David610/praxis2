#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
#define DHT_MSG_SIZE 11
#define MAX_CACHED_RESPONSES 10

// DHT Message types
enum {
    MSG_LOOKUP = 0,
    MSG_REPLY = 1
};

// DHT message structure
struct dht_message {
    uint8_t type;
    uint16_t hash_id;
    uint16_t node_id;
    struct in_addr node_ip;
    uint16_t node_port;
};

// DHT Node state
struct dht_node {
    uint16_t id;
    uint16_t predecessor_id;
    char *predecessor_ip;
    uint16_t predecessor_port;
    uint16_t successor_id;
    char *successor_ip;
    uint16_t successor_port;
};

// Server state combining HTTP and DHT
struct server_state {
    // HTTP state
    struct connection_state http_conn;
    int tcp_socket;
    
    // DHT state
    struct dht_node node;
    int udp_socket;
    
    // Cache for DHT responses
    struct {
        uint16_t hash;
        uint16_t responsible_id;
        char *responsible_ip;
        uint16_t responsible_port;
    } response_cache[MAX_CACHED_RESPONSES];
    int cache_count;
};

// Static resources
struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof("Foo") - 1},
    {"/static/bar", "Bar", sizeof("Bar") - 1},
    {"/static/baz", "Baz", sizeof("Baz") - 1}
};

// Function declarations
static void dht_init(struct dht_node *node, const char *self_ip, uint16_t self_port);
static bool is_responsible(struct dht_node *node, uint16_t hash);
static void handle_dht_message(struct server_state *state);
static void send_dht_lookup(struct server_state *state, uint16_t hash);
static void send_dht_reply(struct server_state *state, struct dht_message *request);
static void cache_dht_response(struct server_state *state, uint16_t hash, 
                             uint16_t id, const char *ip, uint16_t port);
static bool get_cached_response(struct server_state *state, uint16_t hash,
                              uint16_t *id, char **ip, uint16_t *port);

// Buffer handling utilities
static char *buffer_discard(char *buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard);
    return buffer + keep;
}

// Connection setup
static void connection_setup(struct connection_state *state, int sock) {
    state->sock = sock;
    state->end = state->buffer;
    memset(state->buffer, 0, HTTP_MAX_SIZE);
    memset(&state->current_request, 0, sizeof(state->current_request));
}

// Initialize DHT node state from environment variables
// Function declarations
static void connection_setup(struct connection_state *state, int sock);
static char *buffer_discard(char *buffer, size_t discard, size_t keep);

static void dht_init(struct dht_node *node, const char *self_ip, uint16_t self_port) {
    char *pred_id = getenv("PRED_ID");
    char *pred_ip = getenv("PRED_IP"); 
    char *pred_port = getenv("PRED_PORT");
    char *succ_id = getenv("SUCC_ID");
    char *succ_ip = getenv("SUCC_IP");
    char *succ_port = getenv("SUCC_PORT");
    
    if (pred_id && pred_ip && pred_port) {
        node->predecessor_id = (uint16_t)strtoul(pred_id, NULL, 10);
        node->predecessor_ip = strdup(pred_ip);
        node->predecessor_port = (uint16_t)strtoul(pred_port, NULL, 10);
    }
    
    if (succ_id && succ_ip && succ_port) {
        node->successor_id = (uint16_t)strtoul(succ_id, NULL, 10);
        node->successor_ip = strdup(succ_ip);
        node->successor_port = (uint16_t)strtoul(succ_port, NULL, 10);
    }
}

// Check if this node is responsible for the given hash
static bool is_responsible(struct dht_node *node, uint16_t hash) {
    // In Chord, a node is responsible for hashes between (predecessor_id, node_id]
    if (node->predecessor_id < node->id) {
        return hash > node->predecessor_id && hash <= node->id;
    } else {
        // Handle wrap-around case
        return hash > node->predecessor_id || hash <= node->id;
    }
}

// Send a DHT lookup message
static void send_dht_lookup(struct server_state *state, uint16_t hash) {
    struct dht_message msg = {
        .type = MSG_LOOKUP,
        .hash_id = htons(hash),
        .node_id = htons(state->node.id),
        .node_port = htons(ntohs(((struct sockaddr_in *)&state->http_conn.sock)->sin_port))
    };
    inet_pton(AF_INET, state->node.successor_ip, &msg.node_ip);
    
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(state->node.successor_port)
    };
    inet_pton(AF_INET, state->node.successor_ip, &dest.sin_addr);
    
    sendto(state->udp_socket, &msg, sizeof(msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));
}

// Send a DHT reply message
static void send_dht_reply(struct server_state *state, struct dht_message *msg) {
    struct dht_message reply;
    reply.type = MSG_REPLY;
    reply.hash_id = htons(state->node.predecessor_id);  // Previous node ID
    reply.node_id = htons(state->node.id);             // This node's ID (responsible)
    
    // Set our own IP and port
    struct sockaddr_in self_addr;
    socklen_t addr_len = sizeof(self_addr);
    getsockname(state->udp_socket, (struct sockaddr *)&self_addr, &addr_len);
    reply.node_ip = self_addr.sin_addr;
    reply.node_port = self_addr.sin_port;
    
    // Send to original requester
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = msg->node_port,
        .sin_addr = msg->node_ip
    };
    
    sendto(state->udp_socket, &reply, sizeof(reply), 0,
           (struct sockaddr *)&dest, sizeof(dest));
}

// Handle incoming DHT messages
static void handle_dht_message(struct server_state *state) {
    struct dht_message msg;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    
    ssize_t recv_len = recvfrom(state->udp_socket, &msg, sizeof(msg), 0,
                               (struct sockaddr *)&sender, &sender_len);
                               
    if (recv_len != sizeof(struct dht_message)) {
        return;
    }
    
    // Convert network to host byte order
    msg.hash_id = ntohs(msg.hash_id);
    msg.node_id = ntohs(msg.node_id);
    msg.node_port = ntohs(msg.node_port);
    
    switch (msg.type) {
        case MSG_LOOKUP:
            if (is_responsible(&state->node, msg.hash_id)) {
                // We are responsible - send reply
                send_dht_reply(state, &msg);
            } else {
                // Forward lookup to successor
                struct sockaddr_in next = {
                    .sin_family = AF_INET,
                    .sin_port = htons(state->node.successor_port)
                };
                inet_pton(AF_INET, state->node.successor_ip, &next.sin_addr);
                
                sendto(state->udp_socket, &msg, sizeof(msg), 0,
                       (struct sockaddr *)&next, sizeof(next));
            }
            break;
            
        case MSG_REPLY: {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &msg.node_ip, ip_str, sizeof(ip_str));
            cache_dht_response(state, msg.hash_id, msg.node_id, 
                             ip_str, msg.node_port);
            break;
        }
    }
}

// Cache a DHT response
static void cache_dht_response(struct server_state *state, uint16_t hash,
                             uint16_t id, const char *ip, uint16_t port) {
    if (state->cache_count >= MAX_CACHED_RESPONSES) {
        // Remove oldest entry
        memmove(&state->response_cache[0], &state->response_cache[1],
                sizeof(state->response_cache[0]) * (MAX_CACHED_RESPONSES - 1));
        state->cache_count--;
    }
    
    int idx = state->cache_count++;
    state->response_cache[idx].hash = hash;
    state->response_cache[idx].responsible_id = id;
    state->response_cache[idx].responsible_ip = strdup(ip);
    state->response_cache[idx].responsible_port = port;
}

// Get a cached DHT response
static bool get_cached_response(struct server_state *state, uint16_t hash,
                              uint16_t *id, char **ip, uint16_t *port) {
    for (int i = 0; i < state->cache_count; i++) {
        if (state->response_cache[i].hash == hash) {
            *id = state->response_cache[i].responsible_id;
            *ip = state->response_cache[i].responsible_ip;
            *port = state->response_cache[i].responsible_port;
            return true;
        }
    }
    return false;
}

// Send HTTP response
static void send_http_response(int conn, struct request *request, struct server_state *state) {
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;
    
    uint16_t uri_hash = pseudo_hash((unsigned char *)request->uri, strlen(request->uri));
    
    if (is_responsible(&state->node, uri_hash)) {
        // We are responsible for this resource
        if (strcmp(request->method, "GET") == 0) {
            size_t resource_length;
            const char *resource = get(request->uri, resources, MAX_RESOURCES, &resource_length);

            if (resource) {
                offset = sprintf(reply, 
                    "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                    resource_length);
                memcpy(reply + offset, resource, resource_length);
                offset += resource_length;
            } else {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                offset = strlen(reply);
            }
        } else if (strcmp(request->method, "PUT") == 0) {
            if (set(request->uri, request->payload, request->payload_length,
                    resources, MAX_RESOURCES)) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
            }
            offset = strlen(reply);
        } else if (strcmp(request->method, "DELETE") == 0) {
            if (delete(request->uri, resources, MAX_RESOURCES)) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 404 Not Found\r\n\r\n";
            }
            offset = strlen(reply);
        } else {
            reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
            offset = strlen(reply);
        }
    } else {
        // Check if we have cached response
        uint16_t resp_id;
        char *resp_ip;
        uint16_t resp_port;
        
        if (get_cached_response(state, uri_hash, &resp_id, &resp_ip, &resp_port)) {
            // We know who's responsible
            offset = sprintf(reply,
                "HTTP/1.1 303 See Other\r\n"
                "Location: http://%s:%u%s\r\n"
                "Content-Length: 0\r\n\r\n",
                resp_ip, resp_port, request->uri);
        } else {
            // Need to do lookup
            send_dht_lookup(state, uri_hash);
            reply = "HTTP/1.1 503 Service Unavailable\r\n"
                   "Retry-After: 1\r\n"
                   "Content-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
    }

    if (send(conn, reply, offset, 0) == -1) {
        perror("send");
        close(conn);
    }
}

// Process a packet from the buffer
// Process a packet from the buffer
static size_t process_packet(struct connection_state *conn, struct server_state *state) {
    struct request request = {0};  // Initialize all fields to zero
    
    ssize_t bytes_processed = parse_request(conn->buffer, 
                                          conn->end - conn->buffer,
                                          &request);
    if (bytes_processed > 0) {
        // Calculate hash of URI for DHT routing
        uint16_t uri_hash = pseudo_hash((const unsigned char *)request.uri, strlen(request.uri));
        
        if (is_responsible(&state->node, uri_hash)) {
            // We are responsible - handle directly
            if (strcmp(request.method, "GET") == 0) {
                size_t resource_length;
                const char *resource = get(request.uri, resources, MAX_RESOURCES, &resource_length);
                if (resource) {
                    char response[HTTP_MAX_SIZE];
                    int len = sprintf(response, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", resource_length);
                    memcpy(response + len, resource, resource_length);
                    send(conn->sock, response, len + resource_length, 0);
                } else {
                    const char *response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                    send(conn->sock, response, strlen(response), 0);
                }
            } else if (strcmp(request.method, "PUT") == 0) {
                bool updated = set(request.uri, request.payload, request.payload_length, resources, MAX_RESOURCES);
                const char *response = updated ? 
                    "HTTP/1.1 204 No Content\r\n\r\n" :
                    "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
                send(conn->sock, response, strlen(response), 0);
            } else if (strcmp(request.method, "DELETE") == 0) {
                bool deleted = delete(request.uri, resources, MAX_RESOURCES);
                const char *response = deleted ?
                    "HTTP/1.1 204 No Content\r\n\r\n" :
                    "HTTP/1.1 404 Not Found\r\n\r\n";
                send(conn->sock, response, strlen(response), 0);
            } else {
                const char *response = "HTTP/1.1 501 Not Implemented\r\n\r\n";
                send(conn->sock, response, strlen(response), 0);
            }
        } else {
            // Check cache first
            uint16_t resp_id;
            char *resp_ip;
            uint16_t resp_port;
            
            if (get_cached_response(state, uri_hash, &resp_id, &resp_ip, &resp_port)) {
                // We know the responsible node
                char response[HTTP_MAX_SIZE];
                int len = sprintf(response, 
                    "HTTP/1.1 303 See Other\r\n"
                    "Location: http://%s:%u%s\r\n"
                    "Content-Length: 0\r\n\r\n",
                    resp_ip, resp_port, request.uri);
                send(conn->sock, response, len, 0);
            } else {
                // Need to do lookup
                send_dht_lookup(state, uri_hash);
                const char *response = 
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Retry-After: 1\r\n"
                    "Content-Length: 0\r\n\r\n";
                send(conn->sock, response, strlen(response), 0);
            }
        }
        
        // Check if connection should be closed
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close") == 0) {
            return -1;
        }
    } else if (bytes_processed == -1) {
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn->sock, bad_request, strlen(bad_request), 0);
        return -1;
    }

    return bytes_processed;
}

// Setup TCP socket
static int setup_tcp_socket(const char *ip, uint16_t port) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("TCP socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket to non-blocking mode
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl failed");
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    const int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("TCP bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1)) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Setup UDP socket
static int setup_udp_socket(const char *ip, uint16_t port) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("UDP socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    const int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt for UDP failed");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("UDP bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Handle connection
static bool handle_connection(struct connection_state *state, struct server_state *server) {
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;
    
    ssize_t bytes_read = recv(state->sock, state->end, 
                             buffer_end - state->end, 0);
    if (bytes_read == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;  // No data available right now
        }
        perror("recv");
        return false;
    } else if (bytes_read == 0) {
        return false;  // Connection closed
    }

    state->end += bytes_read;
    
    size_t processed_bytes = 0;
    char *current = state->buffer;
    
    while ((processed_bytes = process_packet(state, server)) > 0) {
        current += processed_bytes;
        if (current >= state->end) {
            break;
        }
    }
    
    if (processed_bytes == -1) {
        return false;
    }
    
    // Move any remaining data to start of buffer
    size_t remaining = state->end - current;
    if (remaining > 0 && current > state->buffer) {
        memmove(state->buffer, current, remaining);
    }
    state->end = state->buffer + remaining;
    
    return true;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <ip> <port> [node_id]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse command line arguments
    const char *ip = argv[1];
    uint16_t port = atoi(argv[2]);
    uint16_t node_id = argc == 4 ? atoi(argv[3]) : 0;

    // Initialize server state
    struct server_state server = {0};
    server.node.id = node_id;

    // Initialize DHT node
    dht_init(&server.node, ip, port);

    // Setup TCP and UDP sockets
    server.tcp_socket = setup_tcp_socket(ip, port);
    server.udp_socket = setup_udp_socket(ip, port);

    // Setup polling
    struct pollfd sockets[3] = {
        {.fd = server.tcp_socket, .events = POLLIN},  // TCP listening socket
        {.fd = -1, .events = 0},                      // Active TCP connection
        {.fd = server.udp_socket, .events = POLLIN}   // UDP socket
    };

    // Main event loop
    while (true) {
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        // Process events on monitored sockets
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++) {
            if (sockets[i].revents != POLLIN) {
                continue;
            }

            int s = sockets[i].fd;

            if (s == server.tcp_socket) {
                // Handle new TCP connection
                int connection = accept(server.tcp_socket, NULL, NULL);
                if (connection == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }
                } else {
                    // Setup new connection state
                    connection_setup(&server.http_conn, connection);
                    sockets[0].events = 0;  // Stop accepting new connections
                    sockets[1].fd = connection;
                    sockets[1].events = POLLIN;
                }
            } else if (s == server.udp_socket) {
                // Handle DHT message
                handle_dht_message(&server);
            } else {
                // Handle HTTP data on active connection
                assert(s == server.http_conn.sock);
                bool cont = handle_connection(&server.http_conn, &server);
                if (!cont) {
                    // Connection closed, ready to accept new ones
                    sockets[0].events = POLLIN;
                    sockets[1].fd = -1;
                    sockets[1].events = 0;
                }
            }
        }
    }

    // Cleanup
    close(server.tcp_socket);
    close(server.udp_socket);
    free(server.node.predecessor_ip);
    free(server.node.successor_ip);
    for (int i = 0; i < server.cache_count; i++) {
        free(server.response_cache[i].responsible_ip);
    }

    return EXIT_SUCCESS;
}