#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
#define FLAGS_LOOKUP 0
#define FLAGS_REPLY 1
#define MAX_CACHED_RESP 10

struct wire_msg {
    uint8_t  flags;
    uint16_t msg_id;
    uint16_t peer_id;
    struct in_addr peer_ip;
    uint16_t peer_port;
} __attribute__((packed));

static uint16_t g_last_lookup_hash = 0;

struct chord_node {
    uint16_t id;
    uint16_t predecessor_id;
    char    *predecessor_ip;
    uint16_t predecessor_port;
    uint16_t successor_id;
    char    *successor_ip;
    uint16_t successor_port;
};

struct resp_entry {
    uint16_t hash;
    uint16_t responsible_id;
    char    *responsible_ip;
    uint16_t responsible_port;
};

struct server_state {
    struct connection_state http_conn;
    int tcp_socket;
    struct chord_node node;
    int udp_socket;
    struct resp_entry cache[MAX_CACHED_RESP];
    int cache_count;
};

static struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof("Foo") - 1},
    {"/static/bar", "Bar", sizeof("Bar") - 1},
    {"/static/baz", "Baz", sizeof("Baz") - 1}
};

static int in_range(uint16_t start, uint16_t end, uint16_t x) {
    if (start < end) return (x > start) && (x <= end);
    return (x > start) || (x <= end);
}

static void chord_init_env(struct chord_node *n, const char *ip, uint16_t port, uint16_t id) {
    memset(n, 0, sizeof(*n));
    n->id = id;
    n->predecessor_id = id;
    n->predecessor_ip = strdup(ip);
    n->predecessor_port = port;
    n->successor_id = id;
    n->successor_ip = strdup(ip);
    n->successor_port = port;
    char *p_id = getenv("PRED_ID");
    char *p_ip = getenv("PRED_IP");
    char *p_port = getenv("PRED_PORT");
    char *s_id = getenv("SUCC_ID");
    char *s_ip = getenv("SUCC_IP");
    char *s_port = getenv("SUCC_PORT");
    if (p_id && p_ip && p_port) {
        free(n->predecessor_ip);
        n->predecessor_id = (uint16_t)strtoul(p_id, NULL, 10);
        n->predecessor_ip = strdup(p_ip);
        n->predecessor_port = (uint16_t)strtoul(p_port, NULL, 10);
    }
    if (s_id && s_ip && s_port) {
        free(n->successor_ip);
        n->successor_id = (uint16_t)strtoul(s_id, NULL, 10);
        n->successor_ip = strdup(s_ip);
        n->successor_port = (uint16_t)strtoul(s_port, NULL, 10);
    }
}

static void cache_store(struct server_state *st, uint16_t hash, uint16_t rid, const char *rip, uint16_t rport) {
    if (st->cache_count >= MAX_CACHED_RESP) {
        memmove(&st->cache[0], &st->cache[1], sizeof(st->cache[0])*(MAX_CACHED_RESP-1));
        st->cache_count--;
    }
    int idx = st->cache_count++;
    st->cache[idx].hash = hash;
    st->cache[idx].responsible_id = rid;
    st->cache[idx].responsible_ip = strdup(rip);
    st->cache[idx].responsible_port = rport;
}

static int cache_find(struct server_state *st, uint16_t hash, uint16_t *rid, char **rip, uint16_t *rport) {
    for (int i = 0; i < st->cache_count; i++) {
        if (st->cache[i].hash == hash) {
            *rid = st->cache[i].responsible_id;
            *rip = st->cache[i].responsible_ip;
            *rport = st->cache[i].responsible_port;
            return 1;
        }
    }
    return 0;
}

static void handle_dht_message(struct server_state *st) {
    struct wire_msg msg;
    memset(&msg, 0, sizeof(msg));
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);
    ssize_t n = recvfrom(st->udp_socket, &msg, sizeof(msg), 0, (struct sockaddr*)&sender, &slen);
    if (n != (ssize_t)sizeof(msg)) return;
    uint8_t flags = msg.flags;
    uint16_t msg_id = ntohs(msg.msg_id);
    uint16_t peer_id = ntohs(msg.peer_id);
    struct in_addr peer_ip = msg.peer_ip;
    uint16_t peer_port_h = ntohs(msg.peer_port);
    if (flags == FLAGS_LOOKUP) {
        uint16_t hash = msg_id;
        g_last_lookup_hash = hash;
        if (in_range(st->node.id, st->node.successor_id, hash)) {
            struct wire_msg rep;
            memset(&rep, 0, sizeof(rep));
            rep.flags = FLAGS_REPLY;
            rep.msg_id = htons(st->node.id);
            rep.peer_id = htons(st->node.successor_id);
            struct sockaddr_in succ;
            memset(&succ, 0, sizeof(succ));
            succ.sin_family = AF_INET;
            succ.sin_port = htons(st->node.successor_port);
            inet_pton(AF_INET, st->node.successor_ip, &succ.sin_addr);
            rep.peer_ip = succ.sin_addr;
            rep.peer_port = htons(st->node.successor_port);
            struct sockaddr_in origin;
            memset(&origin, 0, sizeof(origin));
            origin.sin_family = AF_INET;
            origin.sin_addr = peer_ip;
            origin.sin_port = htons(peer_port_h);
            sendto(st->udp_socket, &rep, sizeof(rep), 0, (struct sockaddr*)&origin, sizeof(origin));
        } else {
            struct wire_msg fwd;
            memset(&fwd, 0, sizeof(fwd));
            fwd.flags = FLAGS_LOOKUP;
            fwd.msg_id = htons(hash);
            fwd.peer_id = htons(peer_id);
            fwd.peer_ip = peer_ip;
            fwd.peer_port = htons(peer_port_h);
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(st->node.successor_port);
            inet_pton(AF_INET, st->node.successor_ip, &dest.sin_addr);
            sendto(st->udp_socket, &fwd, sizeof(fwd), 0, (struct sockaddr*)&dest, sizeof(dest));
        }
    } else if (flags == FLAGS_REPLY) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &msg.peer_ip, ip_str, sizeof(ip_str));
        cache_store(st, g_last_lookup_hash, peer_id, ip_str, peer_port_h);
    }
}

static void send_http_response(int conn, struct request *rq, struct server_state *st) {
    char buffer[HTTP_MAX_SIZE];
    memset(buffer, 0, sizeof(buffer));
    size_t off = 0;
    uint16_t h = pseudo_hash((unsigned char*)rq->uri, strlen(rq->uri));
    if (in_range(st->node.predecessor_id, st->node.id, h)) {
        if (strcmp(rq->method, "GET") == 0) {
            size_t length;
            const char *val = get(rq->uri, resources, MAX_RESOURCES, &length);
            if (val) {
                off = snprintf(buffer, sizeof(buffer),
                               "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", length);
                if (off + length < sizeof(buffer)) {
                    memcpy(buffer + off, val, length);
                    off += length;
                }
            } else {
                off = snprintf(buffer, sizeof(buffer),
                               "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            }
        } else if (strcmp(rq->method, "PUT") == 0) {
            bool overwrote = set(rq->uri, rq->payload, rq->payload_length, resources, MAX_RESOURCES);
            if (overwrote) {
                off = snprintf(buffer, sizeof(buffer), "HTTP/1.1 204 No Content\r\n\r\n");
            } else {
                off = snprintf(buffer, sizeof(buffer),
                               "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
            }
        } else if (strcmp(rq->method, "DELETE") == 0) {
            bool deleted = delete(rq->uri, resources, MAX_RESOURCES);
            if (deleted) {
                off = snprintf(buffer, sizeof(buffer), "HTTP/1.1 204 No Content\r\n\r\n");
            } else {
                off = snprintf(buffer, sizeof(buffer), "HTTP/1.1 404 Not Found\r\n\r\n");
            }
        } else {
            off = snprintf(buffer, sizeof(buffer), "HTTP/1.1 501 Not Implemented\r\n\r\n");
        }
    } else {
        uint16_t rid, rport;
        char *rip;
        if (cache_find(st, h, &rid, &rip, &rport)) {
            off = snprintf(buffer, sizeof(buffer),
                           "HTTP/1.1 303 See Other\r\nLocation: http://%s:%u%s\r\nContent-Length: 0\r\n\r\n",
                           rip, rport, rq->uri);
        } else {
            struct wire_msg m;
            memset(&m, 0, sizeof(m));
            m.flags = FLAGS_LOOKUP;
            m.msg_id = htons(h);
            m.peer_id = htons(st->node.id);
            struct sockaddr_in self_addr;
            socklen_t sl = sizeof(self_addr);
            getsockname(st->udp_socket, (struct sockaddr*)&self_addr, &sl);
            m.peer_ip = self_addr.sin_addr;
            m.peer_port = self_addr.sin_port;
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(st->node.successor_port);
            inet_pton(AF_INET, st->node.successor_ip, &dest.sin_addr);
            sendto(st->udp_socket, &m, sizeof(m), 0, (struct sockaddr*)&dest, sizeof(dest));
            g_last_lookup_hash = h;
            off = snprintf(buffer, sizeof(buffer),
                           "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n");
        }
    }
    send(conn, buffer, off, 0);
}

static size_t process_packet(struct connection_state *cs, struct server_state *st) {
    struct request r;
    memset(&r, 0, sizeof(r));
    ssize_t used = parse_request(cs->buffer, cs->end - cs->buffer, &r);
    if (used > 0) {
        send_http_response(cs->sock, &r, st);
        const char *conn_hdr = get_header(&r, "Connection");
        if (conn_hdr && strcmp(conn_hdr,"close")==0) return (size_t)-1;
    } else if (used == -1) {
        const char *bad = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(cs->sock, bad, strlen(bad), 0);
        return (size_t)-1;
    }
    return used;
}

static bool handle_connection(struct connection_state *cs, struct server_state *st) {
    char *endbuf = cs->buffer + HTTP_MAX_SIZE;
    ssize_t n = recv(cs->sock, cs->end, endbuf - cs->end, 0);
    if (n == -1) {
        if (errno==EAGAIN || errno==EWOULDBLOCK) return true;
        perror("recv");
        return false;
    } else if (n==0) {
        return false;
    }
    cs->end += n;
    size_t used = 0;
    char *cur = cs->buffer;
    while ((used = process_packet(cs, st))>0) {
        cur += used;
        if (cur >= cs->end) break;
    }
    if (used==(size_t)-1) return false;
    size_t remain = cs->end - cur;
    if (remain && (cur>cs->buffer)) {
        memmove(cs->buffer, cur, remain);
    }
    cs->end = cs->buffer + remain;
    return true;
}

static void connection_setup(struct connection_state *cs, int sock) {
    cs->sock = sock;
    cs->end  = cs->buffer;
    memset(cs->buffer, 0, HTTP_MAX_SIZE);
    memset(&cs->current_request, 0, sizeof(cs->current_request));
}

static int setup_tcp_socket(const char *ip, uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s==-1) exit(1);
    if (fcntl(s,F_SETFL,O_NONBLOCK)==-1) exit(1);
    int yes=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    bind(s,(struct sockaddr*)&addr,sizeof(addr));
    listen(s,1);
    return s;
}

static int setup_udp_socket(const char *ip, uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) exit(1);
    int yes=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    bind(s,(struct sockaddr*)&addr,sizeof(addr));
    return s;
}

int main(int argc, char **argv) {
    if (argc<3 || argc>4) return 1;
    const char *ip=argv[1];
    uint16_t port=(uint16_t)atoi(argv[2]);
    uint16_t id=0;
    if (argc==4) id=(uint16_t)atoi(argv[3]);
    struct server_state st;
    memset(&st,0,sizeof(st));
    chord_init_env(&st.node, ip, port, id);
    st.tcp_socket = setup_tcp_socket(ip, port);
    st.udp_socket = setup_udp_socket(ip, port);
    struct pollfd fds[3] = {0};
    fds[0].fd     = st.tcp_socket;
    fds[0].events = POLLIN;
    fds[1].fd     = -1;
    fds[2].fd     = st.udp_socket;
    fds[2].events = POLLIN;
    while (1) {
        int r = poll(fds,3,-1);
        if (r==-1) exit(1);
        if (fds[0].revents & POLLIN) {
            int c = accept(st.tcp_socket, NULL,NULL);
            if (c!=-1) {
                connection_setup(&st.http_conn, c);
                fds[0].events=0;
                fds[1].fd=c;
                fds[1].events=POLLIN;
            }
        }
        if (fds[1].fd!=-1 && (fds[1].revents & POLLIN)) {
            bool keep = handle_connection(&st.http_conn,&st);
            if (!keep) {
                close(st.http_conn.sock);
                fds[0].events=POLLIN;
                fds[1].fd=-1;
                fds[1].events=0;
            }
        }
        if (fds[2].revents & POLLIN) {
            handle_dht_message(&st);
        }
    }
    return 0;
}
