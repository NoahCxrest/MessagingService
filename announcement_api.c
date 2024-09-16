#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdatomic.h>
#include "mongoose.h"

// Constants
#define MAX_MESSAGE_LENGTH 256
#define AUTH_TOKEN_LENGTH 24
#define POLL_INTERVAL_MS 50

// Structs for Announcement and Flags
typedef struct {
    unsigned int has_announcement : 1;
    unsigned int reserved : 7;
} __attribute__((packed)) AnnouncementFlags;

typedef struct {
    char message[MAX_MESSAGE_LENGTH];
    time_t expires_at;
    AnnouncementFlags flags;
} __attribute__((packed)) Announcement;

// Global variables
static Announcement current_announcement = {.message = "", .expires_at = 0, .flags = {0, 0}};
static atomic_flag spinlock = ATOMIC_FLAG_INIT;
static atomic_int connection_count = 0;
const char *cors_headers = "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                           "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
static char auth_token[AUTH_TOKEN_LENGTH + 1] = {0};
static struct mg_mgr mgr;

// Lock management functions
static inline void acquire_lock(void) {
    while (atomic_flag_test_and_set(&spinlock)) {
        struct timespec ts = {0, 1000000}; // 1 ms
        nanosleep(&ts, NULL);
    }
}

static inline void release_lock(void) {
    atomic_flag_clear(&spinlock);
}

// Announcement management functions
static inline bool get_announcement(char *buffer, size_t buffer_size, time_t *expires_at) {
    bool has_announcement;
    acquire_lock();
    has_announcement = current_announcement.flags.has_announcement && current_announcement.expires_at > time(NULL);
    if (has_announcement) {
        strncpy(buffer, current_announcement.message, buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        *expires_at = current_announcement.expires_at;
    }
    release_lock();
    return has_announcement;
}

static inline int set_announcement(const char *message, time_t expires_at, const char *token) {
    if (memcmp(token, auth_token, AUTH_TOKEN_LENGTH) != 0) {
        return -1;  // Unauthorized
    }

    acquire_lock();
    strncpy(current_announcement.message, message, MAX_MESSAGE_LENGTH - 1);
    current_announcement.message[MAX_MESSAGE_LENGTH - 1] = '\0';
    current_announcement.expires_at = expires_at;
    current_announcement.flags.has_announcement = 1;
    release_lock();
    return 1;
}

static inline void clear_announcement(const char *token) {
    if (memcmp(token, auth_token, AUTH_TOKEN_LENGTH) == 0) {
        acquire_lock();
        current_announcement.expires_at = 0;
        current_announcement.message[0] = '\0';
        current_announcement.flags.has_announcement = 0;
        release_lock();

        char broadcast_message[512];
        snprintf(broadcast_message, sizeof(broadcast_message), "{\"type\":\"announcement_cleared\"}");

        size_t message_len = strlen(broadcast_message);
        for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) {
            if (c->is_websocket) {
                mg_ws_send(c, broadcast_message, message_len, WEBSOCKET_OP_BINARY);
            }
        }
    }
}

static void broadcast_announcement(void) {
    char buffer[MAX_MESSAGE_LENGTH];
    time_t expires_at;

    if (get_announcement(buffer, sizeof(buffer), &expires_at)) {
        char broadcast_message[512];
        snprintf(broadcast_message, sizeof(broadcast_message),
                 "{\"type\":\"announcement\",\"message\":\"%s\",\"expiresat\":%ld}",
                 buffer, (long)expires_at);

        size_t message_len = strlen(broadcast_message);
        for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) {
            if (c->is_websocket) {
                mg_ws_send(c, broadcast_message, message_len, WEBSOCKET_OP_BINARY);
            }
        }
    }
}

// HTTP request handlers
static void handle_get_announcement(struct mg_connection *c) {
    char buffer[MAX_MESSAGE_LENGTH];
    time_t expires_at;

    if (get_announcement(buffer, sizeof(buffer), &expires_at)) {
        mg_http_reply(c, 200, cors_headers,
                      "{\"message\":\"%s\",\"expiresat\":%ld}", buffer, (long)expires_at);
    } else {
        mg_http_reply(c, 204, cors_headers, "");
    }
}

static void handle_set_announcement(struct mg_connection *c, struct mg_http_message *hm) {
    char message[MAX_MESSAGE_LENGTH] = {0};
    char token[AUTH_TOKEN_LENGTH + 1] = {0};
    time_t expires_at = mg_json_get_long(hm->body, "$.expiresat", 0);

    char *msg_str = mg_json_get_str(hm->body, "$.message");
    if (msg_str) {
        strncpy(message, msg_str, sizeof(message) - 1);
        free(msg_str);
    }

    char *token_str = mg_json_get_str(hm->body, "$.token");
    if (token_str) {
        strncpy(token, token_str, sizeof(token) - 1);
        free(token_str);
    }

    int result = set_announcement(message, expires_at, token);
    if (result == 1) {
        broadcast_announcement();
    }
    mg_http_reply(c, result == 1 ? 201 : 401, cors_headers,
                  result == 1 ? "{\"status\":\"success\"}" : "{\"status\":\"unauthorized\"}");
}

static void handle_clear_announcement(struct mg_connection *c, struct mg_http_message *hm) {
    char token[AUTH_TOKEN_LENGTH + 1] = {0};
    char *token_str = mg_json_get_str(hm->body, "$.token");
    if (token_str) {
        strncpy(token, token_str, sizeof(token) - 1);
        free(token_str);
    }
    clear_announcement(token);
    broadcast_announcement();
    mg_http_reply(c, 200, cors_headers, "{\"status\":\"success\"}");
}

// WebSocket event handler
static void handle_websocket(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_WS_OPEN) {
        c->is_websocket = 1;
        atomic_fetch_add(&connection_count, 1);
        mg_ws_send(c, "{\"type\":\"connected\"}", 20, WEBSOCKET_OP_BINARY);

        char buffer[MAX_MESSAGE_LENGTH];
        time_t expires_at;
        if (get_announcement(buffer, sizeof(buffer), &expires_at)) {
            char announcement_message[512];
            snprintf(announcement_message, sizeof(announcement_message),
                     "{\"type\":\"announcement\",\"message\":\"%s\",\"expiresat\":%ld}",
                     buffer, (long)expires_at);
            mg_ws_send(c, announcement_message, strlen(announcement_message), WEBSOCKET_OP_BINARY);
        }
    } else if (ev == MG_EV_CLOSE) {
        if (c->is_websocket) {
            atomic_fetch_sub(&connection_count, 1);
        }
    } else if (ev == MG_EV_WS_MSG) {
       // Handle WebSocket message
    }
}

// Event handler for HTTP and WebSocket events
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_strcmp(hm->uri, mg_str("/announcement")) == 0) {
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                handle_get_announcement(c);
            } else if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
                handle_set_announcement(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("DELETE")) == 0) {
                handle_clear_announcement(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200, cors_headers, "");
            } else {
                mg_http_reply(c, 405, cors_headers, "{\"status\":\"method not allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/stream")) == 0 &&
                   mg_strcmp(hm->method, mg_str("GET")) == 0) {
            mg_ws_upgrade(c, hm, NULL);
        } else {
            mg_http_reply(c, 404, cors_headers, "{\"status\":\"not found\"}");
        }
    } else if (ev == MG_EV_WS_MSG) {
        handle_websocket(c, ev, ev_data);
    }
}

// Main function
int main() {
    const char *env_token = getenv("ANNOUNCEMENT_AUTH_TOKEN");

    if (!env_token || strlen(env_token) != AUTH_TOKEN_LENGTH) {
        fprintf(stderr, "Invalid or missing ANNOUNCEMENT_AUTH_TOKEN environment variable.\n");
        return 1;
    }
    strncpy(auth_token, env_token, AUTH_TOKEN_LENGTH);
    auth_token[AUTH_TOKEN_LENGTH] = '\0'; // Ensure null-termination

    mg_mgr_init(&mgr);

    struct mg_connection *nc = mg_http_listen(&mgr, "http://0.0.0.0:5671", ev_handler, NULL);
    if (nc == NULL) {
        fprintf(stderr, "Failed to create listener.\n");
        mg_mgr_free(&mgr);
        return 1;
    }

    printf("Starting Announcement API server on port 5671\n");

    while (true) {
        mg_mgr_poll(&mgr, POLL_INTERVAL_MS);
    }

    mg_mgr_free(&mgr);
    return 0;
}
