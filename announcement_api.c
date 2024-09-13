#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "mongoose.h"

#define MAX_MESSAGE_LENGTH 256
#define AUTH_TOKEN_LENGTH 24

typedef struct {
    unsigned int has_announcement : 1;
    unsigned int reserved : 7;
} __attribute__((packed)) AnnouncementFlags;

typedef struct {
    char message[MAX_MESSAGE_LENGTH];
    time_t expires_at;
    AnnouncementFlags flags;
} __attribute__((packed)) Announcement;

static Announcement current_announcement = {.message = "", .expires_at = 0, .flags = {0, 0}};
static _Atomic int spinlock = 0;
const char *cors_headers = "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                           "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";


static char auth_token[AUTH_TOKEN_LENGTH + 1] = {0};  // Authorization token

static inline void acquire_lock(void) {
    while (__atomic_test_and_set(&spinlock, __ATOMIC_ACQUIRE)) {
        __builtin_ia32_pause();
    }
}

static inline void release_lock(void) {
    __atomic_clear(&spinlock, __ATOMIC_RELEASE);
}

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
    if (__builtin_expect(memcmp(token, auth_token, AUTH_TOKEN_LENGTH) != 0, 0)) {
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
    if (__builtin_expect(memcmp(token, auth_token, AUTH_TOKEN_LENGTH) == 0, 1)) {
        acquire_lock();
        current_announcement.expires_at = 0;
        current_announcement.message[0] = '\0';
        current_announcement.flags.has_announcement = 0;
        release_lock();
    }
}

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
    mg_http_reply(c, 200, cors_headers, "{\"status\":\"success\"}");
}

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
                // Handle preflight CORS requests
                mg_http_reply(c, 200, cors_headers, "");
            } else {
                mg_http_reply(c, 405, cors_headers, "{\"status\":\"method not allowed\"}");
            }
        } else {
            mg_http_reply(c, 404, cors_headers, "{\"status\":\"not found\"}");
        }
    }
}


int main(void) {
    const char *env_token = getenv("ANNOUNCEMENT_AUTH_TOKEN");
    if (!env_token || strlen(env_token) != AUTH_TOKEN_LENGTH) {
        fprintf(stderr, "Invalid or missing ANNOUNCEMENT_AUTH_TOKEN environment variable.\n");
        return 1;
    }
    memcpy(auth_token, env_token, AUTH_TOKEN_LENGTH);

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:5671", ev_handler, NULL);
    printf("Starting Announcement API server on port 5671\n");

    for (;;) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    return 0;
}
