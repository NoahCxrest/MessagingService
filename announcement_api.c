#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <stdbool.h>
#include "mongoose.h"

#define MAX_MESSAGE_LENGTH 256
#define AUTH_TOKEN_LENGTH 24

typedef struct {
    char message[MAX_MESSAGE_LENGTH];
    time_t expires_at;
} Announcement;

static atomic_flag lock = ATOMIC_FLAG_INIT;
static Announcement current_announcement = {{0}, 0};
static const char auth_token[AUTH_TOKEN_LENGTH] = "very-mindful-very-demure";

static inline void acquire_lock(void) {
    while (atomic_flag_test_and_set(&lock)) {
        __builtin_ia32_pause();
    }
}

static inline void release_lock(void) {
    atomic_flag_clear(&lock);
}

static inline bool get_announcement(char *buffer, size_t buffer_size, time_t *expires_at) {
    acquire_lock();
    time_t now = time(NULL);
    if (current_announcement.expires_at > now) {
        memcpy(buffer, current_announcement.message, buffer_size);
        *expires_at = current_announcement.expires_at;
        release_lock();
        return true;
    }
    release_lock();
    return false;
}

static inline int set_announcement(const char *message, time_t expires_at, const char *token) {
    if (__builtin_expect(memcmp(token, auth_token, AUTH_TOKEN_LENGTH) != 0, 0)) {
        return -1;  // Unauthorized
    }
    acquire_lock();
    size_t msg_len = strnlen(message, MAX_MESSAGE_LENGTH - 1);
    memcpy(current_announcement.message, message, msg_len);
    current_announcement.message[msg_len] = '\0';
    current_announcement.expires_at = expires_at;
    release_lock();
    return 1;
}

static inline void clear_announcement(const char *token) {
    if (__builtin_expect(memcmp(token, auth_token, AUTH_TOKEN_LENGTH) == 0, 1)) {
        acquire_lock();
        current_announcement.expires_at = 0;
        current_announcement.message[0] = '\0';
        release_lock();
    }
}

static void handle_get_announcement(struct mg_connection *c, struct mg_http_message *hm) {
    char buffer[MAX_MESSAGE_LENGTH];
    time_t expires_at;
    
    if (get_announcement(buffer, sizeof(buffer), &expires_at)) {
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                      "{\"message\":\"%s\",\"expiresat\":%ld}", buffer, (long)expires_at);
    } else {
        mg_http_reply(c, 204, "", "");
    }
}

static void handle_set_announcement(struct mg_connection *c, struct mg_http_message *hm) {
    char message[MAX_MESSAGE_LENGTH];
    time_t expires_at;
    char token[AUTH_TOKEN_LENGTH];

    const char *msg = mg_json_get_str(hm->body, "$.message");
    if (msg) {
        strncpy(message, msg, sizeof(message) - 1);
        message[sizeof(message) - 1] = '\0';
    }
    
    expires_at = mg_json_get_long(hm->body, "$.expiresat", 0);
    
    const char *tok = mg_json_get_str(hm->body, "$.token");
    if (tok) {
        memcpy(token, tok, AUTH_TOKEN_LENGTH - 1);
        token[AUTH_TOKEN_LENGTH - 1] = '\0';
    }

    int result = set_announcement(message, expires_at, token);
    if (result == 1) {
        mg_http_reply(c, 201, "Content-Type: application/json\r\n", "{\"status\":\"success\"}");
    } else if (result == -1) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", "{\"status\":\"unauthorized\"}");
    } else {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", "{\"status\":\"bad request\"}");
    }
}

static void handle_clear_announcement(struct mg_connection *c, struct mg_http_message *hm) {
    char token[AUTH_TOKEN_LENGTH];
    
    const char *tok = mg_json_get_str(hm->body, "$.token");
    if (tok) {
        memcpy(token, tok, AUTH_TOKEN_LENGTH - 1);
        token[AUTH_TOKEN_LENGTH - 1] = '\0';
    }

    clear_announcement(token);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"status\":\"success\"}");
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (mg_strcmp(hm->uri, mg_str("/announcement")) == 0) {
            if (mg_vcmp(&hm->method, "GET") == 0) {
                handle_get_announcement(c, hm);
            } else if (mg_vcmp(&hm->method, "POST") == 0) {
                handle_set_announcement(c, hm);
            } else if (mg_vcmp(&hm->method, "DELETE") == 0) {
                handle_clear_announcement(c, hm);
            }
        }
    }
}

int main(void) {
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:5671", ev_handler, NULL);
    printf("Starting Announcement API server on port 5671\n");
    for (;;) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    return 0;
}
