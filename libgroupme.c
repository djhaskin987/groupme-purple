/*
 *   GroupMe plugin for libpurple
 *   Copyright (C) 2021 Daniel Jay Haskin
 *   Copyright (C) 2017-2018 Alyssa Rosenzweig
 *   Copyright (C) 2016  Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
#include <unistd.h>
#endif
#include <errno.h>

#ifdef ENABLE_NLS
#      define GETTEXT_PACKAGE "purple-groupme"
#      include <glib/gi18n-lib.h>
#    ifdef _WIN32
#        ifdef LOCALEDIR
#            unset LOCALEDIR
#        endif
#        define LOCALEDIR  wpurple_locale_dir()
#    endif
#else
#      define _(a) (a)
#      define N_(a) (a)
#endif

#include "glib_compat.h"
#include "json_compat.h"
#include "purple_compat.h"

#define GROUPME_PLUGIN_ID "prpl-alyssarosenzweig-groupme"
#ifndef GROUPME_PLUGIN_VERSION
#define GROUPME_PLUGIN_VERSION "0.1"
#endif
#define GROUPME_PLUGIN_WEBSITE "https://notabug.com/alyssa/groupme-purple"

#define GROUPME_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define GROUPME_API_SERVER "api.groupme.com/v3"
#define GROUPME_PUSH_SERVER "push.groupme.com/faye?"
#define GROUPME_GATEWAY_SERVER "push.groupme.com"
#define GROUPME_GATEWAY_PORT 443
#define GROUPME_GATEWAY_SERVER_PATH "/faye"

/* TODO: Websockets */
/* #define USE_LONG_POLL */
#define USE_WEB_SOCKETS

#ifdef USE_LONG_POLL
#define GROUPME_PUSH_TYPE "long-polling"
#else
#define GROUPME_PUSH_TYPE "websocket"
#endif

#define IGNORE_PRINTS

typedef struct {
    guint64 id;
    gchar *name;
    gchar *icon;
    guint64 owner;

    GArray *members;           /* list of member ids */
    GHashTable *nicknames;     /* id->nick? */
    GHashTable *nicknames_rev; /* reverse */
} GroupMeGuild;

typedef struct {
    guint64 id;
    gchar *nick;
    gboolean is_op;
} GroupMeGuildMembership;

typedef struct {
    guint64 id;
    gchar *id_s;
    gchar *name;
    gchar *avatar;
    GHashTable *guild_memberships;
    gboolean bot;
} GroupMeUser;

typedef struct {
    PurpleAccount *account;
    PurpleConnection *pc;

    GHashTable *cookie_table;
    gchar *session_token;
    gchar *channel;
    guint64 self_user_id;
    gchar *self_username;

    guint64 last_message_id;
    gint64 last_load_last_message_id;

    gchar *token;
    gchar *session_id;
    gchar *mfa_ticket;

    PurpleSslConnection *websocket;
    gboolean websocket_header_received;
    gboolean sync_complete;
    guchar packet_code;
    gchar *frame;
    guint64 frame_len;
    guint64 frame_len_progress;

    gint64 seq; /* incrementing counter */
    guint heartbeat_timeout;
    guint long_poller;

    GHashTable *one_to_ones;        /* A store of known room_id's -> username's */
    GHashTable *one_to_ones_rev;    /* A store of known usernames's -> room_id's */
    GHashTable *last_message_id_dm; /* A store of known room_id's -> last_message_id's */
    GHashTable *sent_message_ids;   /* A store of message id's that we generated from this instance */
    GHashTable *result_callbacks;   /* Result ID -> Callback function */
    GQueue *received_message_queue; /* A store of the last 10 received message id's for de-dup */

    GHashTable *new_users;
    GHashTable *new_guilds;

    GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
    gint frames_since_reconnect;
    GSList *pending_writes;
    gint roomlist_guild_count;

    gchar *client_id;

    int push_id;
} GroupMeAccount;

typedef struct {
    GroupMeAccount *account;
    GroupMeGuild *guild;
} GroupMeAccountGuild;

static guint64
to_int(const gchar *id)
{
    return id ? g_ascii_strtoull(id, NULL, 10) : 0;
}

static gchar *
from_int(guint64 id)
{
    return g_strdup_printf("%" G_GUINT64_FORMAT, id);
}

/** libpurple requires unique chat id's per conversation.
    we use a hash function to convert the 64bit conversation id
    into a platform-dependent chat id (worst case 32bit).
    previously we used g_int64_hash() from glib,
    however libpurple requires positive integers */
static gint
groupme_chat_hash(guint64 chat_id)
{
    return ABS((gint) chat_id);
}

static void groupme_free_guild_membership(gpointer data);

/* creating */

static GroupMeUser *
groupme_new_user(JsonObject *json)
{
    GroupMeUser *user = g_new0(GroupMeUser, 1);

    user->id_s = json_object_get_string_member(json, "user_id");

    if (!user->id_s)
        user->id_s = json_object_get_string_member(json, "id");

    user->id = to_int(user->id_s);

    user->name = json_object_get_string_member(json, "nickname");

    if (!user->name)
        user->name = json_object_get_string_member(json, "name");

    user->avatar = g_strdup(json_object_get_string_member(json, "image_url"));

    user->name = g_strdup(user->name);
    user->id_s = g_strdup(user->id_s);

    user->guild_memberships = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_guild_membership);

    return user;
}

static GroupMeGuild *
groupme_new_guild(JsonObject *json)
{
    GroupMeGuild *guild = g_new0(GroupMeGuild, 1);

    guild->id = to_int(json_object_get_string_member(json, "id"));
    guild->name = g_strdup(json_object_get_string_member(json, "name"));
    guild->icon = g_strdup(json_object_get_string_member(json, "image_url"));
    guild->members = g_array_new(TRUE, TRUE, sizeof(guint64));

    guild->nicknames = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    guild->nicknames_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    return guild;
}

static GroupMeGuildMembership *
groupme_new_guild_membership(guint64 id, JsonObject *json)
{
    GroupMeGuildMembership *guild_membership = g_new0(GroupMeGuildMembership, 1);

    guild_membership->id = id;

    /* Search for op roles */
    JsonArray *roles = json_object_get_array_member(json, "roles");

    gint i, len = json_array_get_length(roles);
    guild_membership->is_op = FALSE;

    for (i = len - 1; i >= 0; i--) {
        const gchar *role = json_array_get_string_element(roles, i);

        if ((g_strcmp0(role, "admin") == 0) || (g_strcmp0(role, "op") == 0)) {
            guild_membership->is_op = TRUE;
            break;
        }
    }


    return guild_membership;
}

/* freeing */

static void
groupme_free_guild_membership(gpointer data)
{
    GroupMeGuildMembership *guild_membership = data;
    g_free(guild_membership->nick);

    g_free(guild_membership);
}

static void
groupme_free_user(gpointer data)
{
    GroupMeUser *user = data;
    g_free(user->name);
    g_free(user->avatar);

    g_hash_table_unref(user->guild_memberships);
    g_free(user);
}

static void
groupme_free_guild(gpointer data)
{
    GroupMeGuild *guild = data;
    g_free(guild->name);
    g_free(guild->icon);

    g_array_unref(guild->members);
    g_hash_table_unref(guild->nicknames);
    g_hash_table_unref(guild->nicknames_rev);
    g_free(guild);
}

static void groupme_start_socket(GroupMeAccount *ya);

static void
groupme_got_subscription(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    /* We're good to go */
    groupme_start_socket(da);
}

typedef void (*GroupMeProxyCallbackFunc)(GroupMeAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
    GroupMeAccount *ya;
    GroupMeProxyCallbackFunc callback;
    gpointer user_data;
} GroupMeProxyConnection;

static void groupme_fetch_url(GroupMeAccount *da, const gchar *url, const gchar *postdata, GroupMeProxyCallbackFunc callback, gpointer user_data);

static void
groupme_got_handshake(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    if (node != NULL) {
        JsonArray *responseA = json_node_get_array(node);
        JsonObject *response = json_array_get_object_element(responseA, 0);

        if (json_object_has_member(response, "successful")) {
            const gchar *clientId = json_object_get_string_member(response, "clientId");
            da->client_id = g_strdup(clientId);

            /* Subscribe now */
            const gchar *str = g_strdup_printf(
                    "{\"channel\": \"/meta/subscribe\", \"clientId\": \"%s\", \"subscription\": \"/user/%" G_GUINT64_FORMAT "\", \"ext\": {\"timestamp\": %" G_GUINT64_FORMAT ", \"access_token\": \"%s\"}, \"id\": 2}",
                    clientId,
                    da->self_user_id,
                    time(NULL),
                    da->token);

            da->push_id = 3;

            groupme_fetch_url(da, "https://" GROUPME_PUSH_SERVER, str, groupme_got_subscription, NULL);
        }
    }
}

static GroupMeUser *
groupme_get_user_name(GroupMeAccount *da, int discriminator, gchar *name)
{
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, da->new_users);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        GroupMeUser *user = value;

        if (/*user->discriminator == discriminator && */purple_strequal(user->name, name)) {
            return value;
        }
    }

    return NULL;
}

static GroupMeUser *
groupme_get_user_fullname(GroupMeAccount *da, const gchar *name)
{
    g_return_val_if_fail(name && *name, NULL);

    gchar **split_name = g_strsplit(name, "#", 2);
    GroupMeUser *user = NULL;

    if (split_name != NULL) {
        if (split_name[0] && split_name[1]) {
            user = groupme_get_user_name(da, to_int(split_name[1]), split_name[0]);
        }

        g_strfreev(split_name);
    }

    return user;
}
static GroupMeUser *
groupme_get_user(GroupMeAccount *da, guint64 id)
{
    return g_hash_table_lookup_int64(da->new_users, id);
}

static GroupMeUser *
groupme_upsert_user(GHashTable *user_table, JsonObject *json)
{
    const gchar *suid = json_object_get_string_member(json, "user_id");

    if (!suid)
        suid = json_object_get_string_member(json, "id");

    guint64 *key = NULL, user_id = to_int(suid);
    GroupMeUser *user = NULL;

    if (g_hash_table_lookup_extended_int64(user_table, user_id, (gpointer) &key, (gpointer) &user)) {
        return user;
    } else {
        user = groupme_new_user(json);
        g_hash_table_replace_int64(user_table, user->id, user);
        return user;
    }
}

static gchar *
groupme_alloc_nickname(GroupMeUser *user, GroupMeGuild *guild, const gchar *suggested_nick)
{
    const gchar *base_nick = suggested_nick ? suggested_nick : user->name;
    gchar *nick = NULL;

    if (base_nick == NULL) {
        return NULL;
    }

    guint64 *existing = g_hash_table_lookup(guild->nicknames_rev, base_nick);

    if (existing && *existing != user->id) {
        /* Ambiguous; try with the real name */

        nick = g_strdup_printf("%s (%s)", base_nick, user->name);

        existing = g_hash_table_lookup(guild->nicknames_rev, nick);

        if (existing && *existing != user->id) {
            /* Ambiguous; use the UUID */

            g_free(nick);
            nick = g_strdup_printf("%s (%" G_GUINT64_FORMAT ")", base_nick, user->id);
        }
    }

    if (!nick) {
        nick = g_strdup(base_nick);
    }

    g_hash_table_replace_int64(guild->nicknames, user->id, g_strdup(nick));
    g_hash_table_replace(guild->nicknames_rev, g_strdup(nick), g_memdup(&user->id, sizeof(user->id)));

    return nick;
}

static GroupMeGuild *
groupme_get_guild(GroupMeAccount *da, guint64 id)
{
    return g_hash_table_lookup_int64(da->new_guilds, id);
}

static GroupMeGuild *
groupme_upsert_guild(GHashTable *guild_table, JsonObject *json)
{
    guint64 *key = NULL, guild_id = to_int(json_object_get_string_member(json, "id"));
    GroupMeGuild *guild = NULL;

    if (g_hash_table_lookup_extended_int64(guild_table, guild_id, (gpointer) &key, (gpointer) &guild)) {
        return guild;
    } else {
        guild = groupme_new_guild(json);
        g_hash_table_replace_int64(guild_table, guild->id, guild);
        return guild;
    }
}

PurpleChatUserFlags
groupme_get_user_flags(GroupMeAccount *da, GroupMeGuild *guild, GroupMeUser *user)
{
    if (user == NULL) {
        return PURPLE_CHAT_USER_NONE;
    }

    guint64 gid = guild->id;
    GroupMeGuildMembership *guild_membership = g_hash_table_lookup_int64(user->guild_memberships, gid);
    PurpleChatUserFlags best_flag = user->bot ? PURPLE_CHAT_USER_VOICE : PURPLE_CHAT_USER_NONE;

    if (guild_membership == NULL)
        return best_flag;

    if (guild_membership->is_op)
        return PURPLE_CHAT_USER_OP;

    return best_flag;
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
static void
groupme_update_cookies(GroupMeAccount *ya, const GList *cookie_headers)
{
    const gchar *cookie_start;
    const gchar *cookie_end;
    gchar *cookie_name;
    gchar *cookie_value;
    const GList *cur;

    for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur)) {
        cookie_start = cur->data;

        cookie_end = strchr(cookie_start, '=');

        if (cookie_end != NULL) {
            cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
            cookie_start = cookie_end + 1;
            cookie_end = strchr(cookie_start, ';');

            if (cookie_end != NULL) {
                cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
                cookie_start = cookie_end;

                g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
            }
        }
    }
}

#else
static void
groupme_update_cookies(GroupMeAccount *ya, const gchar *headers)
{
    const gchar *cookie_start;
    const gchar *cookie_end;
    gchar *cookie_name;
    gchar *cookie_value;
    int header_len;

    g_return_if_fail(headers != NULL);

    header_len = strlen(headers);

    /* look for the next "Set-Cookie: " */
    /* grab the data up until ';' */
    cookie_start = headers;

    while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len) {
        cookie_start += 14;
        cookie_end = strchr(cookie_start, '=');

        if (cookie_end != NULL) {
            cookie_name = g_strndup(cookie_start, cookie_end - cookie_start);
            cookie_start = cookie_end + 1;
            cookie_end = strchr(cookie_start, ';');

            if (cookie_end != NULL) {
                cookie_value = g_strndup(cookie_start, cookie_end - cookie_start);
                cookie_start = cookie_end;

                g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
            }
        }
    }
}
#endif

static void
groupme_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
    g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
groupme_cookies_to_string(GroupMeAccount *ya)
{
    GString *str;

    str = g_string_new(NULL);

    g_hash_table_foreach(ya->cookie_table, (GHFunc) groupme_cookie_foreach_cb, str);

    return g_string_free(str, FALSE);
}

static void
groupme_response_callback(PurpleHttpConnection *http_conn,
#if PURPLE_VERSION_CHECK(3, 0, 0)
                          PurpleHttpResponse *response, gpointer user_data)
{
    gsize len;
    const gchar *url_text = purple_http_response_get_data(response, &len);
    const gchar *error_message = purple_http_response_get_error(response);
#else
                          gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
    const gchar *body;
    gsize body_len;
    GroupMeProxyConnection *conn = user_data;
    JsonParser *parser = json_parser_new();

    conn->ya->http_conns = g_slist_remove(conn->ya->http_conns, http_conn);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
    groupme_update_cookies(conn->ya, url_text);

    body = g_strstr_len(url_text, len, "\r\n\r\n");
    body = body ? body + 4 : body;
    body_len = len - (body - url_text);
#else
    groupme_update_cookies(conn->ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

    body = url_text;
    body_len = len;
#endif

    if (body == NULL && error_message != NULL) {
        /* connection error - unersolvable dns name, non existing server */
        gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
        purple_connection_error(conn->ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
        g_free(error_msg_formatted);
        g_free(conn);
        return;
    }

    if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
        purple_debug_info("groupme", "Unparseable body\n");
        if (conn->callback) {
            JsonNode *dummy_node = json_node_new(JSON_NODE_OBJECT);
            JsonObject *dummy_object = json_object_new();

            json_node_set_object(dummy_node, dummy_object);
            json_object_set_string_member(dummy_object, "body", body);
            json_object_set_int_member(dummy_object, "len", body_len);
            g_dataset_set_data(dummy_node, "raw_body", (gpointer) body);

            conn->callback(conn->ya, dummy_node, conn->user_data);

            g_dataset_destroy(dummy_node);
            json_node_free(dummy_node);
            json_object_unref(dummy_object);
        }
    } else {
        JsonNode *root = json_parser_get_root(parser);

        purple_debug_misc("groupme", "Got response: %s\n", body);

        if (conn->callback) {
            conn->callback(conn->ya, root, conn->user_data);
        }
    }

    g_object_unref(parser);
    g_free(conn);
}

static void
groupme_fetch_url_with_method(GroupMeAccount *ya, const gchar *method, const gchar *_url, const gchar *postdata, GroupMeProxyCallbackFunc callback, gpointer user_data)
{
    PurpleAccount *account;
    GroupMeProxyConnection *conn;
    gchar *cookies;
    PurpleHttpConnection *http_conn;

    account = ya->account;

    if (purple_account_is_disconnected(account)) {
        return;
    }

    conn = g_new0(GroupMeProxyConnection, 1);
    conn->ya = ya;
    conn->callback = callback;
    conn->user_data = user_data;

    cookies = groupme_cookies_to_string(ya);

    if (method == NULL) {
        method = "GET";
    }

    /* Attach token to requests */
    gchar *url = g_strdup(_url);

    if (ya->token) {
        g_free(url);
        url = g_strdup_printf("%s&token=%s", _url, ya->token);
    }

    purple_debug_info("groupme", "Fetching url %s\n", url);

#if PURPLE_VERSION_CHECK(3, 0, 0)

    PurpleHttpRequest *request = purple_http_request_new(url);
    purple_http_request_set_method(request, method);
    purple_http_request_header_set(request, "Accept", "*/*");
    purple_http_request_header_set(request, "User-Agent", GROUPME_USERAGENT);
    purple_http_request_header_set(request, "Cookie", cookies);

    if (postdata) {
        if (strstr(url, "/login") && strstr(postdata, "password")) {
            purple_debug_info("groupme", "With postdata ###PASSWORD REMOVED###\n");
        } else {
            purple_debug_info("groupme", "With postdata %s\n", postdata);
        }

        if (postdata[0] == '{') {
            purple_http_request_header_set(request, "Content-Type", "application/json");
        } else {
            purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
        }

        purple_http_request_set_contents(request, postdata, -1);
    }

    http_conn = purple_http_request(ya->pc, request, groupme_response_callback, conn);
    purple_http_request_unref(request);

    if (http_conn != NULL) {
        ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);
    }

#else
    GString *headers;
    gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
    int port;
    purple_url_parse(url, &host, &port, &path, &user, &password);

    headers = g_string_new(NULL);

    /* Use the full 'url' until libpurple can handle path's longer than 256 chars */
    g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", method, path);
    g_string_append_printf(headers, "Connection: close\r\n");
    g_string_append_printf(headers, "Host: %s\r\n", host);
    g_string_append_printf(headers, "Accept: */*\r\n");
    g_string_append_printf(headers, "User-Agent: " GROUPME_USERAGENT "\r\n");
    g_string_append_printf(headers, "Cookie: %s\r\n", cookies);

    if (postdata) {
        if (strstr(url, "/login") && strstr(postdata, "password")) {
            purple_debug_info("groupme", "With postdata ###PASSWORD REMOVED###\n");
        } else {
            purple_debug_info("groupme", "With postdata %s\n", postdata);
        }

        if (postdata[0] == '{') {
            g_string_append(headers, "Content-Type: application/json\r\n");
        } else {
            g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
        }

        g_string_append_printf(headers, "Content-Length: %" G_GSIZE_FORMAT "\r\n", strlen(postdata));
        g_string_append(headers, "\r\n");

        g_string_append(headers, postdata);
    } else {
        g_string_append(headers, "\r\n");
    }

    g_free(host);
    g_free(path);
    g_free(user);
    g_free(password);

    http_conn = purple_util_fetch_url_request_len_with_account(ya->account, url, TRUE, GROUPME_USERAGENT, TRUE, headers->str, TRUE, 6553500, groupme_response_callback, conn);

    if (http_conn != NULL) {
        ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);
    }

    g_string_free(headers, TRUE);
#endif

    g_free(cookies);
    g_free(url);
}

static void
groupme_fetch_url(GroupMeAccount *da, const gchar *url, const gchar *postdata, GroupMeProxyCallbackFunc callback, gpointer user_data)
{
    groupme_fetch_url_with_method(da, (postdata ? "POST" : "GET"), url, postdata, callback, user_data);
}

static void groupme_socket_write_json(GroupMeAccount *ya, JsonObject *data);
static GHashTable *groupme_chat_info_defaults(PurpleConnection *pc, const char *chatname);
static void groupme_mark_room_messages_read(GroupMeAccount *ya, guint64 room_id);

static void groupme_init_push(GroupMeAccount *da);

static guint64
groupme_process_message(GroupMeAccount *da, int channel, JsonObject *data, gboolean is_dm);

static void
groupme_got_push(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    purple_debug_info("groupme", "Got push %d\n", (da->push_id - 1));
    if (node == NULL) {
        printf("Null node. Hoo-haa!\n");
        purple_connection_error(da->pc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Got a push, but no data");
        return;
    }

    if (JSON_NODE_HOLDS_OBJECT(node)) {
        JsonObject *maybe_dummy = json_node_get_object(node);
        if (json_object_has_member(maybe_dummy, "body")) {
            purple_debug_info("groupme", "Unexpected response: %s\n", json_object_get_string_member(maybe_dummy, "body"));
        }
        purple_connection_error(da->pc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Got a push, but data is unparseable.");
        return;
    }

    JsonArray *subscriptions = json_node_get_array(node);

    guint len = json_array_get_length(subscriptions);


    for (int i = len - 1; i >= 0; i--) {
        JsonObject *sub = json_array_get_object_element(subscriptions, i);

        /* Actuate the new response */
        if (!json_object_has_member(sub, "data"))
            continue;

        JsonObject *data = json_object_get_object_member(sub, "data");

        if (!json_object_has_member(data, "subject"))
            continue;

        JsonObject *subj = json_object_get_object_member(data, "subject");

        const gchar *type = json_object_get_string_member(data, "type");

        if (g_strcmp0(type, "line.create") == 0) {
            /* Incoming message */

            int gid = to_int(json_object_get_string_member(subj, "group_id"));
            groupme_process_message(da, gid, subj, FALSE);
        } else if (g_strcmp0(type, "direct_message.create") == 0) {
            /* Direct message: either our sent message or theirs */
            int sid = to_int(json_object_get_string_member(subj, "sender_id"));
            int rid = to_int(json_object_get_string_member(subj, "recipient_id"));

            /* Sometimes we receive our own messages, account for that */
            int channel = sid == da->self_user_id ? rid : sid;

            groupme_process_message(da, channel, subj, TRUE);
        } else {
            printf("Unknown type %s, check debug logs\n", type);
        }
    }

#ifdef USE_LONG_POLL
    /* Long polling consists of repeated reqeusts to the push server */
    groupme_init_push(da);
#endif
}

static void
groupme_init_push(GroupMeAccount *da)
{
    JsonObject *data = json_object_new();

    json_object_set_string_member(data, "channel", "/meta/connect");
    json_object_set_string_member(data, "clientId", da->client_id);
    json_object_set_string_member(data, "connectionType", GROUPME_PUSH_TYPE);

    gchar *id = from_int(da->push_id++);
    json_object_set_string_member(data, "id", id);

    purple_debug_info("groupme", "Sending push %s\n", id);
#ifdef USE_LONG_POLL
    groupme_fetch_url(da, "https://" GROUPME_PUSH_SERVER, json_object_to_string(data), groupme_got_push, NULL);
#else
    groupme_socket_write_json(da, data);
#endif
    json_object_unref(data);
    g_free(id);
}

void groupme_handle_add_new_user(GroupMeAccount *ya, JsonObject *obj);

PurpleGroup *groupme_get_or_create_group(const gchar *name);

static void groupme_got_history_static(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_history_of_room(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_populate_guild(GroupMeAccount *da, JsonObject *guild);
static void groupme_got_guilds(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_chats(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_avatar(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_get_avatar(GroupMeAccount *da, GroupMeUser *user);

static const gchar *groupme_normalise_room_name(const gchar *guild_name, const gchar *name);
static GroupMeGuild *groupme_open_chat(GroupMeAccount *da, guint64 id, gchar *name, gboolean present);

static void
groupme_create_associate(GroupMeAccount *da, guint64 id)
{
    gchar *id_s = from_int(id);

    /* First, check to see if we already are associated */
    PurpleBuddy *buddy = purple_find_buddy(da->account, id_s);

    /* If not, associate */

    if (!buddy) {
        GroupMeUser *user = groupme_get_user(da, id);

        if (!user) {
            printf("Not associating with unknown user %d\n", id);
            return;
        }

        buddy = purple_buddy_new(da->account, id_s, user->name);
        purple_blist_add_buddy(buddy, NULL, groupme_get_or_create_group("GroupMe"), NULL);

        /* Bring it up */
        purple_protocol_got_user_status(da->account, id_s, "online", NULL);

        groupme_get_avatar(da, user);
    }
}

static gchar *
groupme_get_real_name(PurpleConnection *pc, gint id, const char *who)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    PurpleChatConversation *chatconv;

    chatconv = purple_conversations_find_chat(pc, id);
    guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

    if (!room_id_ptr) {
        goto bail;
    }

    guint64 room_id = *room_id_ptr;

    GroupMeGuild *channel = groupme_get_guild(da, room_id);

    if (!channel)
        goto bail;

    guint64 *uid = g_hash_table_lookup(channel->nicknames_rev, who);

    if (uid) {
        groupme_create_associate(da, *uid);
        return from_int(*uid);
    }

/* Probably a fullname already, bail out */
bail:
    return g_strdup(who);
}

static guint64
groupme_process_message(GroupMeAccount *da, int channel, JsonObject *data, gboolean is_dm)
{
    const gchar *guid = json_object_get_string_member(data, "source_guid");
    guint64 author_id = to_int(json_object_get_string_member(data, "sender_id"));

    const gchar *content = json_object_get_string_member(data, "text");
    // Turns out, groupme just gives us an int, no need to create from a string
    // anymore
    time_t timestamp = json_object_get_int_member(data, "created_at");
    // this is how we used to do that
    // time_t timestamp = purple_str_to_time(timestamp_str, FALSE, NULL, NULL, NULL);

    JsonArray *attachments = json_object_get_array_member(data, "attachments");

    PurpleMessageFlags flags;
    gchar *tmp;
    gint i;

    /* Drop our own messages that were pinged back to us */
	if ((author_id == da->self_user_id) && g_hash_table_remove(da->sent_message_ids, guid))
		return;

    if (author_id == da->self_user_id && is_dm) {
        flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
    } else {
        flags = PURPLE_MESSAGE_RECV;
    }

    if (is_dm) {
        /* private message */

        if (author_id == da->self_user_id) {
            PurpleConversation *conv;
            PurpleIMConversation *imconv;
            PurpleMessage *msg;

            gchar *username = groupme_get_user(da, channel)->id_s;
            imconv = purple_conversations_find_im_with_account(username, da->account);

            if (imconv == NULL) {
                imconv = purple_im_conversation_new(da->account, username);
            }

            conv = PURPLE_CONVERSATION(imconv);

            if (content && *content) {
                msg = purple_message_new_outgoing(username, content, flags);
                purple_message_set_time(msg, timestamp);
                purple_conversation_write_message(conv, msg);
                purple_message_destroy(msg);
            }

            if (attachments) {
                for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
                    JsonObject *attachment = json_array_get_object_element(attachments, i);
                    const gchar *url = json_object_get_string_member(attachment, "url");

                    msg = purple_message_new_outgoing(username, url, flags);
                    purple_message_set_time(msg, timestamp);
                    purple_conversation_write_message(conv, msg);
                    purple_message_destroy(msg);
                }
            }
        } else {
            GroupMeUser *author = groupme_upsert_user(da->new_users, data);
            gchar *merged_username = author->id_s;

            if (content && *content) {
                purple_serv_got_im(da->pc, merged_username, content, flags, timestamp);
            }

            if (attachments) {
                for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
                    JsonObject *attachment = json_array_get_object_element(attachments, i);
                    const gchar *url = json_object_get_string_member(attachment, "url");

                    purple_serv_got_im(da->pc, merged_username, url, flags, timestamp);
                }
            }
        }
    } else {
        /* Open the buffer if it's not already */
        groupme_open_chat(da, channel, NULL, FALSE);

        gchar *name = json_object_get_string_member(data, "name");

        if (content && *content) {
            purple_serv_got_chat_in(da->pc, groupme_chat_hash(channel), name, flags, content, timestamp);
        }

        if (attachments) {
            for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
                JsonObject *attachment = json_array_get_object_element(attachments, i);

                if (json_object_has_member(attachment, "url")) {
                    const gchar *url = json_object_get_string_member(attachment, "url");
                    purple_serv_got_chat_in(da->pc, groupme_chat_hash(channel), name, flags, url, timestamp);
                }
            }
        }
    }

    return 1;
}

struct groupme_group_typing_data {
    GroupMeAccount *da;
    guint64 channel_id;
    gchar *username;
    gboolean set;
    gboolean free_me;
};

static gboolean
groupme_set_group_typing(void *_u)
{
    if (_u == NULL) {
        return FALSE;
    }

    struct groupme_group_typing_data *ctx = _u;

    PurpleChatConversation *chatconv = purple_conversations_find_chat(ctx->da->pc, groupme_chat_hash(ctx->channel_id));

    if (chatconv == NULL) {
        goto release_ctx;
    }

    PurpleChatUser *cb = purple_chat_conversation_find_user(chatconv, ctx->username);

    if (!cb) {
        goto release_ctx;
    }

    PurpleChatUserFlags cbflags;

    cbflags = purple_chat_user_get_flags(cb);

    if (ctx->set) {
        cbflags |= PURPLE_CHAT_USER_TYPING;
    } else {
        cbflags &= ~PURPLE_CHAT_USER_TYPING;
    }

    purple_chat_user_set_flags(cb, cbflags);

release_ctx:

    if (ctx->free_me) {
        g_free(ctx->username);
        g_free(ctx);
    }

    return FALSE;
}

static void
groupme_got_nick_change(GroupMeAccount *da, GroupMeUser *user, GroupMeGuild *guild, const gchar *new, const gchar *old, gboolean self)
{
    gchar *old_safe = g_strdup(old);

    if (old) {
        g_hash_table_remove(guild->nicknames_rev, old);
    }

    /* Nick change */
    gchar *nick = groupme_alloc_nickname(user, guild, new);

    /* Propagate through the guild, see e.g. irc_msg_nick */
    GHashTableIter channel_iter;
    gpointer key, value;

    /* TODO: Nick */
    PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, groupme_chat_hash(guild->id));

    if (chat && purple_chat_conversation_has_user(chat, old_safe)) {
        purple_chat_conversation_rename_user(chat, old_safe, nick);
    }

    g_free(nick);
}

PurpleChat *
groupme_bring_up_buddies(PurpleAccount *account)
{
    PurpleBlistNode *node;
    GSList *lst = purple_find_buddies(account, NULL);

    while (lst) {
        PurpleBuddy *buddy = (PurpleBuddy *) lst->data;
        purple_protocol_got_user_status(account, buddy->name, "online", NULL);
        purple_protocol_got_user_idle(account, buddy->name, 0, 0);
        lst = g_slist_delete_link(lst, lst);
    }

    return NULL;
}

PurpleChat *
groupme_find_chat_from_node(PurpleAccount *account, const char *id, PurpleBlistNode *root)
{
    PurpleBlistNode *node;

    for (node = root;
         node != NULL;
         node = purple_blist_node_next(node, TRUE)) {
        if (PURPLE_IS_CHAT(node)) {
            PurpleChat *chat = PURPLE_CHAT(node);

            if (purple_chat_get_account(chat) != account) {
                continue;
            }

            GHashTable *components = purple_chat_get_components(chat);
            const gchar *chat_id = g_hash_table_lookup(components, "id");

            if (purple_strequal(chat_id, id)) {
                return chat;
            }
        }
    }

    return NULL;
}

PurpleChat *
groupme_find_chat(PurpleAccount *account, const char *id)
{
    return groupme_find_chat_from_node(account, id, purple_blist_get_root());
}


PurpleChat *
groupme_find_chat_in_group(PurpleAccount *account, const char *id, PurpleGroup *group)
{
    g_return_val_if_fail(group != NULL, NULL);

    return groupme_find_chat_from_node(account, id, PURPLE_BLIST_NODE(group));
}


static void
groupme_add_channel_to_blist(GroupMeAccount *da, GroupMeGuild *channel, PurpleGroup *group)
{
    GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    gchar *id = from_int(channel->id);

    g_hash_table_replace(components, g_strdup("id"), id);
    g_hash_table_replace(components, g_strdup("name"), g_strdup(channel->name));

    /* Don't re-add the channel to the same group */

    if (groupme_find_chat_in_group(da->account, id, group) == NULL) {
        PurpleChat *chat = purple_chat_new(da->account, channel->name, components);
        purple_blist_add_chat(chat, group, NULL);
    } else {
        g_hash_table_unref(components);
    }
}

PurpleGroup *
groupme_get_or_create_group(const gchar *name)
{
    PurpleGroup *groupme_group = purple_blist_find_group(name);

    if (!groupme_group) {
        groupme_group = purple_group_new(name);
        purple_blist_add_group(groupme_group, NULL);
    }

    return groupme_group;
}

static const gchar *
groupme_normalise_room_name(const gchar *guild_name, const gchar *name)
{
    gchar *channel_name = g_strconcat(guild_name, "#", name, NULL);
    static gchar *old_name = NULL;

    g_free(old_name);
    old_name = g_ascii_strdown(channel_name, -1);
    purple_util_chrreplace(old_name, ' ', '_');
    g_free(channel_name);

    return old_name;
}

static gchar *
groupme_roomlist_serialize(PurpleRoomlistRoom *room)
{
    GList *fields = purple_roomlist_room_get_fields(room);
    const gchar *id = (const gchar *) fields->data;

    return g_strdup(id);
}

PurpleRoomlist *
groupme_roomlist_get_list(PurpleConnection *pc)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    PurpleRoomlist *roomlist;
    GList *fields = NULL;
    PurpleRoomlistField *f;

    roomlist = purple_roomlist_new(da->account);

    f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "id", TRUE);
    fields = g_list_append(fields, f);

    purple_roomlist_set_fields(roomlist, fields);
    purple_roomlist_set_in_progress(roomlist, TRUE);

    GHashTableIter iter;
    gpointer key, guild;

    g_hash_table_iter_init(&iter, da->new_guilds);

    while (g_hash_table_iter_next(&iter, &key, &guild)) {
        GroupMeGuild *g = (GroupMeGuild *) guild;

        PurpleRoomlistRoom *room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, g->name, NULL);
        gchar *channel_id = from_int(g->id);

        purple_roomlist_room_add_field(roomlist, room, channel_id);
        purple_roomlist_room_add(roomlist, room);

        g_free(channel_id);
    }

    purple_roomlist_set_in_progress(roomlist, FALSE);

    return roomlist;
}

static void
groupme_restart_channel(GroupMeAccount *da)
{
    purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTING);
    groupme_start_socket(da);
}

static guint groupme_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, GroupMeAccount *ya);
static gulong chat_conversation_typing_signal = 0;
static void groupme_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);
static gulong conversation_updated_signal = 0;

typedef struct {
    GroupMeAccount *da;
    GroupMeUser *user;
} GroupMeUserInviteResponseStore;

static void
groupme_populate_guild(GroupMeAccount *da, JsonObject *guild)
{
    GroupMeGuild *g = groupme_upsert_guild(da->new_guilds, guild);
    gchar *name = json_object_get_string_member(guild, "name");

    /* Add chat to blist */
    PurpleGroup *group = groupme_get_or_create_group("GroupMe Chats");
    groupme_add_channel_to_blist(da, g, group);

    JsonArray *members = json_object_get_array_member(guild, "members");

    /* Populate members */
    for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
        JsonObject *member = json_array_get_object_element(members, j);

        GroupMeUser *u = groupme_upsert_user(da->new_users, member);
        g_array_append_val(g->members, u->id);

        GroupMeGuildMembership *membership = groupme_new_guild_membership(g->id, member);
        g_hash_table_replace_int64(u->guild_memberships, g->id, membership);

        membership->nick = groupme_alloc_nickname(u, g, json_object_get_string_member(member, "nickname"));
    }
}

static void
groupme_got_guilds(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonObject *container = json_node_get_object(node);
    JsonArray *guilds = json_object_get_array_member(container, "response");
    guint len = json_array_get_length(guilds);

    for (int i = len - 1; i >= 0; i--) {
        JsonObject *guild = json_array_get_object_element(guilds, i);
        groupme_populate_guild(da, guild);
    }
}

static void
groupme_got_chats(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonObject *container = json_node_get_object(node);
    JsonArray *chats = json_object_get_array_member(container, "response");
    guint len = json_array_get_length(chats);

    for (int i = len - 1; i >= 0; i--) {
        JsonObject *chat = json_array_get_object_element(chats, i);
        JsonObject *msg = json_object_get_object_member(chat, "last_message");
        JsonObject *other = json_object_get_object_member(chat, "other_user");
        const gchar *chan = json_object_get_string_member(other, "id");

        /* TODO: Actually fetch history, rolling, save counts, etc */
        groupme_upsert_user(da->new_users, other);
        groupme_process_message(da, to_int(chan), msg, TRUE);
    }
}

static void
groupme_got_self(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonObject *container = json_node_get_object(node);
    JsonObject *resp = json_object_get_object_member(container, "response");
    if (json_object_has_member(container, "meta")) {
        JsonObject *meta = json_object_get_object_member(container, "meta");
        if (json_object_has_member(meta, "code")) {
            guint code = json_object_get_int_member(meta, "code");
            if (code == 401) {
                purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(meta, "errors"));
                return;
            }
        }
    }

    da->self_user_id = to_int(json_object_get_string_member(resp, "id"));
    da->self_username = g_strdup(json_object_get_string_member(resp, "name"));

    /* Now that we have the user ID, we can start the websocket handshake */
    {
        const gchar *str = "{\"channel\": \"/meta/handshake\", \"version\": \"1.0\", \"supportedConnectionTypes\": [\"" GROUPME_PUSH_TYPE "\"], \"id\": 1}";
        groupme_fetch_url(da, "https://" GROUPME_PUSH_SERVER, str, groupme_got_handshake, NULL);
    }

}

static void groupme_login_response(GroupMeAccount *da, JsonNode *node, gpointer user_data);

static void
groupme_mfa_text_entry(gpointer user_data, const gchar *code)
{
    GroupMeAccount *da = user_data;
    JsonObject *data = json_object_new();
    gchar *str;

    json_object_set_string_member(data, "code", code);
    json_object_set_string_member(data, "ticket", da->mfa_ticket);

    str = json_object_to_string(data);
    groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/api/v6/auth/mfa/totp", str, groupme_login_response, NULL);

    g_free(str);
    json_object_unref(data);

    g_free(da->mfa_ticket);
    da->mfa_ticket = NULL;
}

static void
groupme_mfa_cancel(gpointer user_data)
{
    GroupMeAccount *da = user_data;

    purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Cancelled 2FA auth"));
}

static void
groupme_login_response(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{

    if (node != NULL) {
        JsonObject *response = json_node_get_object(node);


        da->token = g_strdup(json_object_get_string_member(response, "token"));

        purple_account_set_string(da->account, "token", da->token);

        if (da->token) {
            groupme_start_socket(da);
            return;
        }

        if (json_object_get_boolean_member(response, "mfa")) {
            g_free(da->mfa_ticket);
            da->mfa_ticket = g_strdup(json_object_get_string_member(response, "ticket"));

            purple_request_input(da->pc, _("Two-factor authentication"),
                                 _("Enter GroupMe auth code"),
                                 _("You can get this token from your two-factor authentication mobile app."),
                                 NULL, FALSE, FALSE, "",
                                 _("_Login"), G_CALLBACK(groupme_mfa_text_entry),
                                 _("_Cancel"), G_CALLBACK(groupme_mfa_cancel),
                                 purple_request_cpar_from_connection(da->pc),
                                 da);
            return;
        }

        if (json_object_has_member(response, "email")) {
            /* Probably an error about new location */
            purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "email"));
            return;
        }

        if (json_object_has_member(response, "password")) {
            /* Probably an error about bad password */
            purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "password"));
            return;
        }
    }

    purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Bad username/password"));
}

void
groupme_login(PurpleAccount *account)
{
    GroupMeAccount *da;
    PurpleConnection *pc = purple_account_get_connection(account);
    PurpleConnectionFlags pc_flags;

    pc_flags = purple_connection_get_flags(pc);
    pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
    pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
    pc_flags |= PURPLE_CONNECTION_FLAG_NO_IMAGES;
    purple_connection_set_flags(pc, pc_flags);

    da = g_new0(GroupMeAccount, 1);
    purple_connection_set_protocol_data(pc, da);
    da->account = account;
    da->pc = pc;
    da->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    da->last_load_last_message_id = purple_account_get_int(account, "last_message_id_high", 0);

    if (da->last_load_last_message_id != 0) {
        da->last_load_last_message_id = (da->last_load_last_message_id << 32) | ((guint64) purple_account_get_int(account, "last_message_id_low", 0) & 0xFFFFFFFF);
    }

    da->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    da->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    da->last_message_id_dm = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    da->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
    da->result_callbacks = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    da->received_message_queue = g_queue_new();

    /* TODO make these the roots of all groupme data */
    da->new_users = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_user);
    da->new_guilds = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_guild);

    purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

    const gchar *dev_token = purple_connection_get_password(da->pc);
    da->token = g_strdup(dev_token);

    /* Test the REST API */
    groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/users/me?", NULL, groupme_got_self, NULL);
    groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/groups?", NULL, groupme_got_guilds, NULL);
    groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/chats?", NULL, groupme_got_chats, NULL);

    /* XXX: Authenticate good */
    purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
    groupme_bring_up_buddies(da->account);

    if (!chat_conversation_typing_signal) {
        chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(groupme_conv_send_typing), NULL);
    }

    if (!conversation_updated_signal) {
        conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(groupme_mark_conv_seen), NULL);
    }
}

static void
groupme_close(PurpleConnection *pc)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    g_return_if_fail(da != NULL);

    if (da->heartbeat_timeout) {
        g_source_remove(da->heartbeat_timeout);
    }
    
    if (da->long_poller) {
		purple_timeout_remove(da->long_poller);
		da->long_poller = 0;
    }

    if (da->websocket != NULL) {
        purple_ssl_close(da->websocket);
        da->websocket = NULL;
    }

    g_hash_table_unref(da->one_to_ones);
    da->one_to_ones = NULL;
    g_hash_table_unref(da->one_to_ones_rev);
    da->one_to_ones_rev = NULL;
    g_hash_table_unref(da->last_message_id_dm);
    da->last_message_id_dm = NULL;
    g_hash_table_unref(da->sent_message_ids);
    da->sent_message_ids = NULL;
    g_hash_table_unref(da->result_callbacks);
    da->result_callbacks = NULL;

    g_hash_table_unref(da->new_users);
    da->new_users = NULL;
    g_hash_table_unref(da->new_guilds);
    da->new_guilds = NULL;
    g_queue_free(da->received_message_queue);
    da->received_message_queue = NULL;

    while (da->http_conns) {
#if !PURPLE_VERSION_CHECK(3, 0, 0)
        purple_util_fetch_url_cancel(da->http_conns->data);
#else
        purple_http_conn_cancel(da->http_conns->data);
#endif
        da->http_conns = g_slist_delete_link(da->http_conns, da->http_conns);
    }

    while (da->pending_writes) {
        json_object_unref(da->pending_writes->data);
        da->pending_writes = g_slist_delete_link(da->pending_writes, da->pending_writes);
    }

    g_hash_table_destroy(da->cookie_table);
    da->cookie_table = NULL;
    g_free(da->frame);
    da->frame = NULL;
    g_free(da->token);
    da->token = NULL;
    g_free(da->session_id);
    da->session_id = NULL;
    g_free(da->self_username);
    da->self_username = NULL;
    g_free(da);
}

/* static void groupme_start_polling(GroupMeAccount *ya); */

static gboolean
groupme_process_frame(GroupMeAccount *da, const gchar *frame)
{
    JsonParser *parser = json_parser_new();
    JsonNode *root;
    gint64 opcode;

    purple_debug_info("groupme", "got frame data: %s\n", frame);

    if (!json_parser_load_from_data(parser, frame, -1, NULL)) {
        purple_debug_error("groupme", "Error parsing response: %s\n", frame);
        return TRUE;
    }

    root = json_parser_get_root(parser);

    if (root != NULL) {
        //JsonObject *obj = json_node_get_object(root);
        groupme_got_push(da, root, NULL);
    }

    g_object_unref(parser);
    return TRUE;
}

static guchar *
groupme_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
    guint64 i;
    guchar *ret = g_new0(guchar, psize);

    for (i = 0; i < psize; i++) {
        ret[i] = pload[i] ^ key[i % 4];
    }

    return ret;
}

static void
groupme_socket_write_data(GroupMeAccount *ya, guchar *data, gsize data_len, guchar type)
{
    guchar *full_data;
    guint len_size = 1;
    guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };

    if (data_len) {
        purple_debug_info("groupme", "Sending frame: %*s\n", (int) data_len, data);

    }

    data = groupme_websocket_mask(mkey, data, data_len);

    if (data_len > 125) {
        if (data_len <= G_MAXUINT16) {
            len_size += 2;
        } else {
            len_size += 8;
        }
    }

    full_data = g_new0(guchar, 1 + data_len + len_size + 4);

    if (type == 0) {
        type = 129;
    }

    full_data[0] = type;

    if (data_len <= 125) {
        full_data[1] = data_len | 0x80;
    } else if (data_len <= G_MAXUINT16) {
        guint16 be_len = GUINT16_TO_BE(data_len);
        full_data[1] = 126 | 0x80;
        memmove(full_data + 2, &be_len, 2);
    } else {
        guint64 be_len = GUINT64_TO_BE(data_len);
        full_data[1] = 127 | 0x80;
        memmove(full_data + 2, &be_len, 8);
    }

    memmove(full_data + (1 + len_size), &mkey, 4);
    memmove(full_data + (1 + len_size + 4), data, data_len);

    purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);

    g_free(full_data);
    g_free(data);
}

/* takes ownership of data parameter */
static void
groupme_socket_write_json(GroupMeAccount *rca, JsonObject *data)
{
    JsonNode *node;
    gchar *str;
    gsize len;
    JsonGenerator *generator;

    if (rca->websocket == NULL) {
        if (data != NULL) {
            rca->pending_writes = g_slist_append(rca->pending_writes, data);
        }

        return;
    }

    node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, data);

    generator = json_generator_new();
    json_generator_set_root(generator, node);
    str = json_generator_to_data(generator, &len);
    g_object_unref(generator);
    json_node_free(node);

    groupme_socket_write_data(rca, (guchar *) str, len, 0);

    g_free(str);
}

static void
groupme_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
    GroupMeAccount *ya = userdata;
    guchar length_code;
    int read_len = 0;
    gboolean done_some_reads = FALSE;
    printf("ws got data\n");

    if (G_UNLIKELY(!ya->websocket_header_received)) {
        gint nlbr_count = 0;
        gchar nextchar;

        while (nlbr_count < 4 && (read_len = purple_ssl_read(conn, &nextchar, 1)) == 1) {
            if (nextchar == '\r' || nextchar == '\n') {
                nlbr_count++;
            } else {
                nlbr_count = 0;
            }
        }

        if (nlbr_count == 4) {
            ya->websocket_header_received = TRUE;
            done_some_reads = TRUE;

            /* flush stuff that we attempted to send before the websocket was ready */
            while (ya->pending_writes) {
                groupme_socket_write_json(ya, ya->pending_writes->data);
                ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
            }
        }
    }

    while (ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
        if (!ya->frame) {
            if (ya->packet_code != 129) {
                if (ya->packet_code == 136) {
                    purple_debug_error("groupme", "websocket closed\n");

                    length_code = 0;
                    purple_ssl_read(conn, &length_code, 1);

                    if (length_code > 0 && length_code <= 125) {
                        guchar error_buf[2];

                        if (purple_ssl_read(conn, &error_buf, 2) == 2) {
                            gint error_code = (error_buf[0] << 8) + error_buf[1];
                            purple_debug_error("groupme", "error code %d\n", error_code);

                            if (error_code == 4004) {
                                /* bad auth token, clear and reset */
                                purple_account_set_string(ya->account, "token", NULL);

                                purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Reauthentication required"));
                                return;
                            }
                        }
                    }

                    /* Try reconnect */
                    groupme_start_socket(ya);

                    return;
                } else if (ya->packet_code == 137) {
                    /* Ping */
                    gint ping_frame_len = 0;
                    length_code = 0;
                    purple_ssl_read(conn, &length_code, 1);

                    if (length_code <= 125) {
                        ping_frame_len = length_code;
                    } else if (length_code == 126) {
                        guchar len_buf[2];
                        purple_ssl_read(conn, len_buf, 2);
                        ping_frame_len = (len_buf[0] << 8) + len_buf[1];
                    } else if (length_code == 127) {
                        purple_ssl_read(conn, &ping_frame_len, 8);
                        ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
                    }

                    if (ping_frame_len) {
                        guchar *pong_data = g_new0(guchar, ping_frame_len);
                        purple_ssl_read(conn, pong_data, ping_frame_len);
                        purple_debug_info("groupme", "Got a ping frame with pong data: %s\n", pong_data);

                        groupme_socket_write_data(ya, pong_data, ping_frame_len, 138);
                        g_free(pong_data);
                    } else {
                        groupme_socket_write_data(ya, (guchar *) "", 0, 138);
                    }

                    return;
                } else if (ya->packet_code == 138) {
                    /* Ignore pong */
                    return;
                }

                purple_debug_error("groupme", "unknown websocket error %d\n", ya->packet_code);
                return;
            }

            length_code = 0;
            purple_ssl_read(conn, &length_code, 1);

            if (length_code <= 125) {
                ya->frame_len = length_code;
            } else if (length_code == 126) {
                guchar len_buf[2];
                purple_ssl_read(conn, len_buf, 2);
                ya->frame_len = (len_buf[0] << 8) + len_buf[1];
            } else if (length_code == 127) {
                purple_ssl_read(conn, &ya->frame_len, 8);
                ya->frame_len = GUINT64_FROM_BE(ya->frame_len);
            }

            ya->frame = g_new0(gchar, ya->frame_len + 1);
            ya->frame_len_progress = 0;
        }

        guint64 current_progress = ya->frame_len_progress;

        do {
            read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);

            if (read_len > 0) {
                ya->frame_len_progress += read_len;
            }
        } while (read_len > 0 && ya->frame_len_progress < ya->frame_len);

        if(current_progress == ya->frame_len_progress) {
            purple_debug_info("groupme", "No bytes read into frame\n");
            break;
        }

        done_some_reads = TRUE;

        if (ya->frame_len_progress == ya->frame_len) {
            gboolean success = groupme_process_frame(ya, ya->frame);
            g_free(ya->frame);
            ya->frame = NULL;
            ya->packet_code = 0;
            ya->frame_len = 0;
            ya->frames_since_reconnect++;

            if (G_UNLIKELY(ya->websocket == NULL || success == FALSE)) {
                return;
            }
        } else {
            return;
        }
    }

    if (done_some_reads == FALSE && read_len <= 0) {
        if (read_len < 0 && errno == EAGAIN) {
            return;
        }

        purple_debug_error("groupme", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

        if (ya->frames_since_reconnect < 2) {
            purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Lost connection to server"));
        } else {
            /* Try reconnect */
            groupme_start_socket(ya);
        }
    }
}

static void
groupme_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
    GroupMeAccount *da = userdata;
    gchar *websocket_header;
    const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; /* TODO don't be lazy */

    purple_ssl_input_add(da->websocket, groupme_socket_got_data, da);

    websocket_header = g_strdup_printf("GET %s HTTP/1.1\r\n"
                                       "Host: %s\r\n"
                                       "Connection: Upgrade\r\n"
                                       "Pragma: no-cache\r\n"
                                       "Cache-Control: no-cache\r\n"
                                       "Upgrade: websocket\r\n"
                                       "Sec-WebSocket-Version: 13\r\n"
                                       "Sec-WebSocket-Key: %s\r\n"
                                       "User-Agent: " GROUPME_USERAGENT "\r\n"
                                       "\r\n",
                                       GROUPME_GATEWAY_SERVER_PATH, GROUPME_GATEWAY_SERVER,
                                       websocket_key);

    purple_ssl_write(da->websocket, websocket_header, strlen(websocket_header));

    g_free(websocket_header);

    groupme_init_push(da);
}

static void
groupme_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
    GroupMeAccount *da = userdata;

    da->websocket = NULL;
    da->websocket_header_received = FALSE;

    if (da->frames_since_reconnect < 1) {
        purple_connection_error(da->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Couldn't connect to gateway"));
    } else {
        groupme_restart_channel(da);
    }
}

static gboolean long_poll(gpointer data) {
    GroupMeAccount *da = (GroupMeAccount*) data;
    groupme_init_push(da);
    return TRUE;
}

static void
groupme_start_socket(GroupMeAccount *da)
{
#ifdef USE_LONG_POLL
    /* Set to the empircal timeout for the push server.
     * Hack, maybe? Or is this just what one does? I don't know. Please help!
     * I have no idea what I'm doing.
     * -- Dan Haskin, 11/27/2021
     */
    if (da->long_poller) {
		purple_timeout_remove(da->long_poller);
		da->long_poller = 0;
    }
	//da->long_poller = purple_timeout_add_seconds(60, long_poll, da);
    groupme_init_push(da);
    return;
#endif

    if (da->heartbeat_timeout) {
        g_source_remove(da->heartbeat_timeout);
    }

    /* Reset all the old stuff */
    if (da->websocket != NULL) {
        purple_ssl_close(da->websocket);
    }

    da->websocket = NULL;
    da->websocket_header_received = FALSE;
    g_free(da->frame);
    da->frame = NULL;
    da->packet_code = 0;
    da->frame_len = 0;
    da->frames_since_reconnect = 0;

    da->websocket = purple_ssl_connect(da->account, GROUPME_GATEWAY_SERVER, GROUPME_GATEWAY_PORT, groupme_socket_connected, groupme_socket_failed, da);
}

static void
groupme_chat_leave_by_room_id(PurpleConnection *pc, guint64 room_id)
{
    /*GroupMeAccount *ya = purple_connection_get_protocol_data(pc);
    JsonObject *data = json_object_new();
    JsonArray *params = json_array_new();

    json_array_add_string_element(params, room_id);

    json_object_set_string_member(data, "msg", "method");
    json_object_set_string_member(data, "method", "leaveRoom");
    json_object_set_array_member(data, "params", params);
    json_object_set_string_member(data, "id", groupme_get_next_id_str(ya));

    groupme_socket_write_json(ya, data);*/
}

static void
groupme_chat_leave(PurpleConnection *pc, int id)
{
    PurpleChatConversation *chatconv;
    /* TODO check source */
    chatconv = purple_conversations_find_chat(pc, id);
    guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

    if (!room_id) {
        /* TODO FIXME? */
        room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
    }

    groupme_chat_leave_by_room_id(pc, room_id);
}

/* Invite to a _group DM_
 * The API for inviting to a guild is different, TODO implement that one too */

static void
groupme_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
    GroupMeAccount *ya;
    guint64 room_id;
    PurpleChatConversation *chatconv;
    GroupMeUser *user;

    JsonObject *data;

    ya = purple_connection_get_protocol_data(pc);
    chatconv = purple_conversations_find_chat(pc, id);
    guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

    if(!room_id_ptr) {
        return;
    }

    room_id = *room_id_ptr;
    user = groupme_get_user_fullname(ya, who);

    if (!user) {
        purple_debug_info("groupme", "Missing user in invitation for %s", who);
        return;
    }

    data = json_object_new();
    json_object_set_string_member(data, "recipient", from_int(user->id));
    gchar *postdata = json_object_to_string(data);

    gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/recipients/%" G_GUINT64_FORMAT, room_id, user->id);
    groupme_fetch_url_with_method(ya, "PUT", url, postdata, NULL, NULL);
    g_free(url);

    g_free(postdata);
    json_object_unref(data);

}

static const gchar *
groupme_resolve_nick(GroupMeAccount *da, guint64 id, guint64 channel)
{
    GroupMeGuild *g = groupme_get_guild(da, channel);
    const gchar *nick = g_hash_table_lookup_int64(g->nicknames, id);

    if (nick)
        return nick;

    GroupMeUser *u = groupme_get_user(da, id);
    return u->name;
}

static void
groupme_chat_nick(PurpleConnection *pc, int id, gchar *new_nick)
{
    PurpleChatConversation *chatconv;
    /* TODO check source */
    chatconv = purple_conversations_find_chat(pc, id);
    guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

    if (!room_id) {
        /* TODO FIXME? */
        room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
    }

    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    GroupMeGuild *guild = groupme_get_guild(da, room_id);

    JsonObject *container = json_object_new();
    JsonObject *data = json_object_new();
    json_object_set_string_member(data, "nickname", new_nick);
    json_object_set_object_member(container, "membership", data);
    gchar *postdata = json_object_to_string(container);

    gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/groups/%" G_GUINT64_FORMAT "/memberships/update?", guild->id);
    groupme_fetch_url(da, url, postdata, NULL, NULL);

    g_free(url);
    g_free(postdata);
    json_object_unref(container);

    /* Propragate locally as well */
    const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, da->self_user_id);
    groupme_got_nick_change(da, groupme_get_user(da, da->self_user_id), guild, new_nick, old_nick, TRUE);
}

static GList *
groupme_chat_info(PurpleConnection *pc)
{
    GList *m = NULL;
    PurpleProtocolChatEntry *pce;

    pce = g_new0(PurpleProtocolChatEntry, 1);
    pce->label = _("ID");
    pce->identifier = "id";
    m = g_list_append(m, pce);

    pce = g_new0(PurpleProtocolChatEntry, 1);
    pce->label = _("Name");
    pce->identifier = "name";
    m = g_list_append(m, pce);

    return m;
}

static gboolean
str_is_number(const gchar *str)
{
    gint i = strlen(str) - 1;

    for (; i >= 0; i--) {
        if (!g_ascii_isdigit(str[i])) {
            return FALSE;
        }
    }

    return TRUE;
}

static __attribute__((optimize("O0"))) GHashTable *
groupme_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

    if (chatname != NULL) {
        if (str_is_number(chatname)) {
            printf("Bad case 1\n");
            //GroupMeChannel *channel = groupme_get_channel_global(da, chatname);

            //if (channel != NULL) {
                //g_hash_table_insert(defaults, "name", g_strdup(channel->name));
            //}

            g_hash_table_insert(defaults, "id", g_strdup(chatname));
        } else {
            printf("XXXX bad\n");

            /*GroupMeChannel *channel = groupme_get_channel_global_name(da, chatname);

            if (channel != NULL) {
                g_hash_table_insert(defaults, "name", g_strdup(channel->name));
                g_hash_table_insert(defaults, "id", from_int(channel->id));
            }*/
        }
    }

    return defaults;
}

static gchar *
groupme_get_chat_name(GHashTable *data)
{
    gchar *temp;

    if (data == NULL) {
        return NULL;
    }

    temp = g_hash_table_lookup(data, "name");

    if (temp == NULL) {
        temp = g_hash_table_lookup(data, "id");
    }

    if (temp == NULL) {
        return NULL;
    }

    return g_strdup(temp);
}

static void groupme_set_room_last_id(GroupMeAccount *da, guint64 channel_id, guint64 last_id);

static void
groupme_got_history_of_im(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonObject *container = json_node_get_object(node);
    JsonObject *resp = json_object_get_object_member(container, "response");
    JsonArray *messages = json_object_get_array_member(resp, "direct_messages");

    gint i, len = json_array_get_length(messages);
    guint64 last_message = /* channel->last_message_id */ 0 /* XXX */;
    guint64 rolling_last_message_id = 0;

    /* latest are first */
    for (i = len - 1; i >= 0; i--) {
        JsonObject *message = json_array_get_object_element(messages, i);
        /* Direct message: either our sent message or theirs */
        int sid = to_int(json_object_get_string_member(message, "sender_id"));
        int rid = to_int(json_object_get_string_member(message, "recipient_id"));

        /* Sometimes we receive our own messages, account for that */
        int channel = sid == da->self_user_id ? rid : sid;
        rolling_last_message_id = groupme_process_message(da, channel, message, TRUE);
    }

    if (rolling_last_message_id != 0) {
        /* ACK HISTORY ACK */
#if 0
        groupme_set_room_last_id(da, channel->id, rolling_last_message_id);

        if (rolling_last_message_id < last_message) {
            /* Request the next 100 messages */
            gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, channel->id, rolling_last_message_id);
            groupme_fetch_url(da, url, NULL, groupme_got_history_of_room, channel);
            g_free(url);
        }
#endif
    }
}
static void
groupme_got_history_of_room(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonObject *container = json_node_get_object(node);
    JsonObject *resp = json_object_get_object_member(container, "response");
    JsonArray *messages = json_object_get_array_member(resp, "messages");

    GroupMeGuild *channel = user_data;
    gint i, len = json_array_get_length(messages);
    guint64 last_message = /* channel->last_message_id */ 0 /* XXX */;
    guint64 rolling_last_message_id = 0;

    /* latest are first */
    for (i = len - 1; i >= 0; i--) {
        JsonObject *message = json_array_get_object_element(messages, i);
#if 0
        guint64 id = to_int(json_object_get_string_member(message, "id"));

        if (id >= last_message) {
            break;
        }

#endif
        rolling_last_message_id = groupme_process_message(da, channel->id, message, FALSE);
    }

    if (rolling_last_message_id != 0) {
        /* ACK HISTORY ACK */
#if 0
        groupme_set_room_last_id(da, channel->id, rolling_last_message_id);

        if (rolling_last_message_id < last_message) {
            /* Request the next 100 messages */
            gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, channel->id, rolling_last_message_id);
            groupme_fetch_url(da, url, NULL, groupme_got_history_of_room, channel);
            g_free(url);
        }
#endif
    }
}

/* identical endpoint as above, but not rolling */

static void
groupme_got_history_static(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
    JsonArray *messages = json_node_get_array(node);
    gint i, len = json_array_get_length(messages);

    for (i = len - 1; i >= 0; i--) {
        JsonObject *message = json_array_get_object_element(messages, i);

        //groupme_process_message(da, message, FALSE);
    }
}

/* libpurple can't store a 64bit int on a 32bit machine, so convert to
 * something more usable instead (puke). also needs to work cross platform, in
 * case the accounts.xml is being shared (double puke)
 */

static guint64
groupme_get_room_last_id(GroupMeAccount *da, guint64 id)
{
    guint64 last_message_id = da->last_load_last_message_id;
    PurpleBlistNode *blistnode = NULL;
    gchar *channel_id = from_int(id);

    if (g_hash_table_contains(da->one_to_ones, channel_id)) {
        /* is a direct message */
        blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(da->account, g_hash_table_lookup(da->one_to_ones, channel_id)));
    } else {
        /* twas a group chat */
        blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));
    }

    if (blistnode != NULL) {
        guint64 last_room_id = purple_blist_node_get_int(blistnode, "last_message_id_high");

        if (last_room_id != 0) {
            last_room_id = (last_room_id << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_id_low") & 0xFFFFFFFF);

            last_message_id = MAX(da->last_message_id, last_room_id);
        }
    }

    g_free(channel_id);
    return last_message_id;
}

static void
groupme_set_room_last_id(GroupMeAccount *da, guint64 id, guint64 last_id)
{
    PurpleBlistNode *blistnode = NULL;
    gchar *channel_id = from_int(id);

    if (g_hash_table_contains(da->one_to_ones, channel_id)) {
        /* is a direct message */
        blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(da->account, g_hash_table_lookup(da->one_to_ones, channel_id)));
    } else {
        /* twas a group chat */
        blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(da->account, channel_id));
    }

    if (blistnode != NULL) {
        purple_blist_node_set_int(blistnode, "last_message_id_high", last_id >> 32);
        purple_blist_node_set_int(blistnode, "last_message_id_low", last_id & 0xFFFFFFFF);
    }

    da->last_message_id = MAX(da->last_message_id, last_id);
    purple_account_set_int(da->account, "last_message_id_high", last_id >> 32);
    purple_account_set_int(da->account, "last_message_id_low", last_id & 0xFFFFFFFF);

    g_free(channel_id);
}

static void groupme_join_chat(PurpleConnection *pc, GHashTable *chatdata);

static GroupMeGuild *
groupme_open_chat(GroupMeAccount *da, guint64 id, gchar *name, gboolean present)
{
    PurpleChatConversation *chatconv = NULL;

    GroupMeGuild *channel = groupme_get_guild(da, id);

    if (channel == NULL) {
        return NULL;
    }

    if (name == NULL) {
        name = channel->name;
    }

    gchar *id_str = from_int(id);
    chatconv = purple_conversations_find_chat_with_account(id_str, da->account);

    if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
        g_free(id_str);

        if (present) {
            purple_conversation_present(PURPLE_CONVERSATION(chatconv));
        }

        return NULL;
    }

    chatconv = purple_serv_got_joined_chat(da->pc, groupme_chat_hash(id), id_str);
    g_free(id_str);

    purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_memdup(&(id), sizeof(guint64)));

    purple_conversation_present(PURPLE_CONVERSATION(chatconv));

    /* Adds members */

    GList *users = NULL, *flags = NULL;

    for (int j = channel->members->len - 1; j >= 0; j--) {
        int uid = g_array_index(channel->members, guint64, j);
        GroupMeUser *u = groupme_get_user(da, uid);
        PurpleChatUserFlags cbflags = groupme_get_user_flags(da, channel, u);

        users = g_list_prepend(users, g_strdup(groupme_resolve_nick(da, uid, channel->id)));
        flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
    }

    purple_chat_conversation_clear_users(chatconv);
    purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);

    while (users != NULL) {
        g_free(users->data);
        users = g_list_delete_link(users, users);
    }

    g_list_free(users);
    g_list_free(flags);

    return channel;
}

static PurpleCmdRet
groupme_cmd_history(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data) {


    PurpleConnection *pc = purple_conversation_get_connection(conv);
    if (pc == NULL) {
        printf("Conversation was not found.\n");
        return PURPLE_CMD_RET_FAILED;
    }

    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    if (da == NULL) {
        printf("Account was not found.\n");
        return PURPLE_CMD_RET_FAILED;
    }

    if (conv->type == PURPLE_CONV_TYPE_IM) {
        PurpleConvIm *pim = PURPLE_IM_CONVERSATION(conv);
        guint64 person_id = to_int(purple_conversation_get_name(conv));
        if (person_id == 0) {
            printf("Could not find other person's id.\n");
            return PURPLE_CMD_RET_FAILED;
        }
        gchar *url = g_strdup_printf(
                "https://"
                GROUPME_API_SERVER
                "/direct_messages?other_user_id=%"
                G_GUINT64_FORMAT,
                person_id);
        groupme_fetch_url(da,
                url, NULL, groupme_got_history_of_im, NULL);
        g_free(url);
    } else if (conv->type == PURPLE_CONV_TYPE_CHAT) {
        int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

        if (id == -1) {
            printf("Purple chat was not found.\n");
            return PURPLE_CMD_RET_FAILED;
        }

        GroupMeGuild *channel = groupme_get_guild(da, id);
        if (channel == NULL) {
            printf("Channel was not found.\n");
            return PURPLE_CMD_RET_FAILED;
        }
        gchar *url = g_strdup_printf(
                "https://"
                GROUPME_API_SERVER
                "/groups/%" G_GUINT64_FORMAT
                "/messages?limit=%" G_GUINT64_FORMAT, id, to_int(args[0]));
        groupme_fetch_url(da, url, NULL, groupme_got_history_of_room, channel);
        g_free(url);
    } else {
        printf("Purple conversation type was not found.\n");
        return PURPLE_CMD_RET_FAILED;
    }
    return PURPLE_CMD_RET_OK;
}

static void
groupme_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    guint64 id = to_int(g_hash_table_lookup(chatdata, "id"));
    gchar *name = (gchar *) g_hash_table_lookup(chatdata, "name");

    GroupMeGuild *channel = groupme_open_chat(da, id, name, TRUE);

    if (!channel) {
        return;
    }
    /* TODO: HISTORY */
#if 0
    /* Get any missing messages */
    guint64 last_message_id = groupme_get_room_last_id(da, id);

    if (last_message_id != 0 && channel->last_message_id > last_message_id) {
        gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages?limit=100&after=%" G_GUINT64_FORMAT, id, last_message_id);
        groupme_fetch_url(da, url, NULL, groupme_got_history_of_room, channel);
        g_free(url);
    }
#endif

    gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/groups/%" G_GUINT64_FORMAT "/messages?limit=100", id);
    groupme_fetch_url(da, url, NULL, groupme_got_history_of_room, channel);
}

static void
groupme_mark_room_messages_read(GroupMeAccount *da, guint64 channel_id)
{
#if 0
    if (!channel_id) {
        return;
    }

    GroupMeChannel *channel = groupme_get_channel_global_int(da, channel_id);

    guint64 last_message_id;

    if (channel) {
        last_message_id = channel->last_message_id;
    } else {
        gchar *channel = from_int(channel_id);
        gchar *msg = g_hash_table_lookup(da->last_message_id_dm, channel);
        g_free(channel);

        if (msg) {
            last_message_id = to_int(msg);
        } else {
            purple_debug_info("groupme", "Unknown acked channel %" G_GUINT64_FORMAT, channel_id);
            return;
        }
    }

    if (last_message_id == 0) {
        purple_debug_info("groupme", "Won't ack message ID == 0");
    }

    guint64 known_message_id = groupme_get_room_last_id(da, channel_id);

    if (last_message_id == known_message_id) {
        /* Up to date */
        return;
    }

    groupme_set_room_last_id(da, channel_id, last_message_id);

    gchar *url;

    url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/messages/%" G_GUINT64_FORMAT "/ack", channel_id, last_message_id);
    groupme_fetch_url(da, url, "{\"token\":null}", NULL, NULL);
    g_free(url);
#endif
}

static void
groupme_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
    PurpleConnection *pc;
    GroupMeAccount *ya;

    if (type != PURPLE_CONVERSATION_UPDATE_UNSEEN) {
        return;
    }

    pc = purple_conversation_get_connection(conv);

    if (!PURPLE_CONNECTION_IS_CONNECTED(pc)) {
        return;
    }

    if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), GROUPME_PLUGIN_ID)) {
        return;
    }

    ya = purple_connection_get_protocol_data(pc);

    guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");
    guint64 room_id = 0;

    if (room_id_ptr) {
        room_id = *room_id_ptr;
    } else {
        room_id = to_int(g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv)));
    }

    groupme_mark_room_messages_read(ya, room_id);
}

static guint
groupme_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, GroupMeAccount *ya)
{
    PurpleConnection *pc;
    gchar *url;

    if (state != PURPLE_IM_TYPING) {
        return 0;
    }

    pc = ya ? ya->pc : purple_conversation_get_connection(conv);

    if (!PURPLE_CONNECTION_IS_CONNECTED(pc)) {
        return 0;
    }

    if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), GROUPME_PLUGIN_ID)) {
        return 0;
    }

    if (ya == NULL) {
        ya = purple_connection_get_protocol_data(pc);
    }

    printf("Send typing\n");

#if 0
    guint64 *room_id_ptr = purple_conversation_get_data(conv, "id");
    guint64 room_id = 0;

    if (room_id_ptr) {
        room_id = *room_id_ptr;
    } else {
        room_id = to_int(g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv)));
    }

    url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%" G_GUINT64_FORMAT "/typing", room_id);
    groupme_fetch_url(ya, url, "", NULL, NULL);
    g_free(url);
#endif

    return 10;
}

static guint
groupme_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
    PurpleConversation *conv;

    conv = PURPLE_CONVERSATION(purple_conversations_find_im_with_account(who, purple_connection_get_account(pc)));
    g_return_val_if_fail(conv, -1);

    return groupme_conv_send_typing(conv, state, NULL);
}

static gint
groupme_conversation_send_message(GroupMeAccount *da, guint64 room_id, const gchar *message, gboolean is_dm)
{
    JsonObject *data = json_object_new();
    JsonObject *msg = json_object_new();
    gchar *url;
    gchar *postdata;
    gchar *stripped = purple_markup_strip_html(message);

    gchar *rid = from_int(room_id);

        gchar *uuid = g_uuid_string_random();
        gchar *guid = g_strdup_printf("groupme-min-%s", uuid);
        g_free(uuid);

    /* Remember we sent it so we don't double display */
    g_hash_table_replace(da->sent_message_ids, guid, TRUE);

    json_object_set_string_member(msg, "text", stripped);
    json_object_set_string_member(msg, "source_guid", guid);
    json_object_set_object_member(data, is_dm ? "direct_message" : "message", msg);

    if (is_dm) {
        json_object_set_string_member(msg, "recipient_id", rid);
    }

    /* DMs use a different endpoint than group messages */

    if (is_dm) {
        url = g_strdup("https://" GROUPME_API_SERVER "/direct_messages?");
    } else {
        url = g_strdup_printf("https://" GROUPME_API_SERVER "/groups/%" G_GUINT64_FORMAT "/messages?", room_id);
    }

    postdata = json_object_to_string(data);

    groupme_fetch_url(da, url, postdata, NULL, NULL);

    g_free(stripped);
    g_free(url);
    g_free(postdata);
    g_free(rid);
    json_object_unref(data);

    return 1;
}

static gint
groupme_chat_send(PurpleConnection *pc, gint id,
#if PURPLE_VERSION_CHECK(3, 0, 0)
                  PurpleMessage *msg)
{
    const gchar *message = purple_message_get_contents(msg);
#else
                  const gchar *message, PurpleMessageFlags flags)
{
#endif

    GroupMeAccount *da;
    PurpleChatConversation *chatconv;
    gint ret;

    da = purple_connection_get_protocol_data(pc);
    chatconv = purple_conversations_find_chat(pc, id);
    guint64 *room_id_ptr = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
    g_return_val_if_fail(room_id_ptr, -1);
    guint64 room_id = *room_id_ptr;

    ret = groupme_conversation_send_message(da, room_id, message, FALSE);

    if (ret > 0) {
        purple_serv_got_chat_in(pc, groupme_chat_hash(room_id), groupme_resolve_nick(da, da->self_user_id, room_id), PURPLE_MESSAGE_SEND, message, time(NULL));

    }

    return ret;
}

static gint
groupme_conversation_like_message(GroupMeAccount *da, guint64 room_id, gboolean is_dm, gboolean is_like)
{
    gchar *url;
    gchar *postdata;
    gchar *rid = from_int(room_id);

    guint64 last_message_id = da->last_message_id;
    if (last_message_id == 0) {
        last_message_id = groupme_get_room_last_id(da, room_id);
    }

    url = g_strdup_printf("https://"
            GROUPME_API_SERVER
            "/messages/%" G_GUINT64_FORMAT
            "/%" G_GUINT64_FORMAT
            "/%s",
            room_id, da->last_message_id, (is_like ? "like" : "unlike"));
    postdata = "{}";

    groupme_fetch_url(da, url, postdata, NULL, NULL);

    g_free(url);
    g_free(rid);

    return 1;
}

static int
groupme_send_im(PurpleConnection *pc,
#if PURPLE_VERSION_CHECK(3, 0, 0)
                PurpleMessage *msg)
{
    const gchar *who = purple_message_get_recipient(msg);
    const gchar *message = purple_message_get_contents(msg);
#else
                const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    gchar *room_id = g_hash_table_lookup(da->one_to_ones_rev, who);
    int room_id_i;

    /* Create DM if there isn't one */
    if (room_id == NULL) {
#if !PURPLE_VERSION_CHECK(3, 0, 0)
        PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
        guint64 uid = to_int(who);
        GroupMeUser *user = groupme_get_user(da, uid);

        if (!user) {
            purple_debug_error("groupme", "Bad user: %s\n", who);
            return 1;
        }


        /* Cache it */
        g_hash_table_replace(da->one_to_ones, from_int(uid), g_strdup(who));
        g_hash_table_replace(da->one_to_ones_rev, g_strdup(who), from_int(uid));

        room_id_i = user->id;
    } else {
        room_id_i = to_int(room_id);
    }

    return groupme_conversation_send_message(da, room_id_i, message, TRUE);
}

static void
groupme_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
    /* PATCH https:// GROUPME_API_SERVER /api/v6/channels/%s channel */
    /*{ "name" : "test", "position" : 1, "topic" : "new topic", "bitrate" : 64000, "user_limit" : 0 } */
}

static void
groupme_got_avatar(GroupMeAccount *ya, JsonNode *node, gpointer user_data)
{
    GroupMeUser *user = user_data;
    gchar *username = user->id_s;

    if (node != NULL) {
        JsonObject *response = json_node_get_object(node);
        const gchar *response_str;
        gsize response_len;
        gpointer response_dup;

        response_str = g_dataset_get_data(node, "raw_body");
        response_len = json_object_get_int_member(response, "len");
        response_dup = g_memdup(response_str, response_len);

        purple_buddy_icons_set_for_user(ya->account, username, response_dup, response_len, user->avatar);
    }
}

static void
groupme_get_avatar(GroupMeAccount *da, GroupMeUser *user)
{
    if (!user) {
        return;
    }

    gchar *username = from_int(user->id);
    const gchar *checksum = purple_buddy_icons_get_checksum_for_user(purple_blist_find_buddy(da->account, username));
    g_free(username);

    if (purple_strequal(checksum, user->avatar)) {
        return;
    }

    /* Disable token for image requests */
    gchar *token = da->token;
    da->token = NULL;
    groupme_fetch_url(da, user->avatar, NULL, groupme_got_avatar, user);
    da->token = token;
}

static void
groupme_get_info(PurpleConnection *pc, const gchar *username)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    gchar *url;
    GroupMeUser *user = groupme_get_user(da, to_int(username));

    if (!user) {
        return;
    }

    PurpleNotifyUserInfo *user_info;
    user_info = purple_notify_user_info_new();

    purple_notify_user_info_add_pair_html(user_info, _("ID"), username);
    purple_notify_user_info_add_pair_html(user_info, _("Name"), user->name);
    purple_notify_user_info_add_pair_html(user_info, _("Avatar"), user->avatar);

    purple_notify_user_info_add_section_break(user_info);
    purple_notify_user_info_add_pair_html(user_info, _("Mutual Groups"), "");

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, user->guild_memberships);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        GroupMeGuildMembership *membership = value;
        GroupMeGuild *guild = groupme_get_guild(da, membership->id);

        gchar *name = membership->nick;

        gchar *str = g_strdup_printf("%s%s", name, membership->is_op ? "*" : "");
        purple_notify_user_info_add_pair_html(user_info, guild->name, str);
        g_free(str);

    }

    purple_notify_userinfo(da->pc, username, user_info, NULL, NULL);
}

static const char *
groupme_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
    return "groupme";
}

static GList *
groupme_status_types(PurpleAccount *account)
{
    PurpleStatusType *status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, FALSE, FALSE);
    return g_list_append(NULL, status);
}

static gchar *
groupme_status_text(PurpleBuddy *buddy)
{
    return NULL;
}

static void
groupme_block_user(PurpleConnection *pc, const char *who)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    gchar *url;
    GroupMeUser *user = groupme_get_user_fullname(da, who);

    if (!user) {
        return;
    }

    url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
    groupme_fetch_url_with_method(da, "PUT", url, "{\"type\":2}", NULL, NULL);
    g_free(url);
}

static void
groupme_unblock_user(PurpleConnection *pc, const char *who)
{
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);
    gchar *url;
    GroupMeUser *user = groupme_get_user_fullname(da, who);

    if (!user) {
        return;
    }

    url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
    groupme_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
    g_free(url);
}

const gchar *
groupme_list_emblem(PurpleBuddy *buddy)
{
    PurpleAccount *account = purple_buddy_get_account(buddy);

    if (purple_account_is_connected(account)) {
        PurpleConnection *pc = purple_account_get_connection(account);
        GroupMeAccount *da = purple_connection_get_protocol_data(pc);
        GroupMeUser *user = groupme_get_user_fullname(da, purple_buddy_get_name(buddy));

        if (user != NULL) {
            if (user->bot) {
                return "bot";
            }
        }
    }

    return NULL;
}

void
groupme_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
    PurplePresence *presence = purple_buddy_get_presence(buddy);
    PurpleStatus *status = purple_presence_get_active_status(presence);
    const gchar *message = purple_status_get_attr_string(status, "message");

    purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));

    if (message != NULL) {
        gchar *escaped = g_markup_printf_escaped("%s", message);

        purple_notify_user_info_add_pair_html(user_info, _("Playing"), escaped);

        g_free(escaped);
    }
}

static GHashTable *
groupme_get_account_text_table(PurpleAccount *unused)
{
    GHashTable *table;

    table = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(table, "login_label", (gpointer) _("Email address..."));

    return table;
}

static GList *
groupme_add_account_options(GList *account_options)
{
    PurpleAccountOption *option;

    option = purple_account_option_bool_new(_("Use status message as in-game info"), "use-status-as-game", FALSE);
    account_options = g_list_append(account_options, option);

    option = purple_account_option_bool_new(_("Auto-create rooms on buddy list"), "populate-blist", TRUE);
    account_options = g_list_append(account_options, option);

    option = purple_account_option_int_new(_("Number of users in a large channel"), "large-channel-count", 20);
    account_options = g_list_append(account_options, option);

    return account_options;
}

void
groupme_join_server_text(gpointer user_data, const gchar *text)
{
    GroupMeAccount *da = user_data;
    gchar *url;
    const gchar *invite_code;

    invite_code = strrchr(text, '/');

    if (invite_code == NULL) {
        invite_code = text;
    } else {
        invite_code += 1;
    }

    url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/invite/%s", purple_url_encode(invite_code));

    groupme_fetch_url(da, url, "", NULL, NULL);

    g_free(url);
}

void
groupme_join_server(PurpleProtocolAction *action)
{
    PurpleConnection *pc = purple_protocol_action_get_connection(action);
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    purple_request_input(pc, _("Join a server"),
                         _("Join a server"),
                         _("Enter the join URL here"),
                         NULL, FALSE, FALSE, "https://groupme.gg/ABC123",
                         _("_Join"), G_CALLBACK(groupme_join_server_text),
                         _("_Cancel"), NULL,
                         purple_request_cpar_from_connection(pc),
                         da);
}

static GList *
groupme_actions(
#if !PURPLE_VERSION_CHECK(3, 0, 0)
  PurplePlugin *plugin, gpointer context
#else
  PurpleConnection *pc
#endif
  )
{
    GList *m = NULL;
    PurpleProtocolAction *act;

    act = purple_protocol_action_new(_("Join a server..."), groupme_join_server);
    m = g_list_append(m, act);

    return m;
}

static PurpleCmdRet
groupme_cmd_like(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
    PurpleConnection *pc = purple_conversation_get_connection(conv);
    GroupMeAccount *da = purple_connection_get_protocol_data(pc);

    int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

    if (pc == NULL || id == -1) {
        return PURPLE_CMD_RET_FAILED;
    }

    PurpleChatConversation *chatconv;
    /* TODO check source */
    chatconv = purple_conversations_find_chat(pc, id);
    guint64 room_id = *(guint64 *) purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

    if (!room_id) {
        /* TODO FIXME? */
        room_id = to_int(purple_conversation_get_name(PURPLE_CONVERSATION(chatconv)));
    }
    groupme_conversation_like_message(da, room_id, FALSE, TRUE);
    return PURPLE_CMD_RET_OK;
}
static PurpleCmdRet
groupme_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
    PurpleConnection *pc = purple_conversation_get_connection(conv);
    int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

    if (pc == NULL || id == -1) {
        return PURPLE_CMD_RET_FAILED;
    }

    groupme_chat_leave(pc, id);

    return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
groupme_cmd_nick(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
    PurpleConnection *pc = purple_conversation_get_connection(conv);
    int id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

    if (pc == NULL || id == -1) {
        return PURPLE_CMD_RET_FAILED;
    }

    groupme_chat_nick(pc, id, args[0]);

    return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
    purple_cmd_register(
            "history", "s", PURPLE_CMD_P_PLUGIN,
            PURPLE_CMD_FLAG_IM |
            PURPLE_CMD_FLAG_CHAT |
            PURPLE_CMD_FLAG_PROTOCOL_ONLY |
            PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
            GROUPME_PLUGIN_ID,
            groupme_cmd_history,
            _("history <number>: Get <number> of messages in history"), NULL);
    purple_cmd_register("nick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
                                                            PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
                        GROUPME_PLUGIN_ID, groupme_cmd_nick,
                        _("nick <new nickname>:  Changes nickname on a server"), NULL);

#if 0
    purple_cmd_register("kick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
    PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
    GROUPME_PLUGIN_ID, groupme_slash_command,
    _("kick <username>:  Remove someone from channel"), NULL);
#endif
    purple_cmd_register(
            "like",
            "",
            PURPLE_CMD_P_PLUGIN,
            PURPLE_CMD_FLAG_CHAT |
            PURPLE_CMD_FLAG_PROTOCOL_ONLY |
            PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
            GROUPME_PLUGIN_ID, groupme_cmd_like,
            _("like: Like the previous message"), NULL);
    purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
                                                            PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
                        GROUPME_PLUGIN_ID, groupme_cmd_leave,
                        _("leave:  Leave the channel"), NULL);

    purple_cmd_register("part", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
                                                           PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
                        GROUPME_PLUGIN_ID, groupme_cmd_leave,
                        _("part:  Leave the channel"), NULL);

#if 0
    purple_cmd_register("mute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
    PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
    GROUPME_PLUGIN_ID, groupme_slash_command,
    _("mute <username>:  Mute someone in channel"), NULL);

    purple_cmd_register("unmute", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
    PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
    GROUPME_PLUGIN_ID, groupme_slash_command,
    _("unmute <username>:  Un-mute someone in channel"), NULL);

    purple_cmd_register("topic", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
    PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
    GROUPME_PLUGIN_ID, groupme_slash_command,
    _("topic <description>:  Set the channel topic description"), NULL);
#endif

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
    purple_signals_disconnect_by_handle(plugin);

    return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
    return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
    return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{

#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

    PurplePluginInfo *info;
    PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);

    info = plugin->info;

    if (info == NULL) {
        plugin->info = info = g_new0(PurplePluginInfo, 1);
    }

    info->extra_info = prpl_info;
#if PURPLE_MINOR_VERSION >= 5
    prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
#endif

    prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
    prpl_info->protocol_options = groupme_add_account_options(prpl_info->protocol_options);
    prpl_info->icon_spec.format = "png,gif,jpeg";
    prpl_info->icon_spec.min_width = 0;
    prpl_info->icon_spec.min_height = 0;
    prpl_info->icon_spec.max_width = 96;
    prpl_info->icon_spec.max_height = 96;
    prpl_info->icon_spec.max_filesize = 0;
    prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

    prpl_info->get_account_text_table = groupme_get_account_text_table;
    prpl_info->list_emblem = groupme_list_emblem;
    prpl_info->status_text = groupme_status_text;
    prpl_info->tooltip_text = groupme_tooltip_text;
    prpl_info->list_icon = groupme_list_icon;
    prpl_info->status_types = groupme_status_types;
    prpl_info->chat_info = groupme_chat_info;
    prpl_info->chat_info_defaults = groupme_chat_info_defaults;
    prpl_info->login = groupme_login;

    prpl_info->close = groupme_close;
    prpl_info->send_im = groupme_send_im;
    prpl_info->send_typing = groupme_send_typing;
    prpl_info->join_chat = groupme_join_chat;
    prpl_info->get_chat_name = groupme_get_chat_name;
    prpl_info->find_blist_chat = groupme_find_chat;
    prpl_info->chat_invite = groupme_chat_invite;
    prpl_info->chat_send = groupme_chat_send;
    //prpl_info->keepalive = groupme_keepalive;

    prpl_info->set_chat_topic = groupme_chat_set_topic;
    prpl_info->get_cb_real_name = groupme_get_real_name;
    prpl_info->get_info = groupme_get_info;
    prpl_info->add_deny = groupme_block_user;
    prpl_info->rem_deny = groupme_unblock_user;

    prpl_info->roomlist_get_list = groupme_roomlist_get_list;
    prpl_info->roomlist_room_serialize = groupme_roomlist_serialize;
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    /*    PURPLE_MAJOR_VERSION,
        PURPLE_MINOR_VERSION,
    */
    2, 1,
    PURPLE_PLUGIN_PROTOCOL,            /* type */
    NULL,                            /* ui_requirement */
    0,                                /* flags */
    NULL,                            /* dependencies */
    PURPLE_PRIORITY_DEFAULT,        /* priority */
    GROUPME_PLUGIN_ID,                /* id */
    "GroupMe",                        /* name */
    GROUPME_PLUGIN_VERSION,            /* version */
    "",                                /* summary */
    "",                                /* description */
    "Alyssa Rosenzweig <alyssa@rosenzweig.io>", /* author */
    GROUPME_PLUGIN_WEBSITE,            /* homepage */
    libpurple2_plugin_load,            /* load */
    libpurple2_plugin_unload,        /* unload */
    NULL,                            /* destroy */
    NULL,                            /* ui_info */
    NULL,                            /* extra_info */
    NULL,                            /* prefs_info */
    groupme_actions,                /* actions */
    NULL,                            /* padding */
    NULL,
    NULL,
    NULL
};

PURPLE_INIT_PLUGIN(groupme, plugin_init, info);

#else
/* Purple 3 plugin load functions */

G_MODULE_EXPORT GType groupme_protocol_get_type(void);
#define GROUPME_TYPE_PROTOCOL (groupme_protocol_get_type())
#define GROUPME_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), GROUPME_TYPE_PROTOCOL, GroupMeProtocol))
#define GROUPME_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), GROUPME_TYPE_PROTOCOL, GroupMeProtocolClass))
#define GROUPME_IS_PROTOCOL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), GROUPME_TYPE_PROTOCOL))
#define GROUPME_IS_PROTOCOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), GROUPME_TYPE_PROTOCOL))
#define GROUPME_PROTOCOL_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), GROUPME_TYPE_PROTOCOL, GroupMeProtocolClass))

typedef struct _GroupMeProtocol {
    PurpleProtocol parent;
} GroupMeProtocol;

typedef struct _GroupMeProtocolClass {
    PurpleProtocolClass parent_class;
} GroupMeProtocolClass;

static void
groupme_protocol_init(PurpleProtocol *prpl_info)
{
    PurpleProtocol *info = prpl_info;

    info->id = GROUPME_PLUGIN_ID;
    info->name = "GroupMe";
    info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_UNIQUE_CHATNAME;
    info->account_options = groupme_add_account_options(info->account_options);
}

static void
groupme_protocol_class_init(PurpleProtocolClass *prpl_info)
{
    prpl_info->login = groupme_login;
    prpl_info->close = groupme_close;
    prpl_info->status_types = groupme_status_types;
    prpl_info->list_icon = groupme_list_icon;
}

static void
groupme_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
    prpl_info->send = groupme_send_im;
    prpl_info->send_typing = groupme_send_typing;
}

static void
groupme_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
    prpl_info->send = groupme_chat_send;
    prpl_info->info = groupme_chat_info;
    prpl_info->info_defaults = groupme_chat_info_defaults;
    prpl_info->join = groupme_join_chat;
    prpl_info->get_name = groupme_get_chat_name;
    prpl_info->invite = groupme_chat_invite;
    prpl_info->set_topic = groupme_chat_set_topic;
    prpl_info->get_user_real_name = groupme_get_real_name;
}

static void
groupme_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
    prpl_info->get_info = groupme_get_info;
}

static void
groupme_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
    prpl_info->get_account_text_table = groupme_get_account_text_table;
    prpl_info->status_text = groupme_status_text;
    prpl_info->get_actions = groupme_actions;
    prpl_info->list_emblem = groupme_list_emblem;
    prpl_info->tooltip_text = groupme_tooltip_text;
    prpl_info->find_blist_chat = groupme_find_chat;
}

static void
groupme_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
    prpl_info->add_deny = groupme_block_user;
    prpl_info->rem_deny = groupme_unblock_user;
}

static void
groupme_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
    prpl_info->get_list = groupme_roomlist_get_list;
    prpl_info->room_serialize = groupme_roomlist_serialize;
}

static PurpleProtocol *groupme_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
    GroupMeProtocol, groupme_protocol, PURPLE_TYPE_PROTOCOL, 0,

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
                                      groupme_protocol_im_iface_init)

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
                                      groupme_protocol_chat_iface_init)

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
                                      groupme_protocol_server_iface_init)

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
                                      groupme_protocol_client_iface_init)

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
                                      groupme_protocol_privacy_iface_init)

    PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
                                      groupme_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
    groupme_protocol_register_type(plugin);
    groupme_protocol = purple_protocols_add(GROUPME_TYPE_PROTOCOL, error);

    if (!groupme_protocol) {
        return FALSE;
    }

    return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
    if (!plugin_unload(plugin, error)) {
        return FALSE;
    }

    if (!purple_protocols_remove(groupme_protocol, error)) {
        return FALSE;
    }

    return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

    return purple_plugin_info_new(
      "id", GROUPME_PLUGIN_ID,
      "name", "GroupMe",
      "version", GROUPME_PLUGIN_VERSION,
      "category", _("Protocol"),
      "summary", _("GroupMe Protocol Plugins."),
      "description", _("Adds GroupMe protocol support to libpurple."),
      "website", GROUPME_PLUGIN_WEBSITE,
      "abi-version", PURPLE_ABI_VERSION,
      "flags", PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
                 PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
      NULL);
}

PURPLE_PLUGIN_INIT(groupme, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
