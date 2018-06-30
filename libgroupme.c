/*
 *   GroupMe plugin for libpurple
 *   Copyright (C) 2016  Eion Robb
 *   Copyright (C) 2017 Alyssa Rosenzweig
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
#	ifdef _WIN32
#		ifdef LOCALEDIR
#			unset LOCALEDIR
#		endif
#		define LOCALEDIR  wpurple_locale_dir()
#	endif
#else
#      define _(a) (a)
#      define N_(a) (a)
#endif

#include "glib_compat.h"
#include "json_compat.h"
#include "purple_compat.h"

#define GROUPME_PLUGIN_ID "prpl-eionrobb-groupme"
#ifndef GROUPME_PLUGIN_VERSION
#define GROUPME_PLUGIN_VERSION "0.1"
#endif
#define GROUPME_PLUGIN_WEBSITE "https://github.com/EionRobb/groupme-libpurple"

#define GROUPME_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define GROUPME_BUFFER_DEFAULT_SIZE 40960

#define GROUPME_API_SERVER "api.groupme.com/v3"
#define GROUPME_PUSH_SERVER "push.groupme.com/faye?"
#define GROUPME_GATEWAY_SERVER "push.groupme.com"
#define GROUPME_GATEWAY_PORT 443
#define GROUPME_GATEWAY_SERVER_PATH "/faye"

#define IGNORE_PRINTS

static GRegex *channel_mentions_regex = NULL;
static GRegex *role_mentions_regex = NULL;
static GRegex *emoji_regex = NULL;
static GRegex *emoji_natural_regex = NULL;
static GRegex *action_star_regex = NULL;
static GRegex *mention_regex = NULL;
static GRegex *natural_mention_regex = NULL;

typedef enum {
	USER_ONLINE,
	USER_IDLE,
	USER_OFFLINE,
	USER_DND
} GroupMeStatus;

typedef enum {
	CHANNEL_GUILD_TEXT = 0,
	CHANNEL_DM = 1,
	CHANNEL_VOICE = 2,
	CHANNEL_GROUP_DM = 3,
	CHANNEL_GUILD_CATEGORY = 4
} GroupMeChannelType;

typedef struct {
	guint64 id;
	gchar *name;
	int color;
	gint64 permissions;
} GroupMeGuildRole;

typedef struct {
	guint64 id;
	gint64 deny;
	gint64 allow;
} GroupMePermissionOverride;

typedef struct {
	guint64 id;
	guint64 guild_id;
	gchar *name;
	gchar *topic;
	GroupMeChannelType type;
	int position;
	guint64 last_message_id;
	GHashTable *permission_user_overrides;
	GHashTable *permission_role_overrides;
	GList *recipients; /* For group DMs */
} GroupMeChannel;

typedef struct {
	guint64 id;
	gchar *name;
	gchar *icon;
	guint64 owner;

	GHashTable *roles;
	GArray *members;		   /* list of member ids */
	GHashTable *nicknames;	 /* id->nick? */
	GHashTable *nicknames_rev; /* reverse */

	GHashTable *channels;
	int afk_timeout;
	const gchar *afk_voice_channel;

	GHashTable *emojis;
} GroupMeGuild;

typedef struct {
	guint64 id;
	gchar *nick;
	gchar *joined_at;
	GArray *roles; /* list of ids */
} GroupMeGuildMembership;

typedef struct {
	guint64 id;
	gchar *name;
	int discriminator;
	GroupMeStatus status;
	gchar *game;
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

	GHashTable *one_to_ones;		/* A store of known room_id's -> username's */
	GHashTable *one_to_ones_rev;	/* A store of known usernames's -> room_id's */
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
static void groupme_free_guild_role(gpointer data);
static void groupme_free_channel(gpointer data);
static gboolean groupme_permission_is_role(JsonObject *json);

/* creating */

static GroupMeUser *
groupme_new_user(JsonObject *json)
{
	GroupMeUser *user = g_new0(GroupMeUser, 1);

	user->id = to_int(json_object_get_string_member(json, "user_id"));
	user->name = g_strdup(json_object_get_string_member(json, "nickname"));

#if 0
	user->discriminator = to_int(json_object_get_string_member(json, "discriminator"));
	user->bot = json_object_get_boolean_member(json, "bot");
	user->avatar = g_strdup(json_object_get_string_member(json, "avatar"));

	user->guild_memberships = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_guild_membership);
	user->status = user->bot ? USER_ONLINE : USER_OFFLINE; /* Is offline the best assumption on a new user? */
#endif

	return user;
}

static GroupMeGuild *
groupme_new_guild(JsonObject *json)
{
	GroupMeGuild *guild = g_new0(GroupMeGuild, 1);

	guild->id = to_int(json_object_get_string_member(json, "id"));
	guild->name = g_strdup(json_object_get_string_member(json, "name"));
	guild->members = g_array_new(TRUE, TRUE, sizeof(guint64));
#if 0
	guild->icon = g_strdup(json_object_get_string_member(json, "icon"));
	guild->owner = to_int(json_object_get_string_member(json, "owner_id"));

	guild->roles = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_guild_role);
	guild->members = g_array_new(TRUE, TRUE, sizeof(guint64));
	guild->nicknames = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	guild->nicknames_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	guild->channels = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, groupme_free_channel);
	guild->afk_timeout = json_object_get_int_member(json, "afk_timeout");
	guild->afk_voice_channel = g_strdup(json_object_get_string_member(json, "afk_channel_id"));

	guild->emojis = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	JsonArray *emojis = json_object_get_array_member(json, "emojis");

	for (int i = json_array_get_length(emojis) - 1; i >= 0; i--) {
		JsonObject *emoji = json_array_get_object_element(emojis, i);

		gchar *id = g_strdup(json_object_get_string_member(emoji, "id"));
		gchar *name = g_strdup(json_object_get_string_member(emoji, "name"));
		g_hash_table_replace(guild->emojis, name, id);
	}
#endif

	return guild;
}

static GroupMePermissionOverride *
groupme_new_permission_override(JsonObject *json)
{
	GroupMePermissionOverride *permission = g_new0(GroupMePermissionOverride, 1);

	permission->id = to_int(json_object_get_string_member(json, "id"));
	permission->deny = json_object_get_int_member(json, "deny");
	permission->allow = json_object_get_int_member(json, "allow");

	return permission;
}

static GroupMeChannel *
groupme_new_channel(JsonObject *json)
{
	GroupMeChannel *channel = g_new0(GroupMeChannel, 1);

	channel->id = to_int(json_object_get_string_member(json, "id"));
	channel->name = g_strdup(json_object_get_string_member(json, "name"));
	channel->topic = g_strdup(json_object_get_string_member(json, "topic"));
	channel->position = json_object_get_int_member(json, "position");
	channel->type = json_object_get_int_member(json, "type");
	channel->last_message_id = to_int(json_object_get_string_member(json, "last_message_id"));

	channel->permission_user_overrides = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	channel->permission_role_overrides = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);

	channel->recipients = NULL;

	return channel;
}

static GroupMeGuildMembership *
groupme_new_guild_membership(guint64 id, JsonObject *json)
{
	GroupMeGuildMembership *guild_membership = g_new0(GroupMeGuildMembership, 1);

	guild_membership->id = id;
	guild_membership->nick = g_strdup(json_object_get_string_member(json, "nick"));
	guild_membership->joined_at = g_strdup(json_object_get_string_member(json, "joined_at"));

	guild_membership->roles = g_array_new(TRUE, TRUE, sizeof(guint64));

	return guild_membership;
}

static GroupMeGuildRole *
groupme_new_guild_role(JsonObject *json)
{
	GroupMeGuildRole *guild_role = g_new0(GroupMeGuildRole, 1);

	guild_role->id = to_int(json_object_get_string_member(json, "id"));
	guild_role->name = g_strdup(json_object_get_string_member(json, "name"));
	guild_role->color = json_object_get_int_member(json, "color");
	guild_role->permissions = json_object_get_int_member(json, "permissions");

	return guild_role;
}

/* freeing */

static void
groupme_free_guild_role(gpointer data)
{
	GroupMeGuildRole *guild_role = data;
	g_free(guild_role->name);
	g_free(guild_role);
}

static void
groupme_free_guild_membership(gpointer data)
{
	GroupMeGuildMembership *guild_membership = data;
	g_free(guild_membership->nick);
	g_free(guild_membership->joined_at);

	g_array_unref(guild_membership->roles);
	g_free(guild_membership);
}

static void
groupme_free_user(gpointer data)
{
	GroupMeUser *user = data;
	g_free(user->name);
	g_free(user->game);
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

	g_hash_table_unref(guild->roles);
	g_array_unref(guild->members);
	g_hash_table_unref(guild->nicknames);
	g_hash_table_unref(guild->nicknames_rev);
	g_hash_table_unref(guild->channels);
	g_hash_table_unref(guild->emojis);
	g_free(guild);
}

static void
groupme_free_channel(gpointer data)
{
	GroupMeChannel *channel = data;
	g_free(channel->name);
	g_free(channel->topic);

	g_hash_table_unref(channel->permission_user_overrides);
	g_hash_table_unref(channel->permission_role_overrides);
	g_list_free_full(channel->recipients, g_free);

	g_free(channel);
}

static void groupme_start_socket(GroupMeAccount *ya);

static void
groupme_got_subscription(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	printf("Subscribed! TODO: Check\n");

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
			printf("Handshake success\n");
			const gchar *clientId = json_object_get_string_member(response, "clientId");
			da->client_id = g_strdup(clientId);
			printf("Client ID: %s\n", clientId);

			/* Subscribe now */
			const gchar *str = g_strdup_printf(
					"{\"channel\": \"/meta/subscribe\", \"clientId\": \"%s\", \"subscription\": \"/user/%d\", \"ext\": {\"timestamp\": %d, \"access_token\": \"%s\"}, \"id\": 2}",
					clientId,
					da->self_user_id,
					time(NULL),
					da->token);

			groupme_fetch_url(da, "https://" GROUPME_PUSH_SERVER, str, groupme_got_subscription, NULL);
		}
	}
}

/* updating */

static void
groupme_update_status(GroupMeUser *user, JsonObject *json)
{
	json_object_get_string_member(json, "id");

	if (json_object_has_member(json, "status")) {
		const gchar *status = json_object_get_string_member(json, "status");

		if (purple_strequal("online", status)) {
			user->status = USER_ONLINE;
		} else if (purple_strequal("idle", status)) {
			user->status = USER_IDLE;
		} else if (purple_strequal("dnd", status)) {
			user->status = USER_DND;
		} else {
			user->status = USER_OFFLINE; /* All else fails probably offline */
		}
	}

	if (json_object_has_member(json, "game")) {
		const gchar *game = json_object_get_string_member(json_object_get_object_member(json, "game"), "name");
		g_free(user->game);
		user->game = g_strdup(game);
	}
}

static GroupMeChannel *
groupme_add_channel(GroupMeGuild *guild, JsonObject *json, guint64 guild_id)
{
	GroupMeChannel *channel = groupme_new_channel(json);
	channel->guild_id = guild_id;
	g_hash_table_replace_int64(guild->channels, channel->id, channel);
	return channel;
}

static GroupMeGuildRole *
groupme_add_guild_role(GroupMeGuild *guild, JsonObject *json)
{
	GroupMeGuildRole *role = groupme_new_guild_role(json);
	g_hash_table_replace_int64(guild->roles, role->id, role);
	return role;
}

static GroupMePermissionOverride *
groupme_add_permission_override(GroupMeChannel *channel, JsonObject *json)
{
	GroupMePermissionOverride *permission_override = groupme_new_permission_override(json);
	gboolean is_role = groupme_permission_is_role(json);
	GHashTable *overrides = is_role ? channel->permission_role_overrides : channel->permission_user_overrides;
	g_hash_table_replace_int64(overrides, permission_override->id, permission_override);
	return permission_override;
}

/* managing */
static gboolean
groupme_permission_is_role(JsonObject *json)
{
	return purple_strequal(json_object_get_string_member(json, "type"), "role");
}

void
groupme_dump_int64_hashtable_keys(GHashTable *hash_table)
{
	GHashTableIter iter;
	guint64 *key;
	gpointer value;

	g_hash_table_iter_init(&iter, hash_table);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		purple_debug_info("groupme", "%" G_GUINT64_FORMAT, *key);
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

		if (user->discriminator == discriminator && purple_strequal(user->name, name)) {
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
	guint64 *key = NULL, user_id = to_int(json_object_get_string_member(json, "user_id"));
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
groupme_create_fullname(GroupMeUser *user)
{
	g_return_val_if_fail(user != NULL, NULL);
	
	return g_strdup_printf("%s#%04d", user->name, user->discriminator);
}

static gchar *
groupme_create_fullname_from_id(GroupMeAccount *da, guint64 id)
{
	GroupMeUser *user = groupme_get_user(da, id);

	if (user) {
		return groupme_create_fullname(user);
	}

	return NULL;
}

static gchar *groupme_create_nickname(GroupMeUser *author, GroupMeGuild *guild);

static gchar *
groupme_alloc_nickname(GroupMeUser *user, GroupMeGuild *guild, const gchar *suggested_nick)
{
	const gchar *base_nick = suggested_nick ? suggested_nick : user->name;
	gchar *nick = NULL;

	if (base_nick == NULL) {
		return NULL;
	}

	GroupMeUser *existing = g_hash_table_lookup(guild->nicknames_rev, base_nick);
	
	if (existing && existing->id != user->id) {
		/* Ambiguous; try with the discriminator */

		nick = g_strdup_printf("%s#%04d", base_nick, user->discriminator);

		existing = g_hash_table_lookup(guild->nicknames_rev, nick);

		if (existing && existing->id != user->id) {
			/* Ambiguous; use the full tag */

			g_free(nick);
			nick = g_strdup_printf("%s (%s#%04d)", base_nick, user->name, user->discriminator);
		}
	}
	
	if (!nick) {
		nick = g_strdup(base_nick);
	}

	g_hash_table_replace_int64(guild->nicknames, user->id, g_strdup(nick));
	g_hash_table_replace(guild->nicknames_rev, g_strdup(nick), g_memdup(&user->id, sizeof(user->id)));

	return nick;
}

static gchar *
groupme_create_nickname_from_id(GroupMeAccount *da, GroupMeGuild *g, guint64 id)
{
	GroupMeUser *user = groupme_get_user(da, id);

	if (user) {
		return groupme_create_nickname(user, g);
	}

	return NULL;
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

static GroupMeChannel *
groupme_get_channel_global_int_guild(GroupMeAccount *da, guint64 id, GroupMeGuild **o_guild)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GroupMeGuild *guild = value;

		if (!guild) {
			continue;
		}

		GroupMeChannel *channel = g_hash_table_lookup_int64(guild->channels, id);

		if (channel) {
			if (o_guild) {
				*o_guild = guild;
			}

			return channel;
		}
	}

	return NULL;
}

static GroupMeChannel *
groupme_get_channel_global_int(GroupMeAccount *da, guint64 id)
{
	return groupme_get_channel_global_int_guild(da, id, NULL);
}

static GroupMeChannel *
groupme_get_channel_global_name(GroupMeAccount *da, const gchar *name)
{
	GHashTableIter guild_iter, channel_iter;
	gpointer key, value;

	g_hash_table_iter_init(&guild_iter, da->new_guilds);

	while (g_hash_table_iter_next(&guild_iter, &key, &value)) {
		GroupMeGuild *guild = value;
		g_hash_table_iter_init(&channel_iter, guild->channels);

		while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
			GroupMeChannel *channel = value;

			if (purple_strequal(name, channel->name)) {
				return channel;
			}
		}
	}

	return NULL;
}

static GroupMeChannel *
groupme_get_channel_global(GroupMeAccount *da, const gchar *id)
{
	return groupme_get_channel_global_int(da, to_int(id));
}
/* debug */

#define groupme_print_append(L, B, R, M, D) \
	g_string_printf((R), (M), (D));         \
	groupme_print_append_row((L), (B), (R));

#ifndef IGNORE_PRINTS
static void
groupme_print_append_row(int level, GString *buffer, GString *row)
{
	for (int i = 0; i < level; i++) {
		g_string_prepend_c(row, '\t');
	}

	g_string_append(buffer, row->str);
	g_string_append_c(buffer, '\n');
}

static void
groupme_print_permission_override(GString *buffer, GHashTable *permission_overrides, const gchar *type)
{
	GHashTableIter permission_override_iter;
	GString *row_buffer = g_string_new("");
	gpointer key, value;

	type = purple_strequal("role", type) ? "Role override count: %d" : "User override count: %d";
	groupme_print_append(2, buffer, row_buffer, type, g_hash_table_size(permission_overrides));
	g_hash_table_iter_init(&permission_override_iter, permission_overrides);

	while (g_hash_table_iter_next(&permission_override_iter, &key, &value)) {
		GroupMePermissionOverride *permission_override = value;

		groupme_print_append(3, buffer, row_buffer, "Override id: %" G_GUINT64_FORMAT, permission_override->id);
		groupme_print_append(4, buffer, row_buffer, "Allow: %" G_GUINT64_FORMAT, permission_override->allow);
		groupme_print_append(4, buffer, row_buffer, "Deny: %" G_GUINT64_FORMAT, permission_override->deny);
	}
}
#endif

static void
groupme_print_guilds(GHashTable *guilds)
{
#ifdef IGNORE_PRINTS
	return;
#else
	GString *buffer = g_string_new("\n");
	GString *row_buffer = g_string_new("");
	GHashTableIter guild_iter, channel_iter, role_iter;
	gpointer key, value;

	g_hash_table_iter_init(&guild_iter, guilds);

	while (g_hash_table_iter_next(&guild_iter, &key, &value)) {
		GroupMeGuild *guild = value;

		groupme_print_append(0, buffer, row_buffer, "Guild id: %" G_GUINT64_FORMAT, guild->id);
		groupme_print_append(1, buffer, row_buffer, "Name: %s", guild->name);
		groupme_print_append(1, buffer, row_buffer, "Icon: %s", guild->icon);
		groupme_print_append(1, buffer, row_buffer, "Owner: %" G_GUINT64_FORMAT, guild->owner);
		groupme_print_append(1, buffer, row_buffer, "Afk timeout: %d", guild->afk_timeout);
		groupme_print_append(1, buffer, row_buffer, "Afk channel: %s", guild->afk_voice_channel);

		g_hash_table_iter_init(&role_iter, guild->roles);

		while (g_hash_table_iter_next(&role_iter, &key, &value)) {
			GroupMeGuildRole *role = value;
			groupme_print_append(1, buffer, row_buffer, "Role id: %" G_GUINT64_FORMAT, role->id);
			groupme_print_append(2, buffer, row_buffer, "Name: %s", role->name);
			groupme_print_append(2, buffer, row_buffer, "Color: %d", role->color);
			groupme_print_append(2, buffer, row_buffer, "Permissions: %" G_GUINT64_FORMAT, role->permissions);
		}

		groupme_print_append(1, buffer, row_buffer, "Member count: %d", guild->members->len);

		for (guint i = 0; i < guild->members->len; i++) {
			guint64 member_id = g_array_index(guild->members, guint64, i);
			groupme_print_append(3, buffer, row_buffer, "Member id: %" G_GUINT64_FORMAT, member_id);
		}

		g_hash_table_iter_init(&channel_iter, guild->channels);

		while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
			GroupMeChannel *channel = value;

			groupme_print_append(1, buffer, row_buffer, "Channel id: %" G_GUINT64_FORMAT, channel->id);
			groupme_print_append(2, buffer, row_buffer, "Name: %s", channel->name);
			groupme_print_append(2, buffer, row_buffer, "Topic: %s", channel->topic);
			groupme_print_append(2, buffer, row_buffer, "Type: %d", channel->type);
			groupme_print_append(2, buffer, row_buffer, "Position: %d", channel->position);
			groupme_print_append(2, buffer, row_buffer, "Last message: %" G_GUINT64_FORMAT, channel->last_message_id);

			groupme_print_permission_override(buffer, channel->permission_role_overrides, "Role");
			groupme_print_permission_override(buffer, channel->permission_user_overrides, "User");
		}
	}

	purple_debug_info("groupme", "%s", buffer->str);
	g_string_free(buffer, TRUE);
	g_string_free(row_buffer, TRUE);
#endif
}

static void
groupme_print_users(GHashTable *users)
{
#ifdef IGNORE_PRINTS
	return;
#else
	GString *buffer = g_string_new("\n");
	GString *row_buffer = g_string_new("");
	GHashTableIter user_iter, guild_membership_iter;
	gpointer key, value;

	g_hash_table_iter_init(&user_iter, users);

	while (g_hash_table_iter_next(&user_iter, &key, &value)) {
		GroupMeUser *user = value;

		groupme_print_append(0, buffer, row_buffer, "User id: %" G_GUINT64_FORMAT, user->id);
		groupme_print_append(1, buffer, row_buffer, "Name: %s", user->name);
		groupme_print_append(1, buffer, row_buffer, "Discriminator: %d", user->discriminator);
		groupme_print_append(1, buffer, row_buffer, "Game: %s", user->game);
		groupme_print_append(1, buffer, row_buffer, "Avatar: %s", user->avatar);
		groupme_print_append(1, buffer, row_buffer, "Status: %d", user->status);

		g_hash_table_iter_init(&guild_membership_iter, user->guild_memberships);

		while (g_hash_table_iter_next(&guild_membership_iter, &key, &value)) {
			GroupMeGuildMembership *guild_membership = value;

			groupme_print_append(1, buffer, row_buffer, "Guild membership id: %" G_GUINT64_FORMAT, guild_membership->id);
			groupme_print_append(2, buffer, row_buffer, "Nick: %s", guild_membership->nick);
			groupme_print_append(2, buffer, row_buffer, "Joined at: %s", guild_membership->joined_at);
			groupme_print_append(2, buffer, row_buffer, "Role count: %d", guild_membership->roles->len);

			for (guint i = 0; i < guild_membership->roles->len; i++) {
				guint64 role_id = g_array_index(guild_membership->roles, guint64, i);
				groupme_print_append(3, buffer, row_buffer, "Role id: %" G_GUINT64_FORMAT, role_id);
			}
		}
	}

	purple_debug_info("groupme", "%s", buffer->str);

	g_string_free(buffer, TRUE);
	g_string_free(row_buffer, TRUE);
#endif
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

	if (guild_membership == NULL) {
		return best_flag;
	}

	for (guint i = 0; i < guild_membership->roles->len; i++) {
		guint64 role_id = g_array_index(guild_membership->roles, guint64, i);
		GroupMeGuildRole *role = g_hash_table_lookup_int64(guild->roles, role_id);
		PurpleChatUserFlags this_flag = PURPLE_CHAT_USER_NONE;

		if (role != NULL) {
			if (role->permissions & 0x8) { /* Admin */
				this_flag = PURPLE_CHAT_USER_OP;
			} else if (role->permissions & (0x2 | 0x4)) { /* Ban/kick */
				this_flag = PURPLE_CHAT_USER_HALFOP;
			}
		}

		if (this_flag > best_flag) {
			best_flag = this_flag;
		}
	}

	return best_flag;
}

static gchar *
groupme_combine_username(const gchar *username, const gchar *discriminator)
{
	g_return_val_if_fail(username != NULL, NULL);
	
	if (discriminator == NULL) {
		discriminator = "0000";
	}
	
	return g_strconcat(username, "#", discriminator, NULL);
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

	http_conn = purple_util_fetch_url_request_len_with_account(ya->account, url, FALSE, GROUPME_USERAGENT, TRUE, headers->str, TRUE, 6553500, groupme_response_callback, conn);

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

static void
groupme_got_connect(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	printf("/**/\n");
}

static void
groupme_send_auth(GroupMeAccount *da)
{
	JsonObject *data = json_object_new();

	json_object_set_string_member(data, "channel", "/meta/connect");
	json_object_set_string_member(data, "clientId", da->client_id);
	json_object_set_string_member(data, "connectionType", "websocket");
	json_object_set_string_member(data, "id", "3");

	groupme_fetch_url(da, "https://" GROUPME_PUSH_SERVER, json_object_to_string(data), groupme_got_connect, NULL);
	//groupme_socket_write_json(da, data);

	json_object_unref(data);
}

static gboolean
groupme_send_heartbeat(gpointer userdata)
{
	GroupMeAccount *da = userdata;
	JsonObject *obj = json_object_new();

	json_object_set_int_member(obj, "op", 1);
	json_object_set_int_member(obj, "d", da->seq);

	groupme_socket_write_json(da, obj);

	json_object_unref(obj);

	return TRUE;
}

void groupme_handle_add_new_user(GroupMeAccount *ya, JsonObject *obj);

PurpleGroup *groupme_get_or_create_default_group();

static void groupme_create_relationship(GroupMeAccount *da, JsonObject *json);
static void groupme_got_relationships(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_private_channels(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_presences(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_read_states(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_history_static(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_history_of_room(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_populate_guild(GroupMeAccount *da, JsonObject *guild);
static void groupme_got_guilds(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_got_avatar(GroupMeAccount *da, JsonNode *node, gpointer user_data);
static void groupme_get_avatar(GroupMeAccount *da, GroupMeUser *user);

static const gchar *groupme_normalise_room_name(const gchar *guild_name, const gchar *name);
static guint64 groupme_compute_permission(GroupMeAccount *da, GroupMeUser *user, GroupMeChannel *channel);
static GroupMeChannel *groupme_open_chat(GroupMeAccount *da, guint64 id, gchar *name, gboolean present);

static gboolean
groupme_replace_channel(const GMatchInfo *match, GString *result, gpointer user_data)
{
	GroupMeAccount *da = user_data;
	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *channel_id = g_match_info_fetch(match, 1);
	GroupMeChannel *channel = groupme_get_channel_global(da, channel_id);

	if (channel) {
		/* TODO make this a clickable link */
		GroupMeGuild *guild = groupme_get_guild(da, channel->guild_id);

		if (guild) {
			g_string_append_printf(result, "%s", groupme_normalise_room_name(guild->name, channel->name));
		} else {
			g_string_append_printf(result, "#%s", channel->name);
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(channel_id);
	g_free(match_string);

	return FALSE;
}

#define COLOR_START "<font color=\"#%06X\">"
#define COLOR_END "</font>"

static gboolean
groupme_replace_role(const GMatchInfo *match, GString *result, gpointer user_data)
{
	GroupMeAccountGuild *ag = user_data;
	/* GroupMeAccount *da = ag->account; */
	GroupMeGuild *guild = ag->guild;

	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *role_id = g_match_info_fetch(match, 1);
	guint64 rid = to_int(role_id);

	GroupMeGuildRole *role = g_hash_table_lookup_int64(guild->roles, rid);

	if (rid == guild->id) {
		g_string_append(result, "<b>@everyone</b>");
	} else if (role) {
		/* TODO make this a clickable link */

		if (role->color) {
			g_string_append_printf(result, COLOR_START "<b>@%s</b>" COLOR_END, role->color, role->name);
		} else {
			g_string_append_printf(result, "<b>@%s</b>", role->name);
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(role_id);
	g_free(match_string);

	return FALSE;
}


static gboolean
groupme_replace_emoji(const GMatchInfo *match, GString *result, gpointer user_data)
{
	gchar *alt_text = g_match_info_fetch(match, 1);
	gchar *emoji_id = g_match_info_fetch(match, 2);

	/* TODO: download and cache emoji as a PurpleStoredImage? */
	g_string_append_printf(result, "<img src=\"https://cdn.groupmeapp.com/emojis/%s.png\" alt=\":%s:\"/>", emoji_id, alt_text);

	g_free(emoji_id);
	g_free(alt_text);

	return FALSE;
}

static gboolean
groupme_replace_mention(const GMatchInfo *match, GString *result, gpointer user_data)
{
	GroupMeAccountGuild *ag = user_data;
	GroupMeAccount *da = ag->account;
	GroupMeGuild *guild = ag->guild;
	gchar *match_string = g_match_info_fetch(match, 0);

	gchar *snowflake_str = g_match_info_fetch(match, 1);
	guint64 snowflake = to_int(snowflake_str);
	g_free(snowflake_str);

	GroupMeUser *mention_user = groupme_get_user(da, snowflake);

	if (mention_user) {
		/* TODO make this a clickable link */
		gchar *name = groupme_create_nickname(mention_user, guild);

		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, name);

		if (buddy && purple_buddy_get_alias(buddy)) {
			g_free(name);
			name = g_strdup(purple_buddy_get_alias(buddy));
		} else if (!guild && snowflake == da->self_user_id && purple_account_get_private_alias(da->account)) {
			g_free(name);
			name = g_strdup(purple_account_get_private_alias(da->account));
		}

		g_string_append_printf(result, "<b>@%s</b>", name);
		g_free(name);
	} else {
		g_string_append(result, match_string);
	}

	g_free(match_string);

	return FALSE;
}

static gchar *
groupme_replace_mentions_bare(GroupMeAccount *da, GroupMeGuild *g, gchar *message)
{
	GroupMeAccountGuild ag = { .account = da, .guild = g };
	gchar *tmp = g_regex_replace_eval(mention_regex, message, -1, 0, 0, groupme_replace_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	/* Replace <#channel_id> with channel names */
	tmp = g_regex_replace_eval(channel_mentions_regex, message, -1, 0, 0, groupme_replace_channel, da, NULL);

	if (tmp != NULL) {
		g_free(message);
		message = tmp;
	}

	/* Replace <@&role_id> with role names */
	if (g) {
		GroupMeAccountGuild ag = { .account = da, .guild = g };
		tmp = g_regex_replace_eval(role_mentions_regex, message, -1, 0, 0, groupme_replace_role, &ag, NULL);

		if (tmp != NULL) {
			g_free(message);
			message = tmp;
		}
	}

	return message;
}

static guint64
groupme_find_role_by_name(GroupMeGuild *guild, const gchar *name)
{
	if (!guild) {
		return 0;
	}
	
	if (purple_strequal(name, "everyone")) {
		return guild->id;
	}

	GHashTableIter iter;
	gpointer key;
	gpointer value;
	g_hash_table_iter_init(&iter, guild->roles);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		GroupMeGuildRole *role = value;
		if (purple_strequal(role->name, name)) {
			return role->id;
		}
	}

	return 0;
}

static guint64
groupme_find_channel_by_name(GroupMeGuild *guild, gchar *name)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	
	if (!guild) {
		return 0;
	}
	
	g_hash_table_iter_init(&iter, guild->channels);

	while (g_hash_table_iter_next(&iter, (gpointer *) &key, &value)) {
		GroupMeChannel *channel = value;
		if (purple_strequal(channel->name, name)) {
			return channel->id;
		}
	}

	return 0;
}

static gboolean
groupme_make_mention(const GMatchInfo *match, GString *result, gpointer user_data)
{
	GroupMeAccountGuild *ag = user_data;
	GroupMeAccount *da = ag->account;
	GroupMeGuild *guild = ag->guild;

	gchar *match_string = g_match_info_fetch(match, 0);
	gchar *identifier = g_match_info_fetch(match, 1);

	/* Try to find user by discriminator */
	GroupMeUser *user = groupme_get_user_fullname(da, identifier);

	/* If that fails, find it by alias */
	if (!user) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, da->new_users);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			/* Key is the user ID, value is GroupMeUser */

			GroupMeUser *u = value;
			gchar *username = groupme_create_fullname(u);
			PurpleBuddy *buddy = purple_blist_find_buddy(da->account, username);
			g_free(username);

			if (buddy && purple_strequal(purple_buddy_get_alias(buddy), identifier)) {
				user = u;
				break;
			}
		}
	}

	/* If that fails, find it by nick */
	if (!user && guild) {
		guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, identifier);

		if (uid) {
			user = groupme_get_user(da, *uid);
		}
	}

	if (user) {
		g_string_append_printf(result, "&lt;@%" G_GUINT64_FORMAT "&gt; ", user->id);
	} else if (guild != NULL) {
		/* If that fails, find a role */
		guint64 role = groupme_find_role_by_name(guild, identifier);

		if (role) {
			g_string_append_printf(result, "&lt;@&amp;%" G_GUINT64_FORMAT "&gt; ", role);
		} else {
			/* If that fails, find a channel */
			guint64 channel = groupme_find_channel_by_name(guild, identifier);

			if(channel) {
				g_string_append_printf(result, "&lt;#%" G_GUINT64_FORMAT "&gt; ", channel);
			} else {
				/* If all else fails, trap out */
				g_string_append(result, match_string);
			}
		}
	} else {
		g_string_append(result, match_string);
	}

	g_free(match_string);
	g_free(identifier);

	return FALSE;
}

static gchar *
groupme_make_mentions(GroupMeAccount *da, GroupMeGuild *guild, gchar *message)
{
	GroupMeAccountGuild ag = {.account = da, .guild = guild };
	gchar *tmp = g_regex_replace_eval(natural_mention_regex, message, -1, 0, 0, groupme_make_mention, &ag, NULL);

	if (tmp != NULL) {
		g_free(message);
		return tmp;
	}

	return message;
}

#define HTML_TOGGLE_OUT(f, a, b)           \
	out = g_string_append(out, f ? b : a); \
	f = !f;

/* workaround errata in GroupMe's (users') markdown implementation */

static gboolean
groupme_underscore_match(const gchar *html, int i)
{
	while (html[i] != ' ' && html[i]) {
		if (html[i++] == '_') {
			return !html[i] || html[i] == ' ';
		}
	}

	return FALSE;
}

static gchar *
groupme_convert_markdown(const gchar *html)
{
	g_return_val_if_fail(html != NULL, NULL);
	
	guint html_len = strlen(html);
	GString *out = g_string_sized_new(html_len * 2);

	gboolean s_bold = FALSE;
	gboolean s_italics = FALSE;
	gboolean s_underline = FALSE;
	gboolean s_strikethrough = FALSE;
	gboolean s_codeblock = FALSE;
	gboolean s_codebit = FALSE;

	for (guint i = 0; i < html_len; ++i) {
		char c = html[i];

		if ((s_codeblock || s_codebit) && c != '`') {
			out = g_string_append_c(out, html[i]);
			continue;
		}

		if (c == '\\') {
			out = g_string_append_c(out, html[++i]);
		} else if (c == '*') {
			if (html[i + 1] == '*') {
				HTML_TOGGLE_OUT(s_bold, "<b>", "</b>");
				i += 1;
			} else {
				if ((s_italics && html[i - 1] != ' ') || (!s_italics && html[i + 1] != ' ')) {
					HTML_TOGGLE_OUT(s_italics, "<i>", "</i>");
				} else {
					out = g_string_append_c(out, html[i]);
				}
			}
		} else if (c == '~' && html[i + 1] == '~') {
			HTML_TOGGLE_OUT(s_strikethrough, "<s>", "</s>");
			++i;
		} else if (c == '_') {
			if (html[i + 1] == '_') {
				HTML_TOGGLE_OUT(s_underline, "<u>", "</u>");
			} else {
				if (s_italics || groupme_underscore_match(html, i + 1)) {
					HTML_TOGGLE_OUT(s_italics, "<i>", "</i>");
				} else {
					out = g_string_append_c(out, html[i]);
				}
			}
		} else if (c == '`') {
			if (html[i + 1] == '`' && html[i + 2] == '`') {
				if (!s_codeblock) {
					while (html[i] != '\n' && html[i] != ' ' && html[i]) {
						++i;
					}

					out = g_string_append(out, "<br/><span style='font-family: monospace; white-space: pre'>");
				} else {
					out = g_string_append(out, "</span>");
					i += 2;
				}

				s_codeblock = !s_codeblock;
			} else {
				HTML_TOGGLE_OUT(s_codebit, "<span style='font-family: monospace; white-space: pre'>", "</span>");
			}
		} else {
			out = g_string_append_c(out, c);
		}
	}

	return g_string_free(out, FALSE);
}

static gchar *
groupme_create_nickname(GroupMeUser *author, GroupMeGuild *guild)
{
	if (!guild) {
		return groupme_create_fullname(author);
	}

	gchar *name = g_hash_table_lookup_int64(guild->nicknames, author->id);

	if (!name) {
		name = groupme_create_fullname(author);
	} else {
		name = g_strdup(name);
	}

	return name;
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

	GroupMeGuild *guild = NULL;
	groupme_get_channel_global_int_guild(da, room_id, &guild);

	if (!guild) {
		goto bail;
	}

	guint64 *uid = g_hash_table_lookup(guild->nicknames_rev, who);

	if (uid) {
		GroupMeUser *user = groupme_get_user(da, *uid);
		return groupme_create_fullname(user);
	}

/* Probably a fullname already, bail out */
bail:
	return g_strdup(who);
}

static guint64
groupme_process_message(GroupMeAccount *da, GroupMeChannel *channel, JsonObject *data, gboolean edited)
{
	guint64 msg_id = to_int(json_object_get_string_member(data, "id"));
	guint64 author_id = to_int(json_object_get_string_member(data, "sender_id"));

	const gchar *content = json_object_get_string_member(data, "text");
	const gchar *timestamp_str = json_object_get_string_member(data, "created_at");
	time_t timestamp = purple_str_to_time(timestamp_str, FALSE, NULL, NULL, NULL);

	JsonArray *attachments = json_object_get_array_member(data, "attachments");
#if 0
	JsonArray *mentions = json_object_get_array_member(data, "mentions");
	JsonArray *mention_roles = json_object_get_array_member(data, "mention_roles");
#endif

	PurpleMessageFlags flags;
	gchar *tmp;
	gint i;

#if 0
	if (author_id == da->self_user_id) {
		flags = PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED;
	} else {
		flags = PURPLE_MESSAGE_RECV;
	}
#endif
	flags = PURPLE_MESSAGE_RECV;

#if 0
	if (mentions) {
		for (i = json_array_get_length(mentions) - 1; i >= 0; i--) {
			JsonObject *user = json_array_get_object_element(mentions, i);
			guint64 id = to_int(json_object_get_string_member(user, "id"));

			if (id == da->self_user_id) {
				flags |= PURPLE_MESSAGE_NICK;
			}
		}
	}

	if (mention_roles && guild) {
		GroupMeUser *self = groupme_get_user(da, da->self_user_id);
		if (self) {
			GroupMeGuildMembership *membership = g_hash_table_lookup_int64(self->guild_memberships, guild->id);

			for (i = json_array_get_length(mention_roles) - 1; i >= 0; i--) {
				guint64 id = to_int(json_array_get_string_element(mention_roles, i));

				for (guint i = 0; i < membership->roles->len; i++) {
					guint64 role_id = g_array_index(membership->roles, guint64, i);

					if (role_id == id) {
						flags |= PURPLE_MESSAGE_NICK;
						break;
					}
				}
			}
		}
	}

	if (mentions || mention_roles) {
		escaped_content = groupme_replace_mentions_bare(da, guild, escaped_content);
	}

	if (json_object_get_boolean_member(data, "mention_everyone")) {
		flags |= PURPLE_MESSAGE_NICK;
	}

	/* Replace <:emoji:id> with emojis */
	tmp = g_regex_replace_eval(emoji_regex, escaped_content, -1, 0, 0, groupme_replace_emoji, da, NULL);

	if (tmp != NULL) {
		g_free(escaped_content);
		escaped_content = tmp;
	}

	/* translate GroupMe-formatted actions into /me syntax */
	tmp = g_regex_replace(action_star_regex, escaped_content, -1, 0, "/me \\1", 0, NULL);

	if (tmp != NULL) {
		g_free(escaped_content);
		escaped_content = tmp;
	}

	tmp = groupme_convert_markdown(escaped_content);
	g_free(escaped_content);
	escaped_content = tmp;

	/* Add prefix for edited messages */
	if (edited) {
		tmp = g_strconcat("EDIT: ", escaped_content, NULL);
		g_free(escaped_content);
		escaped_content = tmp;
	}
#endif

#if 0
	if (g_hash_table_contains(da->one_to_ones, channel_id_s)) {
		/* private message */

		if (author_id == da->self_user_id) {
			if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
				PurpleConversation *conv;
				PurpleIMConversation *imconv;
				PurpleMessage *msg;

				gchar *username = g_hash_table_lookup(da->one_to_ones, channel_id_s);
				imconv = purple_conversations_find_im_with_account(username, da->account);

				if (imconv == NULL) {
					imconv = purple_im_conversation_new(da->account, username);
				}

				conv = PURPLE_CONVERSATION(imconv);

				if (escaped_content && *escaped_content) {
					msg = purple_message_new_outgoing(username, escaped_content, flags);
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
			}
		} else {
			GroupMeUser *author = groupme_upsert_user(da->new_users, author_obj);
			gchar *merged_username = groupme_create_fullname(author);

			if (escaped_content && *escaped_content) {
				purple_serv_got_im(da->pc, merged_username, escaped_content, flags, timestamp);
			}

			if (attachments) {
				for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
					JsonObject *attachment = json_array_get_object_element(attachments, i);
					const gchar *url = json_object_get_string_member(attachment, "url");

					purple_serv_got_im(da->pc, merged_username, url, flags, timestamp);
				}
			}

			g_free(merged_username);
		}
	} else if (!nonce || !g_hash_table_remove(da->sent_message_ids, nonce)) {
#endif
		/* TODO: Direct messages */

		/* Open the buffer if it's not already */
#if 0
		int head_count = guild ? guild->members->len : 0;
		gboolean mentioned = flags & PURPLE_MESSAGE_NICK;

		if (mentioned || (head_count < purple_account_get_int(da->account, "large-channel-count", 20))) {
			groupme_open_chat(da, channel_id, NULL, mentioned);
		}
#endif
		groupme_open_chat(da, channel->id, NULL, FALSE);

#if 0
		gchar *name = NULL;
		if (json_object_has_member(data, "webhook_id")) {
			name = g_strdup(json_object_get_string_member(author_obj, "username"));
		} else {
			GroupMeUser *author = groupme_upsert_user(da->new_users, author_obj);
			name = groupme_create_nickname(author, guild);
		}
#endif
		gchar *name = json_object_get_string_member(data, "name");
		printf("<%s> %s\n", name, content);

		if (content && *content) {
			printf("Channel %d\n", channel->id);
			purple_serv_got_chat_in(da->pc, groupme_chat_hash(channel->id), name, flags, content, timestamp);
		}

		if (attachments) {
			for (i = json_array_get_length(attachments) - 1; i >= 0; i--) {
				JsonObject *attachment = json_array_get_object_element(attachments, i);

				if (json_object_has_member(attachment, "url")) {
					const gchar *url = json_object_get_string_member(attachment, "url");
					purple_serv_got_chat_in(da->pc, groupme_chat_hash(channel->id), name, flags, url, timestamp);
				}
			}
		}

		//g_free(name);
#if 0
	}

	g_free(escaped_content);
#endif

	return msg_id;
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

	g_hash_table_iter_init(&channel_iter, guild->channels);

	while (g_hash_table_iter_next(&channel_iter, &key, &value)) {
		GroupMeChannel *channel = value;
		PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, groupme_chat_hash(channel->id));

		if (chat && purple_chat_conversation_has_user(chat, old_safe)) {
			purple_chat_conversation_rename_user(chat, old_safe, nick);
		}
	}

	g_free(nick);
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

	if (!group) {
		group = groupme_get_or_create_default_group();
	}
	
	/* Don't re-add the channel to the same group */
	
	if (groupme_find_chat_in_group(da->account, id, group) == NULL) {
		PurpleChat *chat = purple_chat_new(da->account, channel->name, components);
		purple_blist_add_chat(chat, group, NULL);
	} else {
		g_hash_table_unref(components);
	}
}

static void
groupme_process_dispatch(GroupMeAccount *da, const gchar *type, JsonObject *data)
{
	if (purple_strequal(type, "PRESENCE_UPDATE")) {
		GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		groupme_update_status(user, data);

		gchar *username = groupme_create_fullname_from_id(da, user->id);
		const gchar *guild_id = json_object_get_string_member(data, "guild_id");
		gint64 idle_since = json_object_get_int_member(data, "idle_since");

		if (guild_id) {
			GHashTableIter iter;
			gpointer key, value;

			GroupMeGuild *guild = groupme_get_guild(da, to_int(guild_id));
			gchar *nickname = groupme_create_nickname(user, guild);

			g_hash_table_iter_init(&iter, guild->channels);

			while (g_hash_table_iter_next(&iter, &key, &value)) {
				GroupMeChannel *channel = value;
				PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, groupme_chat_hash(channel->id));

				if (chat != NULL) {
					if (user->status == USER_OFFLINE) {
						if (purple_chat_conversation_has_user(chat, nickname)) {
							purple_chat_conversation_remove_user(chat, nickname, NULL);
						}
					} else if (!purple_chat_conversation_has_user(chat, nickname)) {
						PurpleChatUserFlags flags = groupme_get_user_flags(da, guild, user);
						purple_chat_conversation_add_user(chat, nickname, NULL, flags, FALSE);
					}
				}
			}
			g_free(nickname);
			
		} else if (username) {
			const gchar *status = json_object_get_string_member(data, "status");
			purple_protocol_got_user_status(da->account, username, status, "message", user->game, NULL);
			purple_protocol_got_user_idle(da->account, username, idle_since ? TRUE : FALSE, 0);
		}

		g_free(username);
	} else if (purple_strequal(type, "MESSAGE_CREATE") || purple_strequal(type, "MESSAGE_UPDATE")) { /* TODO */
		//groupme_process_message(da, data, purple_strequal(type, "MESSAGE_UPDATE"));

		const gchar *channel_id = json_object_get_string_member(data, "channel_id");

		if (!channel_id) {
			return;
		}

		GroupMeGuild *guild = NULL;
		groupme_get_channel_global_int_guild(da, to_int(channel_id), &guild);

		guint64 tmp = to_int(channel_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, groupme_chat_hash(tmp));

		if (!chatconv) {
			return;
		}

		JsonObject *json = json_object_get_object_member(data, "author");
		gchar *n = groupme_create_nickname_from_id(da, guild, to_int(json_object_get_string_member(json, "id")));

		struct groupme_group_typing_data ctx = {
			.da = da,
			.channel_id = tmp,
			.username = n,
			.set = FALSE,
			.free_me = FALSE
		};

		groupme_set_group_typing(&ctx);

		g_free(n);
	} else if (purple_strequal(type, "TYPING_START")) {
		const gchar *channel_id = json_object_get_string_member(data, "channel_id");
		guint64 user_id = to_int(json_object_get_string_member(data, "user_id"));

		/* Don't display typing notifications from ourselves */
		if (user_id == da->self_user_id) {
			return;
		}

		if (!channel_id) {
			return;
		}

		GroupMeChannel *channel = groupme_get_channel_global(da, channel_id);

		if (channel != NULL) {
			GroupMeGuild *guild = groupme_get_guild(da, channel->guild_id);
			gchar *username = groupme_create_nickname_from_id(da, guild, user_id);

			struct groupme_group_typing_data set = {
				.da = da,
				.channel_id = to_int(channel_id),
				.username = username,
				.set = TRUE,
				.free_me = FALSE
			};

			groupme_set_group_typing(&set);

			struct groupme_group_typing_data *clear = g_memdup(&set, sizeof(set));
			clear->set = FALSE;
			clear->free_me = TRUE;

			g_timeout_add_seconds(10, groupme_set_group_typing, clear);
		} else {
			GroupMeUser *user = groupme_get_user(da, user_id);
			gchar *merged_username = groupme_create_fullname(user);
			
			purple_serv_got_typing(da->pc, merged_username, 10, PURPLE_IM_TYPING);
			
			g_free(merged_username);
		}
	} else if (purple_strequal(type, "CHANNEL_CREATE")) {
		const gchar *channel_id = json_object_get_string_member(data, "id");
		gint64 channel_type = json_object_get_int_member(data, "type");
		const gchar *last_message_id = json_object_get_string_member(data, "last_message_id");

		if (channel_type == 1) {
			/* 1:1 direct message */

			JsonObject *first_recipient = json_array_get_object_element(json_object_get_array_member(data, "recipients"), 0);

			if (first_recipient != NULL) {
				const gchar *username = json_object_get_string_member(first_recipient, "username");
				const gchar *discriminator = json_object_get_string_member(first_recipient, "discriminator");

				g_hash_table_replace(da->one_to_ones, g_strdup(channel_id), groupme_combine_username(username, discriminator));
				g_hash_table_replace(da->last_message_id_dm, g_strdup(channel_id), g_strdup(last_message_id));
				g_hash_table_replace(da->one_to_ones_rev, groupme_combine_username(username, discriminator), g_strdup(channel_id));
			}
		} 
	} else if (purple_strequal(type, "CHANNEL_UPDATE")) {
		guint64 channel_id = to_int(json_object_get_string_member(data, "id"));
		gint64 channel_type = json_object_get_int_member(data, "type");

		if ((channel_type == 0 && json_object_has_member(data, "topic")) || channel_type == 3) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(da->pc, groupme_chat_hash(channel_id));

			if (chatconv) {
				purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(data, (channel_type == 1 ? "topic" : "name")));
			}
		}
	} else if (purple_strequal(type, "RELATIONSHIP_ADD")) {
		groupme_create_relationship(da, data);
	} else if (purple_strequal(type, "RELATIONSHIP_REMOVE")) {
		guint64 user_id = to_int(json_object_get_string_member(data, "id"));
		GroupMeUser *user = groupme_get_user(da, user_id);

		if (user) {
			gchar *username = groupme_create_fullname(user);
			gint64 type = json_object_get_int_member(data, "type");
			
			if (username != NULL) {
				if (type == 2) {
					/* remove user from blocklist */
					purple_account_privacy_deny_remove(da->account, username, TRUE);
					
				} else {
					PurpleBuddy *buddy = purple_blist_find_buddy(da->account, username);
					purple_blist_remove_buddy(buddy);

					g_hash_table_remove(da->one_to_ones, g_hash_table_lookup(da->one_to_ones_rev, username));
					g_hash_table_remove(da->last_message_id_dm, g_hash_table_lookup(da->one_to_ones_rev, username));
					g_hash_table_remove(da->one_to_ones_rev, username);
				}

				g_free(username);
			}
		}
	} else if (purple_strequal(type, "RESUMED")) {
		purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
	} else if (purple_strequal(type, "READY")) {
		JsonObject *self_user = json_object_get_object_member(data, "user");
		GroupMeUser *self_user_obj = NULL;
		da->self_user_id = to_int(json_object_get_string_member(self_user, "id"));

		if (!purple_account_get_private_alias(da->account)) {
			purple_account_set_private_alias(da->account, json_object_get_string_member(self_user, "username"));
		}

		g_free(da->self_username);
		da->self_username = groupme_combine_username(json_object_get_string_member(self_user, "username"), json_object_get_string_member(self_user, "discriminator"));
		purple_connection_set_display_name(da->pc, da->self_username);

		g_free(da->session_id);
		da->session_id = g_strdup(json_object_get_string_member(data, "session_id"));

		self_user_obj = groupme_get_user(da, da->self_user_id);
		if (!self_user_obj) {
			/* Ensure user is non-null... */
			groupme_upsert_user(da->new_users, self_user);
		}

		groupme_got_relationships(da, json_object_get_member(data, "relationships"), NULL);
		groupme_got_private_channels(da, json_object_get_member(data, "private_channels"), NULL);
		groupme_got_presences(da, json_object_get_member(data, "presences"), NULL);
		groupme_got_guilds(da, json_object_get_member(data, "guilds"), NULL);
		groupme_got_read_states(da, json_object_get_member(data, "read_state"), NULL);

		if (!self_user_obj) {
			/* ...But remove afterward, this user object is partial */
			g_hash_table_remove(da->new_users, &da->self_user_id);
		}
		
		/* ready for libpurple to join chats etc */
		purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
		
	} else if (purple_strequal(type, "GUILD_SYNC") || purple_strequal(type, "GUILD_CREATE")) {
		if (purple_strequal(type, "GUILD_CREATE")) {
			groupme_populate_guild(da, data);
		}

		JsonArray *presences = json_object_get_array_member(data, "presences");
		JsonArray *members = json_object_get_array_member(data, "members");
		guint64 guild_id = to_int(json_object_get_string_member(data, "id"));

		GroupMeGuild *guild = groupme_get_guild(da, guild_id);

		g_array_set_size(guild->members, 0);
		
		/* all members in small groups, online in large */
		for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
			JsonObject *member = json_array_get_object_element(members, j);
			JsonObject *user = json_object_get_object_member(member, "user");

			GroupMeUser *u = groupme_upsert_user(da->new_users, user);
			GroupMeGuildMembership *membership = groupme_new_guild_membership(guild_id, member);
			g_hash_table_replace_int64(u->guild_memberships, membership->id, membership);
			g_array_append_val(guild->members, u->id);

			g_free(groupme_alloc_nickname(u, guild, membership->nick));

			JsonArray *roles = json_object_get_array_member(member, "roles");

			for (int k = json_array_get_length(roles) - 1; k >= 0; k--) {
				guint64 role = to_int(json_array_get_string_element(roles, k));
				g_array_append_val(membership->roles, role);
			}
		}

		/* Update online users first */
		for (int j = json_array_get_length(presences) - 1; j >= 0; j--) {
			JsonObject *presence = json_array_get_object_element(presences, j);

			GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(presence, "user"));
			groupme_update_status(user, presence);
		}

		/* Add online people to any open chats */
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, groupme_get_guild(da, guild_id)->channels);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			GList *users = NULL, *flags = NULL;
			GroupMeChannel *channel = value;

			PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, groupme_chat_hash(channel->id));
			if (chat == NULL) {
				//Skip over closed chats
				continue;
			}
		
			/* Presence only contains online users */
			for (int j = json_array_get_length(presences) - 1; j >= 0; j--) {
				JsonObject *presence = json_array_get_object_element(presences, j);

				GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(presence, "user"));
				
				guint64 permission = groupme_compute_permission(da, user, channel);

				/* must have READ_MESSAGES */
				if ((permission & 0x400)) {
					PurpleChatUserFlags cbflags = groupme_get_user_flags(da, guild, user);
					gchar *nickname = groupme_create_nickname(user, guild);
					
					if (nickname != NULL) {
						users = g_list_prepend(users, nickname);
						flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
					}
				}
			}
			
			purple_chat_conversation_clear_users(chat);
			purple_chat_conversation_add_users(chat, users, NULL, flags, FALSE);
			
			while (users != NULL) {
				g_free(users->data);
				users = g_list_delete_link(users, users);
			}

			g_list_free(users);
			g_list_free(flags);
		}


		groupme_print_users(da->new_users);
	} else if (purple_strequal(type, "GUILD_MEMBER_UPDATE")) {
		GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		GroupMeGuild *guild = groupme_get_guild(da, to_int(json_object_get_string_member(data, "guild_id")));

		const gchar *new_nick = json_object_get_string_member(data, "nick");
		const gchar *old_nick = g_hash_table_lookup_int64(guild->nicknames, user->id);

		if (!purple_strequal(new_nick, old_nick)) {
			groupme_got_nick_change(da, user, guild, new_nick, old_nick, FALSE);
		}

		/* TODO: Track role changes */
	} else if (purple_strequal(type, "CHANNEL_RECIPIENT_ADD") || purple_strequal(type, "CHANNEL_RECIPIENT_REMOVE")) {
		GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(data, "user"));
		gchar *name = groupme_create_fullname(user);
		guint64 room_id = to_int(json_object_get_string_member(data, "channel_id"));
		PurpleChatConversation *chat = purple_conversations_find_chat(da->pc, groupme_chat_hash(room_id));

		if (purple_strequal(type, "CHANNEL_RECIPIENT_ADD")) {
			purple_chat_conversation_add_user(chat, name, NULL, PURPLE_CHAT_USER_NONE, TRUE);
		} else {
			purple_chat_conversation_remove_user(chat, name, NULL);
		}
		
		g_free(name);
	} else {
		purple_debug_info("groupme", "Unhandled message type '%s'\n", type);
	}
}

PurpleGroup *
groupme_get_or_create_default_group()
{
	PurpleGroup *groupme_group = purple_blist_find_group("GroupMe");

	if (!groupme_group) {
		groupme_group = purple_group_new("GroupMe");
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

static void
groupme_roomlist_got_list(GroupMeAccount *da, GroupMeGuild *guild, gpointer user_data)
{
	PurpleRoomlist *roomlist = user_data;
	const gchar *guild_name = guild ? guild->name : _("Group DMs");
	PurpleRoomlistRoom *category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, guild_name, NULL);
	purple_roomlist_room_add_field(roomlist, category, (gpointer) guild_name);
	purple_roomlist_room_add(roomlist, category);

	GHashTableIter iter;
	gpointer key, value;

	if (guild != NULL) {
		g_hash_table_iter_init(&iter, guild->channels);
	} 

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GroupMeChannel *channel = value;
		PurpleRoomlistRoom *room;

		gchar *channel_id = from_int(channel->id);
		gchar *type_str;

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, "", category);

		purple_roomlist_room_add_field(roomlist, room, channel_id);
		purple_roomlist_room_add_field(roomlist, room, channel->name);

		switch (channel->type) {
			case 0:
				type_str = _("Text");
				break;
			
			case 1:
				type_str = _("Direct Message");
				break;
			
			case 2:
				type_str = _("Voice");
				break;
			
			case 3:
				type_str = _("Group DM");
				break;
			
			case 4:
				type_str = _("Guild Category");
				break;

			default:
				type_str = _("Unknown");
				break;
		}

		purple_roomlist_room_add_field(roomlist, room, type_str);

		purple_roomlist_room_add(roomlist, room);
		g_free(channel_id);
	}
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

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Room Type"), "type", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);

	// Add group-DM's first
	groupme_roomlist_got_list(da, NULL, roomlist);
	
	GHashTableIter iter;
	gpointer key, guild;

	g_hash_table_iter_init(&iter, da->new_guilds);

	while (g_hash_table_iter_next(&iter, &key, &guild)) {
		groupme_roomlist_got_list(da, guild, roomlist);
	}

	purple_roomlist_set_in_progress(roomlist, FALSE);

	return roomlist;
}

void
groupme_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	GroupMeAccount *ya = purple_connection_get_protocol_data(pc);
	const gchar *status_id = purple_status_get_id(status);
	gchar *postdata;

	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();

	if (g_str_has_prefix(status_id, "set-")) {
		status_id = &status_id[4];
	}

	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status_id);
	json_object_set_int_member(data, "since", 0);

	if (purple_account_get_bool(account, "use-status-as-game", FALSE)) {
		JsonObject *game = json_object_new();
		const gchar *message = purple_status_get_attr_string(status, "message");

		json_object_set_int_member(game, "type", 0); /* 0 = Playing, 1 = Streaming */
		json_object_set_string_member(game, "name", message);
		json_object_set_object_member(data, "game", game);
	} else {
		json_object_set_null_member(data, "game");
	}

	json_object_set_boolean_member(data, "afk", FALSE);
	json_object_set_object_member(obj, "d", data);

	groupme_socket_write_json(ya, obj);

	data = json_object_new();
	json_object_set_string_member(data, "status", status_id);
	postdata = json_object_to_string(data);

	groupme_fetch_url_with_method(ya, "PATCH", "https://" GROUPME_API_SERVER "/api/v6/users/@me/settings", postdata, NULL, NULL);

	g_free(postdata);
	json_object_unref(data);
}

void
groupme_set_idle(PurpleConnection *pc, int idle_time)
{
	GroupMeAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *obj = json_object_new();
	JsonObject *data = json_object_new();
	const gchar *status = "idle";
	gint64 since = (time(NULL) - idle_time) * 1000;

	if (idle_time < 20) {
		status = "online";
		since = 0;
	}

	json_object_set_int_member(obj, "op", 3);
	json_object_set_string_member(data, "status", status);
	json_object_set_int_member(data, "since", since);
	json_object_set_boolean_member(data, "afk", idle_time >= 20);
	json_object_set_object_member(obj, "d", data);

	groupme_socket_write_json(ya, obj);
}

static void
groupme_restart_channel(GroupMeAccount *da)
{
	purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTING);
	groupme_start_socket(da);
}

static void
groupme_build_groups_from_blist(GroupMeAccount *ya)
{
	PurpleBlistNode *node;

	for (node = purple_blist_get_root();
		 node != NULL;
		 node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_BUDDY(node)) {
			const gchar *groupme_id;
			const gchar *name;
			PurpleBuddy *buddy = PURPLE_BUDDY(node);

			if (purple_buddy_get_account(buddy) != ya->account) {
				continue;
			}

			name = purple_buddy_get_name(buddy);
			groupme_id = purple_blist_node_get_string(node, "groupme_id");

			if (groupme_id != NULL) {
				g_hash_table_replace(ya->one_to_ones, g_strdup(groupme_id), g_strdup(name));
				g_hash_table_replace(ya->last_message_id_dm, g_strdup(groupme_id), g_strdup("0"));
				g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(groupme_id));
			}
		}
	}
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
groupme_friends_auth_accept(
#if PURPLE_VERSION_CHECK(3, 0, 0)
  const gchar *response,
#endif
  gpointer userdata)
{
	GroupMeUserInviteResponseStore *store = userdata;
	GroupMeUser *user = store->user;
	GroupMeAccount *da = store->da;

	gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	groupme_fetch_url_with_method(da, "PUT", url, NULL, NULL, NULL);
	g_free(url);

	g_free(store);
}

static void
groupme_friends_auth_reject(
#if PURPLE_VERSION_CHECK(3, 0, 0)
  const gchar *response,
#endif
  gpointer userdata)
{
	GroupMeUserInviteResponseStore *store = userdata;
	GroupMeUser *user = store->user;
	GroupMeAccount *da = store->da;

	gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	groupme_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);

	g_free(store);
}

static void
groupme_create_relationship(GroupMeAccount *da, JsonObject *json)
{
	GroupMeUser *user = groupme_upsert_user(da->new_users, json_object_get_object_member(json, "user"));
	gint64 type = json_object_get_int_member(json, "type");
	gchar *merged_username = groupme_create_fullname(user);

	if (type == 3) {
		/* request add */
		GroupMeUserInviteResponseStore *store = g_new0(GroupMeUserInviteResponseStore, 1);

		store->da = da;
		store->user = user;

		purple_account_request_authorization(da->account, merged_username, NULL, NULL, NULL, FALSE, groupme_friends_auth_accept, groupme_friends_auth_reject, store);
	} else if (type == 1) {
		/* buddy on list */
		PurpleBuddy *buddy = purple_blist_find_buddy(da->account, merged_username);

		if (buddy == NULL) {
			buddy = purple_buddy_new(da->account, merged_username, user->name);
			purple_blist_add_buddy(buddy, NULL, groupme_get_or_create_default_group(), NULL);
		}

		groupme_get_avatar(da, user);
		
	} else if (type == 2) {
		/* blocked buddy */
		purple_account_privacy_deny_add(da->account, merged_username, TRUE);
		
	} else if (type == 4) {
		/* pending buddy */
	}

	g_free(merged_username);
}

static void
groupme_got_relationships(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *relationships = json_node_get_array(node);
	guint len = json_array_get_length(relationships);

	for (int i = len - 1; i >= 0; i--) {
		groupme_create_relationship(da, json_array_get_object_element(relationships, i));
	}
}

static void
groupme_got_private_channels(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *private_channels = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(private_channels);

	for (i = len - 1; i >= 0; i--) {
		JsonObject *channel = json_array_get_object_element(private_channels, i);
		JsonArray *recipients = json_object_get_array_member(channel, "recipients");
		const gchar *room_id = json_object_get_string_member(channel, "id");
		const gchar *last_message_id = json_object_get_string_member(channel, "last_message_id");
		gint64 room_type = json_object_get_int_member(channel, "type");

		if (room_type == 1) {
			/* One-to-one DM */
			JsonObject *user = json_array_get_object_element(recipients, 0);
			const gchar *username = json_object_get_string_member(user, "username");
			const gchar *discriminator = json_object_get_string_member(user, "discriminator");
			gchar *merged_username = groupme_combine_username(username, discriminator);

			g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(merged_username));
			g_hash_table_replace(da->one_to_ones_rev, g_strdup(merged_username), g_strdup(room_id));
			g_hash_table_replace(da->last_message_id_dm, g_strdup(room_id), g_strdup(last_message_id));

			g_free(merged_username);
		} 
	}
}

static void
groupme_got_presences(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *presences = json_node_get_array(node);
	gint i;
	guint len = json_array_get_length(presences);

	for (i = len - 1; i >= 0; i--) {
		/* TODO convert to user object */
		JsonObject *presence = json_array_get_object_element(presences, i);
		JsonObject *user = json_object_get_object_member(presence, "user");
		const gchar *status = json_object_get_string_member(presence, "status");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *discriminator = json_object_get_string_member(user, "discriminator");
		JsonObject *game = json_object_get_object_member(presence, "game");
		const gchar *game_name = json_object_get_string_member(game, "name");
		gchar *merged_username = groupme_combine_username(username, discriminator);

		purple_protocol_got_user_status(da->account, merged_username, status, "message", game_name, NULL);
		purple_protocol_got_user_idle(da->account, merged_username, purple_strequal(status, "idle"), 0);

		g_free(merged_username);
	}
}

static void
groupme_populate_guild(GroupMeAccount *da, JsonObject *guild)
{
	GroupMeGuild *g = groupme_upsert_guild(da->new_guilds, guild);
	gchar *name = json_object_get_string_member(guild, "name");
	printf("Chat w/ name: %s\n", name);

	/* Add chat to blist */
	PurpleGroup *group = groupme_get_or_create_default_group();
	groupme_add_channel_to_blist(da, g, group);

	JsonArray *members = json_object_get_array_member(guild, "members");

	/* Populate members */
	for (int j = json_array_get_length(members) - 1; j >= 0; j--) {
		JsonObject *member = json_array_get_object_element(members, j);

		GroupMeUser *u = groupme_upsert_user(da->new_users, member);
		g_array_append_val(g->members, u->id);
	}

#if 0
	JsonArray *channels = json_object_get_array_member(guild, "channels");
	JsonArray *roles = json_object_get_array_member(guild, "roles");

	for (int j = json_array_get_length(roles) - 1; j >= 0; j--) {
		JsonObject *role = json_array_get_object_element(roles, j);
		groupme_add_guild_role(g, role);
	}

	for (int j = json_array_get_length(channels) - 1; j >= 0; j--) {
		JsonObject *channel = json_array_get_object_element(channels, j);

		GroupMeChannel *c = groupme_add_channel(g, channel, g->id);

		JsonArray *permission_overrides = json_object_get_array_member(channel, "permission_overwrites");

		for (int k = json_array_get_length(permission_overrides) - 1; k >= 0; k--) {
			JsonObject *permission_override = json_array_get_object_element(permission_overrides, k);
			groupme_add_permission_override(c, permission_override);
		}
	}
#endif
}

static void
groupme_got_guilds(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *container = json_node_get_object(node);
	JsonArray *guilds = json_object_get_array_member(container, "response");
	guint len = json_array_get_length(guilds);
	JsonArray *guild_ids = json_array_new();
	JsonObject *obj;

	printf("Got groups\n");
	for (int i = len - 1; i >= 0; i--) {
		JsonObject *guild = json_array_get_object_element(guilds, i);
		groupme_populate_guild(da, guild);
	}
}

/* If count is explicitly specified, use a static request (DMs).
 * If it is not, use a dynamic request (rooms).
 * TODO: Possible edge case if there are over 100 incoming DMs?
 */

static void
groupme_get_history(GroupMeAccount *da, const gchar *channel, const gchar *last, int count)
{
	gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/channels/%s/messages?limit=%d&after=%s", channel, count ? count : 100, last);
	groupme_fetch_url(da, url, NULL, count ? groupme_got_history_static : groupme_got_history_of_room, count ? NULL : groupme_get_channel_global(da, channel));
	g_free(url);
}

static void
groupme_got_read_states(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonArray *states = json_node_get_array(node);
	guint len = json_array_get_length(states);

	for (int i = len - 1; i >= 0; i--) {
		JsonObject *state = json_array_get_object_element(states, i);

		const gchar *channel = json_object_get_string_member(state, "id");
		const gchar *last_id = json_object_get_string_member(state, "last_message_id");
		guint mentions = json_object_get_int_member(state, "mention_count");

		if (mentions) {
			gboolean isDM = g_hash_table_contains(da->one_to_ones, channel);

			if (isDM) {
				groupme_get_history(da, channel, last_id, mentions * 2);
			} else {
				/* TODO: fetch channel history */
				GroupMeChannel *dchannel = groupme_get_channel_global(da, channel);
				if (dchannel != NULL) {
					purple_debug_misc("groupme", "%d unhandled mentions in channel %s\n", mentions, dchannel->name);
				}
			}
		}
	}
}

static void
groupme_got_self(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *container = json_node_get_object(node);
	JsonObject *resp = json_object_get_object_member(container, "response");

	da->self_user_id = to_int(json_object_get_string_member(resp, "id"));
	da->self_username = g_strdup(json_object_get_string_member(resp, "name"));

	/* Now that we have the user ID, we can start the websocket handshake */
	printf("User ID %X (%s)\n", da->self_user_id, da->self_username);
	{
		printf("Fetching handshake\n");
		const gchar *str = "{\"channel\": \"/meta/handshake\", \"version\": \"1.0\", \"supportedConnectionTypes\": [\"websocket\"], \"id\": 1}";
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

#if 0
	if (!strchr(purple_account_get_username(account), '@')) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, _("Username needs to be an email address"));
		return;
	}
#endif

	pc_flags = purple_connection_get_flags(pc);
	pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
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

	groupme_build_groups_from_blist(da);

	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

#if 0
	da->token = g_strdup(purple_account_get_string(account, "token", NULL));

	if (da->token) {
		groupme_start_socket(da);
	} else {
		JsonObject *data = json_object_new();
		gchar *str;

		json_object_set_string_member(data, "email", purple_account_get_username(account));
		json_object_set_string_member(data, "password", purple_connection_get_password(da->pc));

		str = json_object_to_string(data);
		groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/api/v6/auth/login", str, groupme_login_response, NULL);

		g_free(str);
		json_object_unref(data);
	}
#endif
	const gchar *dev_token = purple_connection_get_password(da->pc);
	da->token = dev_token;

	/* Test the REST API */
	groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/users/me?", NULL, groupme_got_self, NULL);
	groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/groups?", NULL, groupme_got_guilds, NULL);

	/* XXX: Authenticate good */
	purple_connection_set_state(da->pc, PURPLE_CONNECTION_CONNECTED);
	
	printf("Dev token: %s\n", dev_token);

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
	printf("process frame!\n");

	purple_debug_info("groupme", "got frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame, -1, NULL)) {
		purple_debug_error("groupme", "Error parsing response: %s\n", frame);
		return TRUE;
	}

	root = json_parser_get_root(parser);

	if (root != NULL) {
		JsonObject *obj = json_node_get_object(root);

		opcode = json_object_get_int_member(obj, "op");

		switch (opcode) {
		case 0: { /* Dispatch */
			const gchar *type = json_object_get_string_member(obj, "t");
			gint64 seq = json_object_get_int_member(obj, "s");

			da->seq = seq;
			groupme_process_dispatch(da, type, json_object_get_object_member(obj, "d"));

			break;
		}

		case 7: { /* Reconnect */
			groupme_start_socket(da);
			break;
		}

		case 9: { /* Invalid session */
			da->seq = 0;
			g_free(da->session_id);
			da->session_id = NULL;

			groupme_send_auth(da);
			break;
		}

		case 10: { /* Hello */
			JsonObject *data = json_object_get_object_member(obj, "d");
			gint64 heartbeat_interval = json_object_get_int_member(data, "heartbeat_interval");
			groupme_send_auth(da);

			if (da->heartbeat_timeout) {
				g_source_remove(da->heartbeat_timeout);
			}

			if (heartbeat_interval) {
				da->heartbeat_timeout = g_timeout_add(json_object_get_int_member(data, "heartbeat_interval"), groupme_send_heartbeat, da);
			} else {
				da->heartbeat_timeout = 0;
			}

			break;
		}

		case 11: { /* Heartbeat ACK */
			break;
		}

		default: {
			purple_debug_info("groupme", "Unhandled op code %" G_GINT64_FORMAT "\n", opcode);
			break;
		}
		}
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
		purple_debug_info("groupme", "sending frame: %*s\n", (int) data_len, data);
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

		do {
			read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);

			if (read_len > 0) {
				ya->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ya->frame_len_progress < ya->frame_len);

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

	printf("Websocket headered\n");
	groupme_send_auth(da);
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

static void
groupme_start_socket(GroupMeAccount *da)
{
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

	GroupMeGuild *guild = NULL;
	groupme_get_channel_global_int_guild(da, room_id, &guild);

	JsonObject *data = json_object_new();
	json_object_set_string_member(data, "nick", new_nick);
	gchar *postdata = json_object_to_string(data);

	gchar *url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/guilds/%" G_GUINT64_FORMAT "/members/@me/nick", guild->id);
	groupme_fetch_url_with_method(da, "PATCH", url, postdata, NULL, NULL);

	g_free(url);
	g_free(postdata);
	json_object_unref(data);

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
			GroupMeChannel *channel = groupme_get_channel_global(da, chatname);

			if (channel != NULL) {
				g_hash_table_insert(defaults, "name", g_strdup(channel->name));
			}

			g_hash_table_insert(defaults, "id", g_strdup(chatname));
		} else {
			GroupMeChannel *channel = groupme_get_channel_global_name(da, chatname);

			if (channel != NULL) {
				g_hash_table_insert(defaults, "name", g_strdup(channel->name));
				g_hash_table_insert(defaults, "id", from_int(channel->id));
			}
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
groupme_got_history_of_room(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *container = json_node_get_object(node);
	JsonObject *resp = json_object_get_object_member(container, "response");
	JsonArray *messages = json_object_get_array_member(resp, "messages");

	GroupMeChannel *channel = user_data;
	gint i, len = json_array_get_length(messages);
	guint64 last_message = /* channel->last_message_id */ 0 /* XXX */;
	guint64 rolling_last_message_id = 0;

	printf("len: %d\n", len);
	printf("reported: %d\n", json_object_get_int_member(resp, "count"));

	/* latest are first */
	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
#if 0
		guint64 id = to_int(json_object_get_string_member(message, "id"));

		if (id >= last_message) {
			break;
		}

#endif
		rolling_last_message_id = groupme_process_message(da, channel, message, FALSE);
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

		printf("XXX\n");
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

/* TODO: Cache better, sane defaults */

/* https://support.groupmeapp.com/hc/en-us/articles/206141927-How-is-the-permission-hierarchy-structured- */

static guint64
groupme_permission_role(GroupMeGuild *guild, guint64 r, guint64 permission)
{
	GroupMeGuildRole *role = g_hash_table_lookup_int64(guild->roles, r);
	return role ? (permission | role->permissions) : permission;
}

static guint64
groupme_permission_role_override(GroupMeChannel *channel, guint64 role, guint64 permission)
{
	GroupMePermissionOverride *ro =
	  g_hash_table_lookup_int64(channel->permission_role_overrides, role);

	return ro ? ((permission & ~(ro->deny)) | ro->allow) : permission;
}

static guint64
groupme_compute_permission(GroupMeAccount *da, GroupMeUser *user, GroupMeChannel *channel)
{
	guint64 uid = user->id;
	guint64 permissions = 0;

	GroupMeGuildMembership *guild_membership = g_hash_table_lookup_int64(user->guild_memberships, channel->guild_id);

	if (guild_membership) {
		/* Should always exist, but just in case... */

		GroupMeGuild *guild = groupme_get_guild(da, channel->guild_id);

		/* @everyone */
		permissions = groupme_permission_role(guild, channel->guild_id, permissions);

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 r = g_array_index(guild_membership->roles, guint64, i);
			permissions = groupme_permission_role(guild, r, permissions);
		}

		permissions = groupme_permission_role_override(channel, channel->guild_id, permissions);

		for (guint i = 0; i < guild_membership->roles->len; i++) {
			guint64 role = g_array_index(guild_membership->roles, guint64, i);
			permissions = groupme_permission_role_override(channel, role, permissions);
		}
	}

	/* Check special permission overrides just for us */

	GroupMePermissionOverride *uo =
	  g_hash_table_lookup_int64(channel->permission_user_overrides, uid);

	if (uo) {
		permissions = (permissions & ~(uo->deny)) | uo->allow;
	}

	return permissions;
}

static void groupme_join_chat(PurpleConnection *pc, GHashTable *chatdata);

static void
groupme_got_channel_info(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	JsonObject *channel = json_node_get_object(node);
	const gchar *id = json_object_get_string_member(channel, "id");

	PurpleChatConversation *chatconv;

	if (id == NULL) {
		/* No permissions?  Should be an error message in json_object_get_string_member(channel, "message") */
		return;
	}

	guint64 tmp = to_int(id);
	chatconv = purple_conversations_find_chat(da->pc, groupme_chat_hash(tmp));

	if (chatconv == NULL) {
		return;
	}

	if (json_object_has_member(channel, "topic")) {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "topic"));
	} else {
		purple_chat_conversation_set_topic(chatconv, NULL, json_object_get_string_member(channel, "name"));
	}

	if (json_object_has_member(channel, "recipients")) {
		// This is a Group DM
		JsonArray *recipients = json_object_get_array_member(channel, "recipients");
		gint i;
		guint len = json_array_get_length(recipients);
		GList *users = NULL, *flags = NULL;

		for (i = len - 1; i >= 0; i--) {
			JsonObject *recipient = json_array_get_object_element(recipients, i);
			GroupMeUser *user = groupme_upsert_user(da->new_users, recipient);
			gchar *fullname = groupme_create_fullname(user);

			if (fullname != NULL) {
				users = g_list_prepend(users, fullname);
				flags = g_list_prepend(flags, PURPLE_CHAT_USER_NONE);
			}
		}

		// Add self
		users = g_list_prepend(users, g_strdup(da->self_username));
		flags = g_list_prepend(flags, PURPLE_CHAT_USER_NONE);

		purple_chat_conversation_clear_users(chatconv);
		purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);

		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}

		g_list_free(users);
		g_list_free(flags);
	} else if (json_object_has_member(channel, "permission_overwrites")) {
		// This is a guild/server room
		GroupMeGuild *guild = groupme_get_guild(da, to_int(json_object_get_string_member(channel, "guild_id")));

		PurpleChatConversation *chat = chatconv;
		GList *users = NULL, *flags = NULL;
		GroupMeChannel *chnl = groupme_get_channel_global_int(da, tmp);
		
		for (guint i = 0; i < guild->members->len; i++) {
			GroupMeUser *user = groupme_get_user(da, g_array_index(guild->members, guint64, i));
			
			/* Ensure that we actually have permissions for this channel */
			guint64 permission = groupme_compute_permission(da, user, chnl);

			/* must have READ_MESSAGES */
			if ((permission & 0x400)) {
				PurpleChatUserFlags cbflags = groupme_get_user_flags(da, guild, user);
				gchar *nickname = groupme_create_nickname(user, guild);

				if (nickname != NULL && user->status != USER_OFFLINE) {
					users = g_list_prepend(users, nickname);
					flags = g_list_prepend(flags, GINT_TO_POINTER(cbflags));
				}
			}
		}

		if (users != NULL) {
			purple_chat_conversation_clear_users(chat);
			purple_chat_conversation_add_users(chat, users, NULL, flags, FALSE);
		}

		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}

		g_list_free(users);
		g_list_free(flags);
	}
}

static GroupMeChannel *
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

		users = g_list_prepend(users, g_strdup(u->name));
		flags = g_list_prepend(flags, PURPLE_CHAT_USER_NONE);
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

static void
groupme_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	GroupMeAccount *da = purple_connection_get_protocol_data(pc);

	guint64 id = to_int(g_hash_table_lookup(chatdata, "id"));
	gchar *name = (gchar *) g_hash_table_lookup(chatdata, "name");

	printf("Joining %s\n", name);

	GroupMeChannel *channel = groupme_open_chat(da, id, name, TRUE);

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

static gboolean
groupme_replace_natural_emoji(const GMatchInfo *match, GString *result, gpointer user_data)
{
	GroupMeGuild *guild = user_data;
	gchar *emoji = g_match_info_fetch(match, 1);

	gchar *emoji_id = g_hash_table_lookup(guild->emojis, emoji);

	if (emoji_id) {
		g_string_append_printf(result, "&lt;:%s:%s&gt;", emoji, emoji_id);
	} else {
		g_string_append_printf(result, ":%s:", emoji);
	}

	g_free(emoji);

	return FALSE;
}

static gchar *
groupme_helper_replace(gchar *a, gchar *b, gchar *c)
{
	gchar *temp = purple_strreplace(a, b, c);
	g_free(a);
	return temp;
}

static gchar *
groupme_html_to_markdown(gchar *html)
{
	html = groupme_helper_replace(html, "<b>", "**");
	html = groupme_helper_replace(html, "</b>", "**");
	html = groupme_helper_replace(html, "<i>", "*");
	html = groupme_helper_replace(html, "</i>", "*");
	html = groupme_helper_replace(html, "<u>", "__");
	html = groupme_helper_replace(html, "</u>", "__");
	html = groupme_helper_replace(html, "<s>", "~~");
	html = groupme_helper_replace(html, "</s>", "~~");

	return html;
}

static gchar *
groupme_escape_md(const gchar *markdown)
{
	size_t markdown_len = strlen(markdown);
	/* Worst case allocation */
	GString *s = g_string_sized_new(markdown_len * 2);

	gboolean verbatim = FALSE;
	gboolean code_block = FALSE;
	gboolean link = FALSE;

	for (guint i = 0; i < markdown_len; ++i) {
		char c = markdown[i];

		if (c == '`') {
			if (code_block) {
				code_block = verbatim = FALSE;
			} else if (!verbatim) {
				code_block = verbatim = TRUE;
			}

			g_string_append_c(s, markdown[i]);

			if (markdown[i + 1] == '`' && markdown[i + 2] == '`') {
				i += 2;
				g_string_append_c(s, markdown[i]);
				g_string_append_c(s, markdown[i]);
				continue;
			}
		}

		if (!verbatim) {
			if (strncmp(markdown + i, "http://", sizeof("http://") - 1) == 0 ||
				strncmp(markdown + i, "https://", sizeof("https://") - 1) == 0)

			{
				link = verbatim = TRUE;
			}
		}

		if (link && c == ' ') {
			link = verbatim = FALSE;
		}

		if (!verbatim) {
			if (
			  (c == '_' && (markdown[i + 1] == ' ' ||
							markdown[i + 1] == '\0' ||
							i == 0 ||
							markdown[i - 1] == ' ' ||
							markdown[i - 1] == '\0')) ||
			  (c == '*') ||
			  (c == '\\' && markdown[i + 1] != '_') ||
			  (c == '~' && (markdown[i + 1] == '~'))) {
				g_string_append_c(s, '\\');
			}
		}

		g_string_append_c(s, c);
	}

	return g_string_free(s, FALSE);
}

static gchar *
groupme_make_guid()
{
	gchar *uuid = g_uuid_string_random();
	gchar *prepped = g_strdup_printf("groupme-min-%s", uuid);
	g_free(uuid);

	return prepped;
}

static gint
groupme_conversation_send_message(GroupMeAccount *da, guint64 room_id, const gchar *message)
{
	JsonObject *data = json_object_new();
	JsonObject *msg = json_object_new();
	gchar *url;
	gchar *postdata;

	gchar *guid = groupme_make_guid();

	json_object_set_string_member(msg, "text", message);
	json_object_set_string_member(msg, "source_guid", guid);
	json_object_set_object_member(data, "message", msg);

	url = g_strdup_printf("https://" GROUPME_API_SERVER "/groups/%" G_GUINT64_FORMAT "/messages?", room_id);
	postdata = json_object_to_string(data);

	groupme_fetch_url(da, url, postdata, NULL, NULL);

	g_free(url);
	g_free(guid);
	g_free(postdata);
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

	ret = groupme_conversation_send_message(da, room_id, message);

	if (ret > 0) {
		printf("Got %s\n", da->self_username);
		purple_serv_got_chat_in(pc, groupme_chat_hash(room_id), da->self_username, PURPLE_MESSAGE_SEND, message, time(NULL));
	}

	return ret;
}

static void
groupme_created_direct_message_send(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	PurpleMessage *msg = user_data;
	JsonObject *result;
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message;
	const gchar *room_id;
	PurpleBuddy *buddy;

	if (node == NULL) {
		purple_conversation_present_error(who, da->account, _("Could not create conversation"));
		purple_message_destroy(msg);
		return;
	}

	result = json_node_get_object(node);
	message = purple_message_get_contents(msg);
	room_id = json_object_get_string_member(result, "id");
	buddy = purple_blist_find_buddy(da->account, who);

	if (room_id != NULL && who != NULL) {
		g_hash_table_replace(da->one_to_ones, g_strdup(room_id), g_strdup(who));
		g_hash_table_replace(da->one_to_ones_rev, g_strdup(who), g_strdup(room_id));
	}

	if (buddy != NULL) {
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", room_id);
	}

	groupme_conversation_send_message(da, to_int(room_id), message);
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

	/* Create DM if there isn't one */
	if (room_id == NULL) {
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
		GroupMeUser *user = groupme_get_user_fullname(da, who);

		if (user) {
			JsonObject *data = json_object_new();
			json_object_set_int_member(data, "recipient_id", user->id);
			gchar *postdata = json_object_to_string(data);

			groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/api/v6/users/@me/channels", postdata, groupme_created_direct_message_send, msg);

			g_free(postdata);
			json_object_unref(data);

			return 1;
		}

		return -1;
	}

	return groupme_conversation_send_message(da, to_int(room_id), message);
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
	gchar *username = groupme_create_fullname(user);

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
	
	g_free(username);
}

static void
groupme_get_avatar(GroupMeAccount *da, GroupMeUser *user)
{
	if (!user) {
		return;
	}

	gchar *username = groupme_create_fullname(user);
	const gchar *checksum = purple_buddy_icons_get_checksum_for_user(purple_blist_find_buddy(da->account, username));
	g_free(username);

	if (purple_strequal(checksum, user->avatar)) {
		return;
	}

	GString *url = g_string_new("https://cdn.groupmeapp.com/avatars/");
	g_string_append_printf(url, "%" G_GUINT64_FORMAT, user->id);
	g_string_append_c(url, '/');
	g_string_append_printf(url, "%s", purple_url_encode(user->avatar));

	groupme_fetch_url(da, url->str, NULL, groupme_got_avatar, user);

	g_string_free(url, TRUE);
}

static void
groupme_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
				  ,
				  const char *message
#endif
				  )
{
	GroupMeAccount *da = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	JsonObject *data;
	gchar *postdata;
	gchar **usersplit;

	if (!strchr(buddy_name, '#')) {
		purple_blist_remove_buddy(buddy);
		return;
	}

	usersplit = g_strsplit_set(buddy_name, "#", 2);
	data = json_object_new();
	json_object_set_string_member(data, "username", usersplit[0]);
	json_object_set_string_member(data, "discriminator", usersplit[1]);

	postdata = json_object_to_string(data);

	groupme_fetch_url(da, "https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships", postdata, NULL, NULL);

	g_free(postdata);
	g_strfreev(usersplit);
	json_object_unref(data);
}

static void
groupme_buddy_remove(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	GroupMeAccount *da = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	gchar *url;
	GroupMeUser *user = groupme_get_user_fullname(da, buddy_name);

	if (!user) {
		return;
	}

	url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/@me/relationships/%" G_GUINT64_FORMAT, user->id);
	groupme_fetch_url_with_method(da, "DELETE", url, NULL, NULL, NULL);
	g_free(url);
}

static void
groupme_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	/* Do nothing to stop the remove+add behaviour */
}

static void
groupme_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	/* Do nothing to stop the remove+add behaviour */
}

static void
groupme_got_info(GroupMeAccount *da, JsonNode *node, gpointer user_data)
{
	GroupMeUser *user = user_data;

	PurpleNotifyUserInfo *user_info;
	JsonObject *info = json_node_get_object(node);
	JsonArray *connected_accounts = json_object_get_array_member(info, "connected_accounts");
	JsonArray *mutual_guilds = json_object_get_array_member(info, "mutual_guilds");
	gint i;

	user_info = purple_notify_user_info_new();

	gchar *id_str = from_int(user->id);
	purple_notify_user_info_add_pair_html(user_info, _("ID"), id_str);
	g_free(id_str);
	
	purple_notify_user_info_add_pair_html(user_info, _("Username"), user->name);

	/* Display other non-profile info that we know about this buddy */
	gchar *status_strings[4] = {
		_("Online"),
		_("Idle"),
		_("Offline"),
		_("Do Not Disturb")
	};

	purple_notify_user_info_add_pair_html(user_info, _("Status"), status_strings[user->status]);

	if (user->game != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Playing"), user->game);
	}

	if (json_array_get_length(connected_accounts)) {
		purple_notify_user_info_add_section_break(user_info);
		purple_notify_user_info_add_pair_html(user_info, _("Connected Accounts"), user->game);
	}

	for (i = json_array_get_length(connected_accounts) - 1; i >= 0; i--) {
		JsonObject *account = json_array_get_object_element(connected_accounts, i);
		const gchar *type = json_object_get_string_member(account, "type");
		const gchar *name = json_object_get_string_member(account, "name");

		/* const gchar *id = json_object_get_string_member(account, "id"); */
		/* TODO href link to account? */

		purple_notify_user_info_add_pair_html(user_info, type, name);
	}

	if (json_array_get_length(mutual_guilds)) {
		purple_notify_user_info_add_section_break(user_info);
		purple_notify_user_info_add_pair_html(user_info, _("Mutual Servers"), user->game);
	}

	for (i = json_array_get_length(mutual_guilds) - 1; i >= 0; i--) {
		JsonObject *guild_o = json_array_get_object_element(mutual_guilds, i);
		guint64 id = to_int(json_object_get_string_member(guild_o, "id"));

		GroupMeGuild *guild = groupme_get_guild(da, id);
		GroupMeGuildMembership *membership = g_hash_table_lookup_int64(user->guild_memberships, id);

		if (membership) {
			gchar *name = membership->nick;
			if (!name || !strlen(name)) {
				name = user->name;
			}

			GString *role_str = g_string_new(name);

			for (guint i = 0; i < membership->roles->len; i++) {
				guint64 role_id = g_array_index(membership->roles, guint64, i);
				GroupMeGuildRole *role = g_hash_table_lookup_int64(guild->roles, role_id);

				g_string_append_printf(role_str, " [" COLOR_START "%s" COLOR_END "]", role->color, role->name);
			}

			purple_notify_user_info_add_pair_html(user_info, guild->name, g_string_free(role_str, FALSE));
		}
	}

	gchar *username = groupme_create_fullname(user);
	purple_notify_userinfo(da->pc, username, user_info, NULL, NULL);
	g_free(username);
}

static void
groupme_get_info(PurpleConnection *pc, const gchar *username)
{
	GroupMeAccount *da = purple_connection_get_protocol_data(pc);
	gchar *url;
	GroupMeUser *user = groupme_get_user_fullname(da, username);

	if (!user) {
		return;
	}

	/* TODO string format fix */
	url = g_strdup_printf("https://" GROUPME_API_SERVER "/api/v6/users/%" G_GUINT64_FORMAT "/profile", user->id);
	groupme_fetch_url(da, url, NULL, groupme_got_info, user);
	g_free(url);
}

static const char *
groupme_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "groupme";
}

static GList *
groupme_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	gboolean use_status_as_game = purple_account_get_bool(account, "use-status-as-game", FALSE);

	/* We can only set statuses without in-game info */
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "set-online", _("Online"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "set-idle", _("Idle"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, "set-dnd", _("Do Not Disturb"), TRUE, !use_status_as_game, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, "set-invisible", _("Invisible"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "set-offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	/* Other people can have an in-game display */
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "idle", _("Idle"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "dnd", _("Do Not Disturb"), TRUE, use_status_as_game, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, FALSE, FALSE, "message", _("Playing"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	return types;
}

static gchar *
groupme_status_text(PurpleBuddy *buddy)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (purple_account_is_connected(account)) {
		PurpleConnection *pc = purple_account_get_connection(account);
		GroupMeAccount *da = purple_connection_get_protocol_data(pc);
		GroupMeUser *user = groupme_get_user_fullname(da, purple_buddy_get_name(buddy));

		if (user == NULL || user->game == NULL) {
			return NULL;
		}

		return g_markup_printf_escaped(_("Playing %s"), user->game);
	}

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
			if (user->game != NULL) {
				return "game";
			} else if (user->bot) {
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

	channel_mentions_regex = g_regex_new("&lt;#(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	role_mentions_regex = g_regex_new("&lt;@&amp;(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	emoji_regex = g_regex_new("&lt;:([^:]+):(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	emoji_natural_regex = g_regex_new(":([^:]+):", G_REGEX_OPTIMIZE, 0, NULL);
	action_star_regex = g_regex_new("^_([^\\*]+)_$", G_REGEX_OPTIMIZE, 0, NULL);
	mention_regex = g_regex_new("&lt;@!?(\\d+)&gt;", G_REGEX_OPTIMIZE, 0, NULL);
	natural_mention_regex = g_regex_new("^([^:]+): ", G_REGEX_OPTIMIZE, 0, NULL);

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

	g_regex_unref(channel_mentions_regex);
	g_regex_unref(role_mentions_regex);
	g_regex_unref(emoji_regex);
	g_regex_unref(emoji_natural_regex);
	g_regex_unref(action_star_regex);
	g_regex_unref(mention_regex);
	g_regex_unref(natural_mention_regex);

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
#if PURPLE_MINOR_VERSION >= 8
/* prpl_info->add_buddy_with_invite = groupme_add_buddy_with_invite; */
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
	prpl_info->set_status = groupme_set_status;
	prpl_info->set_idle = groupme_set_idle;
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
	prpl_info->set_chat_topic = groupme_chat_set_topic;
	prpl_info->get_cb_real_name = groupme_get_real_name;
	prpl_info->add_buddy = groupme_add_buddy;
	prpl_info->remove_buddy = groupme_buddy_remove;
	prpl_info->group_buddy = groupme_fake_group_buddy;
	prpl_info->rename_group = groupme_fake_group_rename;
	prpl_info->get_info = groupme_get_info;
	prpl_info->add_deny = groupme_block_user;
	prpl_info->rem_deny = groupme_unblock_user;

	prpl_info->roomlist_get_list = groupme_roomlist_get_list;
	prpl_info->roomlist_room_serialize = groupme_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	GROUPME_PLUGIN_ID,				/* id */
	"GroupMe",						/* name */
	GROUPME_PLUGIN_VERSION,			/* version */
	"",								/* summary */
	"",								/* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	GROUPME_PLUGIN_WEBSITE,			/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	groupme_actions,				/* actions */
	NULL,							/* padding */
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
	prpl_info->add_buddy = groupme_add_buddy;
	prpl_info->remove_buddy = groupme_buddy_remove;
	prpl_info->set_status = groupme_set_status;
	prpl_info->set_idle = groupme_set_idle;
	prpl_info->group_buddy = groupme_fake_group_buddy;
	prpl_info->rename_group = groupme_fake_group_rename;
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
