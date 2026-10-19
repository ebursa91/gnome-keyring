/*
 * Copyright (C) 2026 Ernest Bursa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-dispatch.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "daemon/gkd-main.h"
#include "egg/egg-secure-memory.h"
#include "pkcs11/gkm/gkm-mock.h"

#include <glib/gstdio.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static GTestDBus *private_bus;

typedef struct {
	GTestDBus *bus;
	GDBusConnection *connection;
	GkdSecretService *service;
	GckModule *module;
	GckSlot *slot;
	CK_FUNCTION_LIST functions;
	GkdSecretSession *session;
	gchar *caller;
	guint filter;
	guint rewrite_filter;
	gboolean published;
	gboolean vanished;
	gint rewrite_sender;
	gint queued;
	gboolean dispose_service;
} Test;

/* gkd-dbus.c also contains the daemon's shutdown handler, which these
 * in-process service tests must never enter. */
void
gkd_main_quit (void)
{
	g_assert_not_reached ();
}

static CK_RV
get_token_info (CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV rv = gkm_mock_C_GetTokenInfo (slot, info);
	if (rv == CKR_OK)
		info->flags &= ~CKF_LOGIN_REQUIRED;
	return rv;
}

static GDBusConnection *
connect_bus (Test *test)
{
	GError *error = NULL;
	GDBusConnection *connection;

	connection = g_dbus_connection_new_for_address_sync (
		g_test_dbus_get_bus_address (test->bus),
		G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
		G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert_nonnull (connection);
	g_dbus_connection_set_exit_on_close (connection, FALSE);
	return connection;
}

static void
wait_for (gboolean *condition)
{
	gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;

	while (!*condition && g_get_monotonic_time () < deadline) {
		while (g_main_context_iteration (NULL, FALSE));
		g_usleep (1000);
	}
	g_assert_true (*condition);
}

static gboolean
publish_session (gpointer user_data)
{
	Test *test = user_data;

	test->session = gkd_secret_session_new (test->service, test->caller);
	g_object_add_weak_pointer (G_OBJECT (test->session), (gpointer *)&test->session);
	gkd_secret_service_publish_dispatch (test->service, test->caller,
	                                    GKD_SECRET_DISPATCH (test->session));
	g_object_unref (test->session);
	if (test->dispose_service) {
		g_object_run_dispose (G_OBJECT (test->service));
		g_clear_object (&test->service);
	}
	test->published = TRUE;
	return G_SOURCE_REMOVE;
}

static GDBusMessage *
rewrite_registration (GDBusConnection *connection, GDBusMessage *message,
                    gboolean incoming, gpointer user_data)
{
	Test *test = user_data;
	GDBusMessage *copy;
	GError *error = NULL;

	if (!incoming || g_dbus_message_get_message_type (message) != G_DBUS_MESSAGE_TYPE_SIGNAL ||
	    g_strcmp0 (g_dbus_message_get_interface (message), "org.gnome.keyring.Test") != 0)
		return message;

	if (g_atomic_int_get (&test->rewrite_sender)) {
		/* Model a message queued before this peer's disconnect but processed
		 * after its NameOwnerChanged notification. Only this test signal is
		 * rewritten, locally, before the real service filter sees it. */
		copy = g_dbus_message_copy (message, &error);
		g_assert_no_error (error);
		g_dbus_message_set_sender (copy, test->caller);
		g_object_unref (message);
		message = copy;
	}
	return message;
}

static GDBusMessage *
queue_registration (GDBusConnection *connection, GDBusMessage *message,
                    gboolean incoming, gpointer user_data)
{
	Test *test = user_data;
	GSource *source;

	if (!incoming || g_dbus_message_get_message_type (message) != G_DBUS_MESSAGE_TYPE_SIGNAL ||
	    g_strcmp0 (g_dbus_message_get_interface (message), "org.gnome.keyring.Test") != 0)
		return message;

	/* The service registers its sender at HIGH priority. Publish immediately
	 * afterwards, before the asynchronous ownership lookup can complete. */
	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH + 1);
	g_source_set_callback (source, publish_session, test, NULL);
	g_source_attach (source, NULL);
	g_source_unref (source);
	g_atomic_int_set (&test->queued, TRUE);
	return message;
}

static void
setup (Test *test, gconstpointer unused)
{
	CK_FUNCTION_LIST_PTR functions;
	GList *slots;

	test->bus = private_bus;
	test->connection = connect_bus (test);
	g_assert_cmpuint (gkm_mock_C_GetFunctionList (&functions), ==, CKR_OK);
	test->functions = *functions;
	test->functions.C_GetTokenInfo = get_token_info;
	g_assert_cmpuint (test->functions.C_Initialize (NULL), ==, CKR_OK);
	test->module = gck_module_new (&test->functions);
	slots = gck_module_get_slots (test->module, TRUE);
	g_assert_nonnull (slots);
	test->slot = g_object_ref (slots->data);
	gck_list_unref_free (slots);
	test->rewrite_filter = g_dbus_connection_add_filter (test->connection,
	                                                   rewrite_registration, test, NULL);
	test->service = g_object_new (GKD_SECRET_TYPE_SERVICE,
	                             "connection", test->connection,
	                             "pkcs11-slot", test->slot, NULL);
	test->filter = g_dbus_connection_add_filter (test->connection,
	                                           queue_registration, test, NULL);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_dbus_connection_remove_filter (test->connection, test->filter);
	g_dbus_connection_remove_filter (test->connection, test->rewrite_filter);
	if (test->service)
		g_object_run_dispose (G_OBJECT (test->service));
	g_clear_object (&test->service);
	while (g_main_context_iteration (NULL, FALSE));
	g_assert_null (test->session);
	g_clear_object (&test->slot);
	g_clear_object (&test->module);
	g_assert_cmpuint (test->functions.C_Finalize (NULL), ==, CKR_OK);
	g_dbus_connection_close_sync (test->connection, NULL, NULL);
	g_clear_object (&test->connection);
	g_free (test->caller);
}

static void
on_name_vanished (GDBusConnection *connection, const gchar *sender,
                  const gchar *path, const gchar *interface, const gchar *member,
                  GVariant *parameters, gpointer user_data)
{
	Test *test = user_data;
	const gchar *name, *old_owner, *new_owner;

	g_variant_get (parameters, "(&s&s&s)", &name, &old_owner, &new_owner);
	if (*new_owner == '\0')
		test->vanished = TRUE;
}

static void
send_registration (Test *test, GDBusConnection *peer)
{
	GError *error = NULL;
	gint64 deadline;

	g_dbus_connection_emit_signal (peer, g_dbus_connection_get_unique_name (test->connection),
	                               "/org/gnome/keyring/Test", "org.gnome.keyring.Test",
	                               "Register", NULL, &error);
	g_assert_no_error (error);
	g_dbus_connection_flush_sync (peer, NULL, &error);
	g_assert_no_error (error);
	/* Do not dispatch the service context until both the service's HIGH
	 * registration idle and our HIGH+1 publication idle have been queued. */
	deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
	while (!g_atomic_int_get (&test->queued) && g_get_monotonic_time () < deadline)
		g_usleep (1000);
	g_assert_true (g_atomic_int_get (&test->queued));
	wait_for (&test->published);
}

static void
wait_for_session_finalized (Test *test)
{
	gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
	while (test->session && g_get_monotonic_time () < deadline) {
		while (g_main_context_iteration (NULL, FALSE));
		g_usleep (1000);
	}
	g_assert_null (test->session);
}

static void
test_disconnect (Test *test, gconstpointer unused)
{
	GDBusConnection *peer = connect_bus (test);

	test->caller = g_strdup (g_dbus_connection_get_unique_name (peer));
	send_registration (test, peer);
	g_assert_nonnull (test->session);
	g_dbus_connection_close_sync (peer, NULL, NULL);
	g_object_unref (peer);
	wait_for_session_finalized (test);
}

static void
test_late_registration (Test *test, gconstpointer unused)
{
	GDBusConnection *peer = connect_bus (test);
	guint subscription;
	GVariant *reply;
	GError *error = NULL;

	test->caller = g_strdup (g_dbus_connection_get_unique_name (peer));
	subscription = g_dbus_connection_signal_subscribe (
		test->connection, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
		"/org/freedesktop/DBus", test->caller, G_DBUS_SIGNAL_FLAGS_NONE,
		on_name_vanished, test, NULL);
	/* A round trip on this connection also orders the subscription's AddMatch
	 * before the peer disconnects, so its notification cannot be missed. */
	reply = g_dbus_connection_call_sync (test->connection, "org.freedesktop.DBus",
	                                     "/org/freedesktop/DBus", "org.freedesktop.DBus",
	                                     "GetNameOwner", g_variant_new ("(s)", test->caller),
	                                     G_VARIANT_TYPE ("(s)"), G_DBUS_CALL_FLAGS_NONE,
	                                     5000, NULL, &error);
	g_assert_no_error (error);
	g_variant_unref (reply);
	g_dbus_connection_close_sync (peer, NULL, NULL);
	g_object_unref (peer);
	wait_for (&test->vanished);
	g_dbus_connection_signal_unsubscribe (test->connection, subscription);
	g_atomic_int_set (&test->rewrite_sender, TRUE);
	peer = connect_bus (test);
	send_registration (test, peer);
	g_dbus_connection_close_sync (peer, NULL, NULL);
	g_object_unref (peer);
	wait_for_session_finalized (test);
}

static void
test_dispose_pending_lookup (Test *test, gconstpointer unused)
{
	GDBusConnection *peer = connect_bus (test);

	test->caller = g_strdup (g_dbus_connection_get_unique_name (peer));
	test->dispose_service = TRUE;
	send_registration (test, peer);
	g_assert_null (test->service);
	g_assert_null (test->session);
	g_dbus_connection_close_sync (peer, NULL, NULL);
	g_object_unref (peer);
}

int
main (int argc, char **argv)
{
	GError *error = NULL;
	gchar *directory;
	gint result;

	/* Set these before GLib caches either location. The mock token never
	 * opens files, and the service's alias/portal lookups stay here too. */
	directory = g_dir_make_tmp ("keyring-client-test-XXXXXX", &error);
	g_assert_no_error (error);
	g_setenv ("HOME", directory, TRUE);
	g_setenv ("XDG_DATA_HOME", directory, TRUE);
	g_setenv ("GNOME_KEYRING_TEST_PATH", directory, TRUE);
	g_test_init (&argc, &argv, NULL);
	private_bus = g_test_dbus_new (G_TEST_DBUS_NONE);
	g_test_dbus_up (private_bus);
	g_test_add ("/secret-client/disconnect", Test, NULL,
	            setup, test_disconnect, teardown);
	g_test_add ("/secret-client/late-registration", Test, NULL,
	            setup, test_late_registration, teardown);
	g_test_add ("/secret-client/dispose-pending-lookup", Test, NULL,
	            setup, test_dispose_pending_lookup, teardown);
	result = g_test_run ();
	g_test_dbus_down (private_bus);
	g_clear_object (&private_bus);
	g_assert_cmpint (g_rmdir (directory), ==, 0);
	g_free (directory);
	return result;
}
