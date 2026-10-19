/*
 * Functional concurrency regression for GNOME Keyring OpenSession.
 * Based on the fresh-connection pattern in GNOME issue 190's reproducer:
 * https://gitlab.gnome.org/-/project/1628/uploads/2a758a1afdb73e7e5c6baf5cf8d59c03/opensession-race-clean.c
 *
 * This client negotiates a plain or DH session, then closes the returned
 * session. It never creates a collection, item, password or token.
 * Use run-opensession.py to supply an isolated, non-activating private bus.
 */
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *address;
static gboolean use_dh;
static gint rounds;
static gint attempted, opened, closed, failures;
static GMutex start_mutex;
static GCond start_cond;
static gint ready;
static gboolean start;

static GDBusConnection *
connect_bus (GError **error)
{
	GDBusConnection *connection = g_dbus_connection_new_for_address_sync (
		address,
		G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
		G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
		NULL, NULL, error);

	if (connection)
		g_dbus_connection_set_exit_on_close (connection, FALSE);
	return connection;
}

static gboolean
open_and_close (GDBusConnection *connection)
{
	GError *error = NULL;
	GVariant *reply = NULL, *output = NULL, *close_reply = NULL;
	const gchar *session_path = NULL;
	gboolean success = FALSE;
	const guchar public_key[] = { 2 };
	GVariant *input = use_dh
		? g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, public_key, sizeof public_key, 1)
		: g_variant_new_string ("");

	reply = g_dbus_connection_call_sync (
		connection, "org.freedesktop.secrets", "/org/freedesktop/secrets",
		"org.freedesktop.Secret.Service", "OpenSession",
		g_variant_new ("(sv)", use_dh ? "dh-ietf1024-sha256-aes128-cbc-pkcs7" : "plain", input),
		G_VARIANT_TYPE ("(vo)"), G_DBUS_CALL_FLAGS_NO_AUTO_START,
		2000, NULL, &error);
	if (!reply)
		goto out;

	g_variant_get (reply, "(v&o)", &output, &session_path);
	if (strcmp (session_path, "/") == 0)
		goto out;
	if (use_dh && (!g_variant_is_of_type (output, G_VARIANT_TYPE_BYTESTRING) ||
		       g_variant_n_children (output) == 0))
		goto out;
	if (!use_dh && (!g_variant_is_of_type (output, G_VARIANT_TYPE_STRING) ||
			strcmp (g_variant_get_string (output, NULL), "") != 0))
		goto out;
	g_atomic_int_inc (&opened);

	close_reply = g_dbus_connection_call_sync (
		connection, "org.freedesktop.secrets", session_path,
		"org.freedesktop.Secret.Session", "Close", NULL,
		G_VARIANT_TYPE ("()"), G_DBUS_CALL_FLAGS_NO_AUTO_START,
		2000, NULL, &error);
	if (!close_reply)
		goto out;
	g_atomic_int_inc (&closed);
	success = TRUE;

out:
	g_clear_error (&error);
	g_clear_pointer (&close_reply, g_variant_unref);
	g_clear_pointer (&output, g_variant_unref);
	g_clear_pointer (&reply, g_variant_unref);
	return success;
}

static gpointer
worker (gpointer data)
{
	(void) data;
	g_mutex_lock (&start_mutex);
	ready++;
	g_cond_broadcast (&start_cond);
	while (!start)
		g_cond_wait (&start_cond, &start_mutex);
	g_mutex_unlock (&start_mutex);

	for (gint i = 0; i < rounds; i++) {
		GError *error = NULL;
		GDBusConnection *connection;
		gboolean success;

		g_atomic_int_inc (&attempted);
		connection = connect_bus (&error);
		if (!connection) {
			g_clear_error (&error);
			g_atomic_int_inc (&failures);
			continue;
		}
		success = open_and_close (connection);
		if (!g_dbus_connection_close_sync (connection, NULL, &error))
			success = FALSE;
		if (!success)
			g_atomic_int_inc (&failures);
		g_clear_error (&error);
		g_object_unref (connection);
	}
	return NULL;
}

static gint
probe_ready (void)
{
	GError *error = NULL;
	GDBusConnection *connection = connect_bus (&error);
	GVariant *reply;
	gboolean owned = FALSE;

	if (!connection) {
		g_clear_error (&error);
		return 1;
	}
	reply = g_dbus_connection_call_sync (
		connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "NameHasOwner",
		g_variant_new ("(s)", "org.freedesktop.secrets"),
		G_VARIANT_TYPE ("(b)"), G_DBUS_CALL_FLAGS_NO_AUTO_START,
		1000, NULL, &error);
	if (reply) {
		g_variant_get (reply, "(b)", &owned);
		g_variant_unref (reply);
	}
	g_clear_error (&error);
	g_dbus_connection_close_sync (connection, NULL, NULL);
	g_object_unref (connection);
	return owned ? 0 : 1;
}

static gint
positive_int (const char *value, gint maximum)
{
	gchar *end = NULL;
	gint64 number = g_ascii_strtoll (value, &end, 10);
	return end != value && *end == '\0' && number > 0 && number <= maximum
		? (gint) number : 0;
}

int
main (int argc, char **argv)
{
	gint threads;
	GThread **workers;

	if (argc == 3 && strcmp (argv[1], "--ready") == 0) {
		address = argv[2];
		return probe_ready ();
	}
	if (argc != 5 || !(threads = positive_int (argv[2], 128)) ||
	    !(rounds = positive_int (argv[3], 100000))) {
		fprintf (stderr, "usage: %s PRIVATE_ADDRESS THREADS ROUNDS plain|dh\n", argv[0]);
		return 2;
	}
	if (strcmp (argv[4], "plain") != 0 && strcmp (argv[4], "dh") != 0)
		return 2;
	use_dh = strcmp (argv[4], "dh") == 0;
	address = argv[1];
	workers = g_new0 (GThread *, threads);
	for (gint i = 0; i < threads; i++)
		workers[i] = g_thread_new ("session-check", worker, NULL);

	g_mutex_lock (&start_mutex);
	while (ready != threads)
		g_cond_wait (&start_cond, &start_mutex);
	start = TRUE;
	g_cond_broadcast (&start_cond);
	g_mutex_unlock (&start_mutex);
	for (gint i = 0; i < threads; i++)
		g_thread_join (workers[i]);
	g_free (workers);

	printf ("{\"calls\":%d,\"opened\":%d,\"closed\":%d,\"failures\":%d}\n",
		g_atomic_int_get (&attempted), g_atomic_int_get (&opened),
		g_atomic_int_get (&closed), g_atomic_int_get (&failures));
	return g_atomic_int_get (&failures) ? 1 : 0;
}
