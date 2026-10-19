/* Exercise OpenSession followed by disconnect before receiving the reply.
 * Only use with run-client-lifecycle.py's empty, non-activating private bus.
 * This client never creates a collection, item, password or token. */
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>

static const char *address;
static gint rounds, attempted, sent, failures;

static gpointer
worker (gpointer unused)
{
	(void) unused;
	for (gint i = 0; i < rounds; i++) {
		GError *error = NULL;
		GDBusConnection *connection;
		GDBusMessage *message;
		gboolean success;

		g_atomic_int_inc (&attempted);
		connection = g_dbus_connection_new_for_address_sync (
			address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
			G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
		if (connection == NULL) {
			g_clear_error (&error);
			g_atomic_int_inc (&failures);
			continue;
		}
		g_dbus_connection_set_exit_on_close (connection, FALSE);
		message = g_dbus_message_new_method_call (
			"org.freedesktop.secrets", "/org/freedesktop/secrets",
			"org.freedesktop.Secret.Service", "OpenSession");
		g_dbus_message_set_flags (message, G_DBUS_MESSAGE_FLAGS_NO_AUTO_START);
		g_dbus_message_set_body (message,
														g_variant_new ("(sv)", "plain", g_variant_new_string ("")));
		success = g_dbus_connection_send_message (
			connection, message, G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, &error);
		if (success)
			success = g_dbus_connection_flush_sync (connection, NULL, &error);
		if (success)
			g_atomic_int_inc (&sent);
		g_clear_error (&error);
		if (!g_dbus_connection_close_sync (connection, NULL, &error))
			success = FALSE;
		if (!success)
			g_atomic_int_inc (&failures);
		g_clear_error (&error);
		g_object_unref (message);
		g_object_unref (connection);
	}
	return NULL;
}

int
main (int argc, char **argv)
{
	GThread **threads;
	gint count;
	if (argc != 4)
		return 2;
	address = argv[1];
	count = atoi (argv[2]);
	rounds = atoi (argv[3]);
	if (count < 1 || count > 128 || rounds < 1 || rounds > 100000)
		return 2;
	threads = g_new0 (GThread *, count);
	for (gint i = 0; i < count; i++)
		threads[i] = g_thread_new ("abortive-client", worker, NULL);
	for (gint i = 0; i < count; i++)
		g_thread_join (threads[i]);
	g_free (threads);
	printf ("{\"attempted\":%d,\"sent\":%d,\"failures\":%d}\n",
					g_atomic_int_get (&attempted), g_atomic_int_get (&sent),
					g_atomic_int_get (&failures));
	return g_atomic_int_get (&failures) ? 1 : 0;
}
