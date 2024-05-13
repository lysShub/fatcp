/*
	datagram transport connect on tcp, provide crypto option and builtin tcp.

	packet structure:

	{[fake tcp header] [attacher bytes] [payload]}

*/

package fatcp
