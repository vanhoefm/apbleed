/*
 * EAP handler which accepts/forwards data from/to a TCP socket.
 * Originally created to test heartbleed over PEAP.
 *
 * TODO: exit() after an error (don't let error messages got lost in the maze)
 */

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
*/

#include "includes.h"

#include "common.h"
#include "crypto/tls.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "eap_config.h"


// Message displayed when an incomming connection should be made
static char connectnow[] = 
"\n"
"\t\t====[ BleedAP: connect to %s:%d ]====\n"
"\n"
"\tBe fast enough, otherwise the connection will time out...\n"
"\n";

static void eap_socket_deinit(struct eap_sm *sm, void *priv);

struct eap_socket_data {
	int sockfd;
	int clientfd;
};



static int accept_socket_connection(struct eap_socket_data *data)
{
	struct sockaddr_in addr;
	static const int PORT = 45678;

	// make a socket
	data->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (data->sockfd < 0) {
		perror("socket(AF_INET)");
		return -1;
	}

	// bind to local address
	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);//INADDR_LOOPBACK;
	addr.sin_port = htons(PORT);
	if (bind(data->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind(AF_INET)");
		goto fail;
	}

	// accept one connection (queue of 1)
	if (listen(data->sockfd, 1) < 0) {
		perror("listen(AF_INET)");
		goto fail;
	}

	printf(connectnow, "localhost", PORT);
	data->clientfd = accept(data->sockfd, NULL, NULL);
	if (data->clientfd < 0) {
		perror("accept(AF_INET)");
		goto fail;
	}

	return 0;
fail:
	close(data->sockfd);
	return -1;
}


static void * eap_socket_init(struct eap_sm *sm)
{
	struct eap_socket_data *data;
	printf(">> %s\n", __FUNCTION__);

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	// Accept connection before associating
	if (accept_socket_connection(data) < 0) {
		os_free(data);
		return NULL;
	}

	return data;
}


static void eap_socket_deinit(struct eap_sm *sm, void *priv)
{
	printf(">> %s\n", __FUNCTION__);

	// TODO
}


static struct wpabuf * eap_socket_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_socket_data *data = (struct eap_socket_data*)priv;
	struct wpabuf *resp;
	const u8 *pos;
	size_t len;
	u8 id, flags = 0;

	printf(">> %s\n", __FUNCTION__);

	//wpa_hexdump_ascii(MSG_INFO, "%s SOCKET-Process request: ", __FUNCTION__, reqData->buf, reqData->used);

	// Validate EAP header and get message ID -- TODO: Allow any EAP type (from config)
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PEAP, reqData, &len);
	if (pos == NULL) {
		ret->ignore = TRUE;
		return NULL;
	}
	id = eap_get_id(reqData);

	// Type EAP_TYPE_PEAP has an additional EAP-TLS flag before the payload
	flags = *pos;
	pos++;
	len--;

	// Remove length field if present
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		pos += 4;
		len -= 4;
	}

	// Forward payload if available
	if (len > 0)
	{
		int i;

		printf(">> %s forwarding %u bytes to SSL/TLS client\n", __FUNCTION__, (unsigned int)len);

		for (i = 0; i < len; ++i) {
			printf("%02X ", pos[i]);
		}
		printf("\n");

		// TODO: Improve error handling
		if (write(data->clientfd, pos, len) != len) {
			perror("write(AF_INET)");
			return NULL;
		}
	}

	// If more fragments will be sent, just ACK current data
	if (flags & EAP_TLS_FLAGS_MORE_FRAGMENTS)
	{
		printf(">> %s sending ACK to radius server\n", __FUNCTION__);

		// Construct EAP reply
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PEAP, 1,
				     EAP_CODE_RESPONSE, id);
		if (resp == NULL)
			return NULL;

		// Set additional EAP-TLS flags
		wpabuf_put_u8(resp, 0);
	}
	// If all data is received, forward data in socket to client. Server will send ACK
	// to inform we can continue sending data =)
	else
	{
		u8 buffer[1000];
		int bufflen, resplen;

		printf(">> %s waiting for data from client ...\n", __FUNCTION__);

		// TODO: Improve error handling
		bufflen = read(data->clientfd, buffer, sizeof(buffer));
		if (bufflen < 0) {
			perror("read(AF_INET)");
			return NULL;
		} else if (bufflen == 0) {
			printf("Client closed connection, exiting\n");
			return NULL;
		}

		// Construct EAP reply
		resplen = bufflen + 1;
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PEAP, resplen,
				     EAP_CODE_RESPONSE, id);
		if (resp == NULL)
			return NULL;

		// Set additional EAP-TLS flags. FIXME: Assume more data available when bufflen==sizeof(buffer).
		flags = 0;
		if (bufflen == sizeof(buffer))
			flags |= EAP_TLS_FLAGS_MORE_FRAGMENTS;
		wpabuf_put_u8(resp, flags);

		// TODO: When to include the TLS/SSL length field?

		// Copy payload to EAP packet
		wpabuf_put_data(resp, buffer, bufflen);

		printf(">> %s client data forwarded to radius server\n", __FUNCTION__);
	}

	//wpa_hexdump_ascii(MSG_INFO, "SOCKET-Process response: ", wpabuf_head_u8(resp) + sizeof(struct eap_hdr) +
	//		      1, resplen);
	//wpabuf_put_data(resp, CLIENT_HEARTBEAT, CLIENT_HEARTBEAT_LEN);

	// ret->ignore = TRUE;
	return resp;
}


int eap_peer_socket_register(void)
{
	struct eap_method *eap;
	int ret;

	printf(">> %s\n", __FUNCTION__);

	// Pretend to be PEAP so the server is more likely to accept the connection.
	// TODO: Get EAP type we want to manipulate from config
	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_PEAP, "SOCKET");
	if (eap == NULL)
		return -1;

	eap->init = eap_socket_init;
	eap->deinit = eap_socket_deinit;
	eap->process = eap_socket_process;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}


