// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the client/server functions to interact with DIGLIM.
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/stat.h>

#include "common.h"

#define SOCK_DIR "/run/diglim"
#define SOCK_PATH SOCK_DIR "/diglim_sock"

static int stop_loop;

static void stop_server(int sig)
{
	stop_loop = 1;
	unlink(SOCK_PATH);
	rmdir(SOCK_DIR);
	kill(0, SIGINT);
}

static int init_clientserver(bool server)
{
	struct sockaddr_un local;
	struct stat st;
	int ret, fd, len;

	if (server) {
		if (stat(SOCK_DIR, &st) == -1)
			mkdir(SOCK_DIR, 0644);

		if (!stat(SOCK_PATH, &st))
			unlink(SOCK_PATH);
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCK_PATH);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return -errno;

	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (server) {
		ret = bind(fd, (struct sockaddr *)&local, len);
		if (ret == -1) {
			close(fd);
			return -errno;
		}

		ret = listen(fd, 5);
		if (ret == -1) {
			close(fd);
			return -errno;
		}
	} else {
		ret = connect(fd, (struct sockaddr *)&local, len);
		if (ret == -1) {
			close(fd);
			return -errno;
		}
	}

	return fd;
}

static void fini_clientserver(bool server)
{
	if (!server)
		return;

	unlink(SOCK_PATH);
	rmdir(SOCK_DIR);
}

/* Request format: <pkt len[4]>:<op[2]>:<path[]> */
static int handle_conn(int server_sock_fd, int map_fd, bool only_immutable)
{
	socklen_t remote_len;
	int ret, client_sock_fd;
	struct sockaddr_un remote;
	char pkt_len_str[6] = { 0 };
	unsigned long pkt_len;
	char op_str[4] = { 0 };
	unsigned long op;
	char *end_ptr;
	char path[PATH_MAX] = { 0 };

	remote_len = sizeof(remote);

	client_sock_fd = accept(server_sock_fd,
				(struct sockaddr *)&remote,
				&remote_len);
	if (client_sock_fd == -1) {
		_log("Failed to accept client\n");
		return 0;
	}

	ret = recv(client_sock_fd, pkt_len_str, sizeof(pkt_len_str) - 1, 0);
	if (ret != sizeof(pkt_len_str) - 1 ||
	    pkt_len_str[sizeof(pkt_len_str) - 2] != ':') {
		_log("Failed to read pkt len\n");
		goto out;
	}

	pkt_len = strtoul(pkt_len_str, &end_ptr, 10);
	if (pkt_len <= sizeof(op_str) - 1 ||
	    pkt_len - sizeof(op_str) - 1 >= sizeof(path) ||
	    end_ptr != &pkt_len_str[sizeof(pkt_len_str) - 2]) {
		_log("Failed to read pkt len\n");
		goto out;
	}

	ret = recv(client_sock_fd, op_str, sizeof(op_str) - 1, 0);
	if (ret != sizeof(op_str) - 1 || op_str[sizeof(op_str) - 2] != ':') {
		_log("Failed to read op\n");
		goto out;
	}

	op = strtoul(op_str, &end_ptr, 10);
	if (op >= CMD__LAST || end_ptr != &op_str[sizeof(op_str) - 2]) {
		_log("Failed to read command\n");
		goto out;
	}

	pkt_len -= sizeof(op_str) - 1;

	ret = recv(client_sock_fd, path, pkt_len, 0);
	if (ret != pkt_len) {
		_log("Failed to read path\n");
		goto out;
	}

	if (path[pkt_len - 1] == '\n')
		path[pkt_len - 1] = '\0';

	ret = diglim_parse_digest_list(map_fd, (unsigned char)op, path,
				       only_immutable);

	ret = send(client_sock_fd, &ret, sizeof(ret), 0);
	if (ret != sizeof(ret)) {
		_log("Failed to write result\n");
		goto out;
	}
out:
	close(client_sock_fd);
	return 0;
}

int diglim_main_loop(int map_fd, bool only_immutable,
		     struct ring_buffer *ringbuf)
{
	fd_set set;
	int max_fd, server_sock_fd, ringbuf_fd = ring_buffer__epoll_fd(ringbuf);
	int ret = 0;

	signal(SIGTERM, stop_server);

	FD_ZERO(&set);

	server_sock_fd = init_clientserver(true);
	if (server_sock_fd < 0) {
		_log("Failed to create a UNIX socket\n");
		return server_sock_fd;
	}

	max_fd = (server_sock_fd > ringbuf_fd) ? server_sock_fd : ringbuf_fd;

	while (!stop_loop) {
		FD_SET(server_sock_fd, &set);
		FD_SET(ringbuf_fd, &set);

		ret = select(max_fd + 1, &set, NULL, NULL, NULL);
		if (ret == -1) {
			ret = -errno;
			break;
		}

		if (FD_ISSET(ringbuf_fd, &set)) {
			ret = ring_buffer__consume(ringbuf);
			if (ret < 0)
				break;

			continue;
		}

		ret = handle_conn(server_sock_fd, map_fd, only_immutable);
		if (ret) {
			if (ret != -ERESTART)
				_log("Failed to handle a connection\n");
			break;
		}
	}

	close(server_sock_fd);
	fini_clientserver(true);

	return (!ret || ret == -ERESTART) ? 0 : ret;
}

int diglim_exec_op(char *path, enum digest_list_ops op, int *server_ret)
{
	char pkt_len_str[6] = { 0 };
	char op_str[4] = { 0 };
	int client_sock_fd;
	int ret, len, path_len;

	if (op >= CMD__LAST) {
		_log("Invalid op %d\n", op);
		return -EINVAL;
	}

	client_sock_fd = init_clientserver(false);
	if (client_sock_fd < 0)
		return client_sock_fd;

	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		_log("Path too big\n");
		ret = -EINVAL;
		goto out;
	}

	len = snprintf(pkt_len_str, sizeof(pkt_len_str), "%04ld:",
		       sizeof(op_str) - 1 + path_len);
	ret = send(client_sock_fd, pkt_len_str, len, 0);
	if (ret != len) {
		_log("Failed to write pkt len\n");
		goto out;
	}

	len = snprintf(op_str, sizeof(op_str), "%02d:", op);
	ret = send(client_sock_fd, op_str, len, 0);
	if (ret != len) {
		_log("Failed to write op\n");
		goto out;
	}

	ret = send(client_sock_fd, path, path_len, 0);
	if (ret != path_len) {
		_log("Failed to write path\n");
		goto out;
	}

	ret = recv(client_sock_fd, server_ret, sizeof(*server_ret), 0);
	if (ret != sizeof(*server_ret)) {
		_log("Failed to read result\n");
		goto out;
	}

	ret = 0;
out:
	close(client_sock_fd);
	return ret;
}
