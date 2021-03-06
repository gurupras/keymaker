import os,sys,argparse
import json
import time
import struct
import socket
import subprocess
import ssh

import pycommons
from pycommons import generic_logging
import logging
if __name__ == '__main__':
	generic_logging.init(level=logging.DEBUG)
logger = logging.getLogger(__file__)

import common
import protocol_pb2

def setup_parser():
	parser = argparse.ArgumentParser()

	parser.add_argument('--port', '-p', type=int, default=41938,
			help='Port to run keymaker')
	parser.add_argument('--secret', '-s', type=str, required=True,
			help='Secret string that keymaker clients should match')

	return parser

def send_response(sock, response):
	msg = response.SerializeToString()
	length = struct.pack(">Q", len(msg))
	logger.info("Response length: %d" % (len(msg)))
	sock.sendall(length + msg)


def handle_key_request_generate(sock, request, response):
	username = request.username.strip()
	hostname = request.hostname.strip()
	name = "%s@%s" % (username, hostname)
	cmd = 'ssh-keygen -t rsa -f %s -C %s -P ""' % (name, name)
	ret, stdout, stderr = pycommons.run(cmd, fail_on_error=False)
	if ret != 0:
		logger.error(stderr)
		return

	response.type = protocol_pb2.Response.KEY_RESPONSE
	response.status = protocol_pb2.OK

	with open(name, 'rb') as f:
		response.keyResponse.privateKey = f.read()
	with open(name+'.pub', 'rb') as f:
		response.keyResponse.publicKey = f.read()

	if request.authorizedKeys is True:
		logger.info("Adding generated public key to authorized keys")
		update_authorized_keys(response.keyResponse.publicKey)

	os.remove(name)
	os.remove(name+'.pub')

def update_authorized_keys(public_key):
	keys = ssh.get_authorized_keys(key_file='authorized_keys')
	key = ssh.parse_key(public_key)
	ssh.update_key(keys, key)
	ssh.update_authorized_keys(keys, key_file='authorized_keys')

def handle_key_request_existing(sock, request, response):
	if request.authorizedKeys is True:
		logger.info("Adding existing public key to authorized keys")
		update_authorized_keys(request.existing.publicKey)
	response.type = protocol_pb2.Response.GENERIC
	response.status = protocol_pb2.OK

def handle_key_request(sock, request, response):
	logger.info("Handling key request")
	if request.type == protocol_pb2.KeyRequest.KEY_REQUEST_GENERATE:
		handle_key_request_generate(sock, request, response)
	elif request.type == protocol_pb2.KeyRequest.KEY_REQUEST_EXISTING:
		handle_key_request_existing(sock, request, response)

def server(port, secret, out=None):
	logger.info("Starting server ...")
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	if out:
		out = pycommons.open_file(output, 'wb')
		generic_logging.add_file_handler(out, logger)
	else:
		out = sys.stdout

	try:
		server_socket.bind(('', port))
	except socket.error as e:
		logger.error('Bind failed! :' + e[1])
		sys.exit(-1)

	server_socket.listen(10)

	while 1:
		sock, addr = server_socket.accept()
#		print str(addr)
		length = struct.unpack('>Q', common.sock_read(sock, 8))[0]
		logger.info("Request length: %d" % (length))
		msg_buf = common.sock_read(sock, length)
		request = protocol_pb2.Request()
		request.ParseFromString(msg_buf)

		if request.secret != common.sha256(secret):
			response = protocol_pb2.Response()
			response.type = protocol_pb2.Response.GENERIC
			response.status = protocol_pb2.ERROR
			response.error = "Invalid secret"
			send_response(sock, response)
			sock.close()
			continue

		response = protocol_pb2.Response()

		if request.type == protocol_pb2.Request.KEY_REQUEST:
			handle_key_request(sock, request.keyRequest, response)

		send_response(sock, response)
		sock.close()



def main(argv):
	parser = setup_parser()
	args = parser.parse_args(argv[1:])

	server(args.port, args.secret)

if __name__ == '__main__':
	main(sys.argv)
