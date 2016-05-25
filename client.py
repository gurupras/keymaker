import os,sys,argparse
import json
import time
import struct
import socket
import subprocess
import traceback

import logging
try:
	import pycommons
	from pycommons import generic_logging
	if __name__ == '__main__':
		generic_logging.init(level=logging.DEBUG)
except:
	print 'No pycommons..continuing anyway'
logger = logging.getLogger(__file__)

import common
import protocol_pb2

def setup_parser():
	parser = argparse.ArgumentParser()

	parser.add_argument('--host', '-H', type=str, required=True,
			help='Host to connect to')
	parser.add_argument('--port', '-p', type=int, default=41938,
			help='Port to run keymaker')
	parser.add_argument('--secret', '-s', type=str, required=True,
			help='Secret string that keymaker clients should match')

	subparsers = parser.add_subparsers(dest='command')

	key = subparsers.add_parser('key')
	key.add_argument('--hostname', '-m', default=socket.getfqdn(),
			help='Use custom hostname in key comment')
	key.add_argument('--username', '-u', default=os.environ['USER'],
			help='Use custom username in key comment')
	key.add_argument('--authorized-keys', '-a', action='store_true',
			default=False,
			help='Append key to authorized_keys on keymaker server')
	key.add_argument('--outdir', '-d',
			default=os.path.join(os.environ['HOME'], '.ssh'),
			help='Output directory')
	key.add_argument('--prefix', '-p', default='id_rsa', help='Key prefix')
	return parser

def handle_response(client_socket, outdir, prefix, **kwargs):
	length = struct.unpack('>Q', common.sock_read(client_socket, 8))[0]
	logger.info("Response length: %d" % (length))

	msg = common.sock_read(client_socket, length)

	response = protocol_pb2.Response()
	response.ParseFromString(msg)

	if response.status != protocol_pb2.OK:
		logger.error(response.error)
		return

	if response.type == protocol_pb2.Response.KEY_RESPONSE:
		with open(os.path.join(outdir, prefix), 'wb') as f:
			f.write(response.keyResponse.privateKey)
		with open(os.path.join(outdir, prefix+'.pub'), 'wb') as f:
			f.write(response.keyResponse.publicKey)

def key_request(request, username, hostname, authorized_keys, **kwargs):
		request.type = protocol_pb2.Request.KEY_REQUEST
		request.keyRequest.hostname = hostname
		request.keyRequest.username = username
		request.keyRequest.authorizedKeys = authorized_keys

def client(host, port, secret, command, **kwargs):
	try:
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((host, port))
	except Exception:
		logger.critical('Could not connect to server!')
		logger.critical(traceback.format_exc())
		return

	request = protocol_pb2.Request()
	request.secret = common.sha256(secret)

	if command == 'key':
		key_request(request, **kwargs)
	msg = request.SerializeToString()
	length = struct.pack('>Q', len(msg))
	logger.info("Request length: %d" % (len(msg)))
	import ipdb
	ipdb.set_trace()
	client_socket.sendall(length + msg)
	handle_response(client_socket, **kwargs)


def main(argv):
	parser = setup_parser()
	args = parser.parse_args(argv[1:])

	client(**args.__dict__)

if __name__ == '__main__':
	main(sys.argv)
