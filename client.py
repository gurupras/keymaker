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
	logging.basicConfig(level=logging.DEBUG)
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
	key.add_argument('--authorized-keys', '-a', action='store_true',
			default=False,
			help='Append key to authorized_keys on keymaker server')

	key_sp = key.add_subparsers(dest='sub_command')
	keygen = key_sp.add_parser('gen')
	keygen.add_argument('--hostname', '-m', default=socket.getfqdn(),
			help='Use custom hostname in key comment')
	keygen.add_argument('--username', '-u', default=os.environ['USER'],
			help='Use custom username in key comment')
	keygen.add_argument('--outdir', '-d',
			default=os.path.join(os.environ['HOME'], '.ssh'),
			help='Output directory')
	keygen.add_argument('--prefix', '-p', default='id_rsa', help='Key prefix')

	key_existing = key_sp.add_parser('existing')
	key_existing.add_argument('public_key', type=str, help='Existing key')
	return parser

def handle_response(client_socket, **kwargs):
	length = struct.unpack('>Q', common.sock_read(client_socket, 8))[0]
	logger.debug("Response length: %d" % (length))

	msg = common.sock_read(client_socket, length)
	logger.info("Received response")

	response = protocol_pb2.Response()
	response.ParseFromString(msg)

	if response.status != protocol_pb2.OK:
		logger.error(response.error)
		return
	else:
		logger.debug("OK")

	if response.type == protocol_pb2.Response.KEY_RESPONSE:
		with open(os.path.join(kwargs['outdir'], kwargs['prefix']), 'wb') as f:
			f.write(response.keyResponse.privateKey)
		with open(os.path.join(kwargs['outdir'], kwargs['prefix']+'.pub'), 'wb') as f:
			f.write(response.keyResponse.publicKey)

def key_request(request, sub_command, authorized_keys, **kwargs):
	request.keyRequest.authorizedKeys = authorized_keys

	if sub_command == 'gen':
		key_generate(request, kwargs['username'], kwargs['hostname'])
	elif sub_command == 'existing':
		key_existing(request, kwargs['public_key'])

def key_generate(request, username, hostname):
	request.type = protocol_pb2.Request.KEY_REQUEST
	request.keyRequest.type = protocol_pb2.KeyRequest.KEY_REQUEST_GENERATE
	request.keyRequest.generate.hostname = hostname
	request.keyRequest.generate.username = username

def key_existing(request, public_key):
	request.type = protocol_pb2.Request.KEY_REQUEST
	request.keyRequest.type = protocol_pb2.KeyRequest.KEY_REQUEST_EXISTING
	key = None
	with open(public_key, 'rb') as f:
		key = f.read()
	setattr(request.keyRequest.existing, 'publicKey', key)

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
	logger.debug("Request length: %d" % (len(msg)))
	client_socket.sendall(length + msg)
	logger.info("Request sent")
	handle_response(client_socket, **kwargs)


def main(argv):
	parser = setup_parser()
	args = parser.parse_args(argv[1:])

	client(**args.__dict__)

if __name__ == '__main__':
	main(sys.argv)
