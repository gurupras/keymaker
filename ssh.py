import os,sys
import json
import re

SSH_PATTERN = re.compile(r'(?P<line>(?P<key>ssh-rsa .*?) (?P<comment>.*))')

KEY_FILE=os.path.join(os.environ['HOME'], '.ssh', 'authorized_keys')

def parse_key(string):
	m = SSH_PATTERN.match(string)
	assert m
	d = m.groupdict()
	return d

def get_authorized_keys(key_file=KEY_FILE):
	keys = {}
	with open(key_file, 'rb') as f:
		for line in f:
			line = line.strip()
			if line == '':
				continue
			d = parse_key(line)
			keys[d['comment']] = d
	return keys

def update_key(keys, key):
	keys[key['comment']] = key

def update_authorized_keys(keys, key_file=KEY_FILE):
	content = '\n'.join([x['line'] for x in keys.values()])
	with open(key_file, 'wb') as f:
		f.write(content + '\n')

def main(args):
	with open('/home/guru/.ssh/authorized_keys', 'rb') as f:
		for line in f:
			m = SSH_PATTERN.match(line)
			assert m

			d = m.groupdict()
			print json.dumps(d)

if __name__ == '__main__':
	main(sys.argv)
