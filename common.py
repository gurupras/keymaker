import hashlib

def sha256(string):
	m = hashlib.sha256()
	m.update(string)
	return m.hexdigest()
