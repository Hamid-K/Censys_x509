"""
You can use this script to parse Censys,io x509 scan files to generate
PEM files for each certificate.
PEM files can then be processed with 'roca-detect' tool to check for
RSA keys that are vulnerable as the result of an implementation flaw
in Infenion RSA key generation algorithm.

"""


import os
import json
from pprint import pprint

try:
	os.makedirs('certs')
except OSError as e:
	if e.errno != errno.EEXIST:
		raise
#with open ('txufevlyrf6fy3s98-certificates.20171016T020002.3.json') as data_file:
with open ('xufevlyrf6fy3s98-certificates.20171016T020002.3.json') as data_file:	
	for line in data_file:
		data = json.loads(line)
		filename = os.path.join('certs',data["fingerprint_sha256"]+'.pem')
		#print '-----BEGIN CERTIFICATE-----\n',data["raw"],'\n-----END CERTIFICATE-----'
		#print data["parsed"]["subject_key_info"]["rsa_public_key"]["modulus"]
		try:
			f = open(filename,"w")
			f.write('-----BEGIN CERTIFICATE-----\n')
			f.write(data["raw"])
			f.write('\n-----END CERTIFICATE-----')
			f.close
		except OSError as e:
			if e.errno != errno.EEXIST:
				raise

