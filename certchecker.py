#! /usr/bin/python

import M2Crypto,OpenSSL,os,re
from glob import glob

def check_associate_cert_with_private_key(cert, private_key):
    """
    :type cert: str
    :type private_key: str
    :rtype: bool
    """
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        raise Exception('private key is not correct: %s' % private_key)

    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        raise Exception('certificate is not correct: %s' % cert)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error as e: 
	return False

if __name__ == '__main__':
	cer_filename = ''
	key_filename = ''

	for file in glob(os.getcwd() + '/*'):
	    if re.search(r'\.key$',file):
        	key_filename = file
	    elif re.search(r'\.cer$',file):
        	cer_filename = file

	try:
		cert =  M2Crypto.X509.load_cert(cer_filename)
		key = M2Crypto.RSA.load_key(key_filename)
	
	except Exception as e:
		if e.errno == 2:
			if cer_filename == '':
				print("cer file not found")
			elif key_filename == '':
				print("key file not found")
		else:
			print(e)

	else:
		keypem = key.as_pem(cipher=None)
		certpem = cert.as_pem()
		print('PrivateKey Checker\ncer: {0}\nkey: {1}\n\nis_valid: {2}'.format(cer_filename,key_filename,check_associate_cert_with_private_key(certpem,keypem)))
