#! /usr/bin/python

import M2Crypto
import re,os
import pysvn

path_repo = '/data/dispatch/configs/ssl/'

client = pysvn.Client()
client.update(path_repo)

def getdnsnames(crtstring):
    dnsmatch = ""
    dnsline = ""
    dnsnames = ""
    dnsline = list()
    dnsnames = list()

    match = re.search(r'DNS:(?P<domain>.*)',crtstring)
    if(match):
        dnsmatch = match.group('domain') #get the full line

    dnsline = re.split(r'DNS:',dnsmatch)
        
    for line in dnsline:
        line = line.replace(',',"")
        dnsnames.append(line)

    dnsnames.append('Crt-File in dmz-crt Not Found')
    return dnsnames[0]

def svncommit(file_path):
	svnadd = list()
	svnadd.append(file_path)
	if not os.path.exists(file_path):
		for line in svnadd:
			client.add(line)

	client.checkin(svnadd, "+ " + file_path + "\n ueber createcrt-bot") 


for r, d, f in os.walk(os.getcwd()):
            for filename in f:	
                # versteckte detein ueberspringen
                match = re.search(r'^\.',filename)
                if match:
                    continue
                # wenn hinter crt. noch was kommt dann auch ueberspringen
                match = re.search(r'pem\..*',filename)
                if match:
                    continue
                else:
                    if '.pem' in filename:	
			crt = M2Crypto.X509.load_cert(filename)
			crtpem = crt.as_pem()
			crtstring = crt.as_text()

			common_name = getdnsnames(crtstring)
			common_name = common_name.replace(' ','')
			#e.sub('\s\n','',domainname)

			with open(path_repo + '/' + common_name + '/' + common_name + '.cer','w+') as f:
			    f.write(crtstring+crtpem)
			svncommit(path_repo + '/' + common_name + '/' + common_name + '.cer')

			print(filename + " --> " + path_repo + '/' + common_name + '/' + common_name + '.cer')
			os.remove(filename)
