#! /usr/bin/python

from OpenSSL import crypto
import sys,re
import json,os

class ProgramPaths(object):

    def __init__(self):
        jsonlocation = './'
        if not os.path.isfile(jsonlocation + 'certs.json'):
            jsonlocation = '/etc/certs/'

        with open(jsonlocation + "certs.json", 'r') as jfile:
            json_file = json.load(jfile)
        
        self.json_file = json_file

class GenerateCsr_Key(ProgramPaths):
    def __init__(self,dns_names):
        super().__init__()
        """
        @dns_names
        list with domains common_name is dns_names[0]
        """
        if not isinstance(dns_names,list):
            raise TypeError("dns_names must be a list")
        for item in dns_names:
            if not isinstance(item,str):
                raise ValueError("dns_names items must be a string")
        
        self.dns_names = dns_names
        req,key = self.generate()

        self.keypem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        self.csrpem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def load_openssl_settigs(self,req):
        
        openssl = self.json_file['openssl']

        try:
            req.get_subject().CN = self.dns_names[0]
            req.get_subject().countryName = openssl["countryName"]
            req.get_subject().stateOrProvinceName = openssl["stateOrProvinceName"]
            req.get_subject().localityName =  openssl["localityName"]
            req.get_subject().organizationName = openssl["organizationName"]
            req.get_subject().organizationalUnitName = openssl["organizationalUnitName"]
        except Exception as e:
            raise e

        return req

    def generate(self):

        TYPE_RSA = crypto.TYPE_RSA
        req = crypto.X509Req()
        req = self.load_openssl_settigs(req)

        sans = []
        for i in self.dns_names:
            sans.append("DNS: %s" % i)
        sans = ", ".join(sans)

        base_constraints = ([
            crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        ])
        x509_extensions = base_constraints

        san_constraint = crypto.X509Extension(b"subjectAltName", False, sans.encode())
        x509_extensions.append(san_constraint)
        req.add_extensions(x509_extensions)
        key = self.generateKey(TYPE_RSA, 2048)
        req.set_pubkey(key)
        req.sign(key, "sha1")

        return req,key

    def generateKey(self,type,bits):

        key = crypto.PKey()
        key.generate_key(type, bits)
        return key

if __name__ == "__main__":

    if len(sys.argv) == 1:
        while True:  
            dns_names = input("Enter dns_names spererated by -d: ")
            dns_names = re.split(',|-d',dns_names)
            dns_names = [re.sub('\s','',item) for item in dns_names]
            if isinstance(dns_names,list):
                if len(dns_names) > 0 and not dns_names[0] == "":
                    break
    else:
        dns_names = sys.argv[1:]
    
    try:
        obj = GenerateCsr_Key(dns_names)
    except Exception as e:
        print(e)
        print("dns_names: {0}".format(dns_names))
    
    else:
        data = {}
        csr = ""
        try:
            import M2Crypto  
        except ImportError:
            csr = obj.csrpem
        else:
            Mcsr = M2Crypto.X509.load_request_string(obj.csrpem)
            csr = Mcsr.as_text() + Mcsr.as_pem()
        finally:
            data['csr'] = csr
            data['key'] = obj.keypem

            for end,value in data.items():
                with open(dns_names[0] + '.' + end,'wb') as f:
                    f.write(value)

