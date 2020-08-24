from OpenSSL import crypto

class GenerateCsr_Key():
    def __init__(self,dns_names):
        """
        @dns_names
        list with domains common_name is dns_names[0]
        """
        self.dns_names = dns_names
        req,key = self.generate()

        self.keypem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        self.csrpem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def generate(self):

        TYPE_RSA = crypto.TYPE_RSA
        req = crypto.X509Req()

        req.get_subject().CN = self.dns_names[0]
        req.get_subject().countryName = "AT"
        req.get_subject().stateOrProvinceName = "Wien"
        req.get_subject().localityName =  "Wien"
        req.get_subject().organizationName = "Stadt Wien"
        req.get_subject().organizationalUnitName = "MA01"

        sans = []
        for i in self.dns_names:
            sans.append("DNS: %s" % i)
        sans = ", ".join(sans)

        base_constraints = ([
            crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
        ])
        x509_extensions = base_constraints

        san_constraint = crypto.X509Extension("subjectAltName", False, sans)
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
