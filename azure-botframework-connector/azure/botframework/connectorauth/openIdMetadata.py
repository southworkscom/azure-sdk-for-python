from datetime import datetime, timedelta
import base64
import struct
import requests

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class OpenIdMetaData:
    def __init__(self, openIdUrl):
        self.url = openIdUrl
        self.lastUpdated = datetime.min
        self.keys = {}

    def getKey(self, keyId):
        now = datetime.now()
        if(self.lastUpdated < now - timedelta(days=1)):
            self.refreshCache()
        if keyId in self.keys:
            return self.keys[keyId]
        else:
            return "", []

    def intarr2long(self, arr):
        return int(''.join(["%02x" % byte for byte in arr]), 16)

    def base64_to_long(self, data):
        if isinstance(data, str):
            data = data.encode("ascii")
        # urlsafe_b64decode will happily convert b64encoded data
        _d = base64.urlsafe_b64decode(bytes(data) + b'==')
        return self.intarr2long(struct.unpack('%sB' % len(_d), _d))

    def refreshCache(self):
        res = requests.get(self.url)
        res.raise_for_status()
        openIdConfig = res.json()
        r = requests.get(openIdConfig["jwks_uri"])
        r.raise_for_status()
        jwks = r.json()["keys"]
        self.keys = {}
        for jwk in jwks:
            if(('e' in jwk) or ('n' in jwk)):
                exponent = self.base64_to_long(jwk['e'])
                modulus = self.base64_to_long(jwk['n'])
                numbers = RSAPublicNumbers(exponent, modulus)
                public_key = numbers.public_key(backend=default_backend())
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                kid = jwk['kid']
                endorsements = []
                if 'endorsements' in jwk:
                    endorsements = jwk['endorsements']
                self.keys[kid] = pem.decode('utf-8'), endorsements
        self.lastUpdated = datetime.now()