import logging
import jwt
import json
from collections import Mapping

from .microsoftAuthentication import AuthSettings
from .openIdMetadata import OpenIdMetaData

class BotCredentials:
    def __init__(self, appId = "", password = ""):
        self.appId = appId
        self.appPassword = password

class BotConnectorEndPoint:
    def __init__(self):
        self.refreshEndpoint = ""
        self.refreshScope = ""
        self.botConnectorOpenIdMetadata = ""
        self.botConnectorIssuer = ""
        self.botConnectorAudience = ""
        self.emulatorOpenIdMetadata = ""
        self.emulatorAuthV31IssuerV1 = ""
        self.emulatorAuthV31IssuerV2 = ""
        self.emulatorAuthV32IssuerV1 = ""
        self.emulatorAuthV32IssuerV2 = ""
        self.emulatorAudience = ""

class BotAuthenticatorSettings(BotCredentials):
    def __init__(self, appId = "", password = "", endpoint : BotConnectorEndPoint = "", openIdMetaDataUrl: str = ""):
        super(self.__class__, self).__init__(appId, password)
        self.endpoint = endpoint
        self.openIdMetaDataUrl = openIdMetaDataUrl

class BotAuthenticator:
    def __init__(self, options : BotAuthenticatorSettings = None ):
        self.settings = {}
        for key in AuthSettings:
            self.settings[key] = AuthSettings[key]
        if(options):
            if(options.openIdMetaDataUrl):
                self.settings["botConnectorOpenIdMetadata"] = options.openIdMetaDataUrl
            if(options.appId != None):
                self.settings["botConnectorAudience"] = options.appId
                self.settings["emulatorAudience"] = options.appId
        self.settings["appId"] = options.appId
        self.settings["appPassword"] = options.appPassword
        self.botConnectorOpenIdMetadata = OpenIdMetaData(self.settings["botConnectorOpenIdMetadata"])
        self.emulatorOpenIdMetadata = OpenIdMetaData(self.settings["emulatorOpenIdMetadata"]);

    def authorize(self, headers, channelId = None, serviceUrl = None):
        token = ""
        isEmulator = (channelId != None) and (channelId == 'emulator')
        authHeaderValue = ""
        if ( 'authorization' in headers):
            authHeaderValue = headers['authorization']
        elif('Authorization' in headers):
            authHeaderValue = headers['Authorization']

        if(authHeaderValue):
            auth = authHeaderValue.strip().split(' ')
            if(len(auth) == 2 and auth[0].lower() == 'bearer'):
                token = auth[1]

        if token:
            decoder = jwt.PyJWT()
            payload, signing_input, header, signature = decoder._load(token)
            algorithms = ['RS256', 'RS384', 'RS512']

            try:
                jsonPayload = json.loads(payload.decode('utf-8'))
            except ValueError as e:
                raise jwt.DecodeError('Invalid payload string: %s' % e)
            if not isinstance(jsonPayload, Mapping):
                raise jwt.DecodeError('Invalid payload string: must be a json object')

            openIdMetaData = None
            verifyOptions = {"algorithms" : algorithms, "iss": "", "aud": "", "clockTolerance": 300}

            if isEmulator:
                if(((jsonPayload["ver"] == "2.0") and (jsonPayload["azp"] != self.settings["appId"])) or ((jsonPayload["ver"] != "2.0") and (jsonPayload["appid"] != self.settings["appId"]))):
                    raise Exception('ChatConnector: receive - invalid token. Requested by unexpected app ID.')

                openIdMetaData = self.msaOpenIdMetadata
                verifyOptions["aud"] = self.settings["emulatorAudience"]

                if((jsonPayload["ver"] == "1.0") and (jsonPayload["iss"] == self.settings["emulatorAuthV31IssuerV1"])):
                    verifyOptions["iss"] = self.settings["emulatorAuthV31IssuerV1"]
                elif((jsonPayload["ver"] == "2.0") and (jsonPayload["iss"] == self.settings["emulatorAuthV31IssuerV1"])):
                    verifyOptions["iss"] = self.settings["emulatorAuthV31IssuerV2"]
                elif((jsonPayload["ver"] == "1.0") and (jsonPayload["iss"] == self.settings["emulatorAuthV32IssuerV1"])):
                    verifyOptions["iss"] = self.settings["emulatorAuthV32IssuerV1"]
                elif((jsonPayload["ver"] == "2.0") and (jsonPayload["iss"] == self.settings["emulatorAuthV32IssuerV2"])):
                    verifyOptions["iss"] = self.settings["emulatorAuthV32IssuerV2"]

            else:
                openIdMetaData = self.botConnectorOpenIdMetadata
                verifyOptions["iss"] = self.settings["botConnectorIssuer"]
                verifyOptions["aud"] = self.settings["botConnectorAudience"]

            
            key, keyEndorsements = openIdMetaData.getKey(header['kid'])
            if(key):
                try:
                    decoder._verify_signature(payload, signing_input, header, signature, key=key, algorithms=verifyOptions["algorithms"])

                    if(jsonPayload["iss"] != verifyOptions["iss"] or jsonPayload["aud"] != verifyOptions["aud"]):
                        raise Exception('BotAuthenticator: receive - invalid token. Check bot\'s app ID & Password.')

                    if(channelId and keyEndorsements and (channelId not in keyEndorsements)):
                        errMsg = 'channelId in req.body: {0} didn\'t match the endorsements: {1}'.format(channelId, ', '.join(keyEndorsements))
                        raise Exception(errMsg)

                    if(serviceUrl and ("serviceUrl" in jsonPayload) and jsonPayload["serviceUrlr"] and jsonPayload["serviceUrl"] != serviceUrl):
                        errMsg = 'ServiceUrl in payload of token: {0} didn\'t match the request\'s serviceurl: {1}.'.format(jsonPayload["serviceUrl"], serviceUrl)
                        raise Exception(errMsg)
                except:
                    raise
            else:
                raise Exception('BotAuthenticator: receive - invalid signing key or OpenId metadata document.')
        elif isEmulator and ("appId" not in self.settings or (not self.settings["appId"])) and ("appPassword" not in self.settings or (not self.settings["appPassword"])):
            logging.warning('BotAuthenticator: receive - emulator running without security enabled.')
        else:
            raise Exception('BotAuthenticator: receive - no security token sent.')
