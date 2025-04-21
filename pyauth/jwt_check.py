import jwt
import os
import base64
import time
import jwt
import json
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PUBLIC_KEY_NAME =  'GLOBAL_PUBLIC_KEY'
ISSUER_KEY =  'iss'
ISSUER_VALUE =  'https://lab.shinova.in/'
ISSUED_AT_KEY = "iat"
EXPIRES_AT_KEY = "exp"
AUD_KEY = "aud"

ALLOWED_DATA_KEY = 'allowed-data'
ALLOWED_ACTIONS_KEY = 'allowed-actions'

AUTHZ_MODEL = 'IMPLIED'
AUTHZ_MODEL_IMPLIED = 'IMPLIED'

_pubk_B64 = os.environ[PUBLIC_KEY_NAME]
if not _pubk_B64:
   raise ValueError(f'Private key ({PUBLIC_KEY_NAME}) not set')

_pubk = base64.b64decode(_pubk_B64) 

PUBLIC_KEY = serialization.load_pem_public_key(
   _pubk, backend=default_backend())


def load_module_from_file(file_path):
   module_namespace = {}
   with open(file_path, 'r') as file:
      exec(file.read(), module_namespace)
   return module_namespace

def find_file_by_name(file_name, search_path):
    for root, dirs, files in os.walk(search_path):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

file_path = find_file_by_name("permissions_map.py", ".")
print(f"Loading permissions from: {file_path}")
permissions = load_module_from_file(file_path)

def __checkJwt(accessToken:str):

   ct = round(time.time())
   unverified = jwt.decode(accessToken, options={"verify_signature": False})

   if unverified[ISSUER_KEY] != ISSUER_VALUE :
      raise ValueError(f'Invalid access token [Token not from trusted source]')
   elif unverified[ISSUED_AT_KEY] > ct :
      raise ValueError(f'Invalid access token [Token is not yet valid]')
   elif unverified[EXPIRES_AT_KEY] < ct :
      raise ValueError(f'Invalid access token [Token expired]')

   tokenAud = unverified[AUD_KEY]

   verified = jwt.decode(accessToken, key=_pubk, algorithms="RS256", audience=tokenAud)
   return verified

def checkAccess(accessToken:str, 
                data:str, 
                page:str, 
                action:str) -> dict:

   vJson = __checkJwt(accessToken)

   # Data validation
   if data not in vJson[ALLOWED_DATA_KEY]:
      raise ValueError(f'Access denied [Not entitled to access requested data {data}]', data)

   pageId = permissions.PAGE_MAPPING[page]
   if not pageId:
      raise ValueError(f'Access denied [Invalid page]')

   if pageId in permissions.PAGE_ACTION_MAPPING and action in permissions.PAGE_ACTION_MAPPING[pageId]:
      actionId = permissions.PAGE_ACTION_MAPPING[pageId][action]
   else:
      actionId = permissions.GEN_ACTION_MAPPING[action]

   if not actionId:
      raise ValueError(f'Access denied [Invalid action]')

   permissionId = pageId + '-' + actionId    

   if permissionId not in vJson[ALLOWED_ACTIONS_KEY]:
      if AUTHZ_MODEL == AUTHZ_MODEL_IMPLIED:
         for k in vJson[ALLOWED_ACTIONS_KEY]:
            if k.startswith(permissionId):
               break
         else:
               raise ValueError(f'Access denied [Not allowed to perform {action} on {page}]',action, page)
      else:      
         raise ValueError(f'Access denied [Not allowed to perform {action} on {page}]',action, page)

   # Allowed access
   return vJson
