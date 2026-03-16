import base64
import os

CRYPT_ALGORITHM_VALUE = "bit_map"
pfn = "permissions_master"
pfx = ".lst"


def __find_file_by_name(file_name, search_path):
    for root, dirs, files in os.walk(search_path):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

# initialize map
master_permissions = {}
master_versions = set()

def __load_permissions(permVer=""):
    global master_permissions
    master_versions.add(permVer)

    fn = pfn + (f"_{permVer}" if permVer else "") + pfx
    permissions_file_path = __find_file_by_name(fn, os.getcwd())

    if not permissions_file_path:
        raise ValueError(f'Permissions file not found: {permVer}')

    perms = []
    with open(permissions_file_path, 'r') as f:
        perms = [line.strip() for line in f.readlines()]
    perms_hash = str(hash(''.join(perms)))
    master_permissions[perms_hash] = perms



def crypt(permsHash: str, actions: list[str] = []) -> tuple[str, str]:
    bitMap = bytes(128)
    permissions = master_permissions.get(permsHash)

    for action in actions:
        if action not in permissions:
            continue
        
        position = permissions.index(action)
        #Get the byte at the position
        bytePosition = position // 8
        bitPosition = position % 8

        #set bit position to 1
        currentByte = bitMap[bytePosition]
        bitMap = bitMap[:bytePosition] + bytes([currentByte | (1 << (7 - bitPosition))]) + bitMap[bytePosition+1:]  
 
    # base64 encode the bitmap
    base64BitMap = base64.b64encode(bitMap).decode('utf-8')
    return CRYPT_ALGORITHM_VALUE, base64BitMap

def decrypt(permsHash: str, base64BitMap: str) -> list[str]:
    # decode base64 to bytes
    bitMap = base64.b64decode(base64BitMap.encode('utf-8'))
    actions = []
    
    print(bitMap)

    permissions = master_permissions.get(permsHash)

    # reverse the bitmap to get actions
    for i in range(len(bitMap)*8):
        bytePosition = i // 8
        bitPosition = i % 8
        if bitMap[bytePosition] & (1 << (7 - bitPosition)):
            actions.append(permissions[i])

    return actions

def supported(permsVer: str, permsHash: str) -> bool:
    if permsHash in master_permissions:
        return True
    elif permsVer in master_versions:
        raise ValueError(f'Permissions file not found: {permsVer}')
    else:
        __load_permissions(permsVer)
        return permsHash in master_permissions
