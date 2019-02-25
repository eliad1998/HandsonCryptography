from Crypto.Cipher import AES
# def padpkcs7(msg):
# 	"""THIS IS A DUMMY FUNCION, you should implement padpcks7 in the exercise."""
# 	return "0123456789abcdef".encode('hex')

"""
:param an integer
@:returns ascii string represented by that integer
"""
def intToHexByte(x):
    hexX = hex(x)
    strHex = str(hex(x))[2:]

    if (x < 16):
        strHex = "0" + strHex
    return strHex

def hexByteToInt(hexStr):
    if len(hexStr) < 2:
        return -1

    if (hexStr[0] == '0'):
        hexStr = hexStr[1:]

    return int(hexStr,16)

def padpkcs7(pthex):
    # Counter by bytes - two hex chars is bytes
    size = len(pthex) / 2

    x = 16 - size % 16
    # Convert from hex string
    hexX = intToHexByte(x)

    p = ""
    for i in range(0,x):
        p += hexX

    # Outputs M || P
    return pthex + p


def aesecb(phex):
	key = 'abcdefghijklmnop' #this is secret
	s = "wowamazing".encode('hex')				#this is secret

	cipher = AES.new(key, AES.MODE_ECB)
	ptexthex = padpkcs7(phex + s)
	ctext =cipher.encrypt(ptexthex.decode('hex'))
	return ctext.encode('hex')


# def checkpkcs7(pthex):
# 	"""THIS IS A DUMMY FUNCION, you should implement checkpkcs7 in the exercise."""
# 	return False

def checkpkcs7(padded_pthex):
    size = len(padded_pthex) / 2
    sizeHex = size * 2
    # First checks if didides 16
    if (size % 16 != 0):
        return False

    try:
        # The last byte is pi and should be multpled by x
        pi = padded_pthex[sizeHex - 2:sizeHex]
        # pi should be equals to x = 16 - len(pthex) / 2
        x = hexByteToInt(pi)
        if (x == 0):
            return False
        # Cant be bigger then 16 in that padding
        if (x > 16):
            return False
        # What pi should be
        p = pi * x
        # Checks if the last x bytes equals to p
        return padded_pthex[sizeHex - 2 * x:sizeHex] == p
    except Exception, e:
        return False
def aescbc(ivhex, cipherhex):
    key = 'abcdefghijklmnop' #this is secret
    decipher = AES.new(key, AES.MODE_CBC, ivhex.decode('hex'))
    mprime = decipher.decrypt(cipherhex.decode('hex'))
    goodpadding = checkpkcs7(mprime.encode('hex'))
    return goodpadding

# aes cbc encryption
def aescbcEncrypt(ivhex,plaintext):
    key = 'abcdefghijklmnop'  # this is secre
    decipher = AES.new(key, AES.MODE_CBC, ivhex.decode('hex'))
    c = decipher.encrypt(plaintext.decode('hex'))
    return c.encode("hex")

if __name__ == '__main__':
    # print aesecb("hello".encode('hex'))
	# aescbc("0123456789abcdef".encode('hex'),"abcdefghijklmnop".encode('hex'))
    iv = "0123456789abcdef".encode("hex")
    plaintext = padpkcs7("abcdefghijklmnopqrstuvawafhgjhwh".encode("hex"))
    print plaintext
    encode =  aescbcEncrypt(iv,plaintext)
    aescbc(iv,encode)

