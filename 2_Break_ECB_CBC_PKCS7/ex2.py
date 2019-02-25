#Eliad,Arzuan,206482622
from aesoracles import *
"""
Helping functions
"""
# Converts ascii string to hex string
def asciiToHexString(str):
    return ''.join(x.encode('hex') for x in str)

# Converts hex string to ascii string
def hexStringToAscii(hexString):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(hexString[0::2],hexString[1::2])])

# Xor two ascii strings
def xorAsciiStrings(size, ascii1,ascii2):
    ret = ""
    for i in range(0,size):
        try:
            # Remove the 0x
            xorRes = hex(ord(ascii1[i]) ^ ord(ascii2[i]))
            if (xorRes > 0):
                xorRes = xorRes[2:]
            if int(xorRes,base=16)< 16:
                ret += "0"
            ret += xorRes
        except:
            print "Got exception probebly you gave wrong length"
            break
    return ret
def xorEqualLength(hex1, hex2):
    size = len(hex1) / 2
    ascii1 = hexStringToAscii(hex1)
    ascii2 = hexStringToAscii(hex2)
    return xorAsciiStrings(size,ascii1=ascii1,ascii2=ascii2)
# Xoer two hex strings with different length
# The hex strings should represent ascii
def xorHex(hex1, hex2):
    size1 = len(hex1)
    size2 = len(hex2)
    # Adding zero in start of the smaller string
    hex1 = (size2 > size1) * (size2 - size1) * "0" + hex1
    hex2 = (size1 > size2) * (size1 - size2) * "0" + hex2

    return xorEqualLength(hex1,hex2)

"""
:param an integer
@:returns ascii string represented by that integer
"""
def intToHexByte(x):
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

"""
@:param str: string
@:param size: The size we want to split the string by
@:return array of the string splitted by chunkSize
"""
def splitString(str, size):
    chunks = len(str)
    arr =   [ str[i:i+size] for i in range(0, chunks, size) ]
    return arr

# Getting block from a string
# Num block starts at 0
def getBlockFromString(str,numBlock):
    return str[numBlock * 32: numBlock * 32 + 32]

# Getting the number of blocks of 16 bytes in string
def getNumBlocks(str):
    return len(str) / 2 / 16


"""
    # Question 1.1
    @:param pthex: a message string M of
                   arbitrary length |M| (which is counted by bytes) - so each 2 hex chars will be byte
    @:returns
"""
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

"""
# Question 1.2
@:param padded_pthex: hex string corresponding to M' (M || P).
@:returns true if padded correctly according to the PKCS#7 standard.
  False returned otherwise
"""
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
        # Cant end with 0
        if x == 0:
            return False

        # Cant be bigger then 16 in that padding
        if (x > 16):
            return False
        # What pi should be
        p = pi * x
        # Checks if the last x bytes equals to p
        return padded_pthex[sizeHex - 2 * x:sizeHex] == p
    except Exception, e:
        print "Got exception checfkpkcs7 with reason" + str(e)
        return False

"""
    # Question 2
    @:param aesecboracle: an oracle to AES-ECB
    The oracle computes AES-ECB_k(padpkcs(p||s)
    @:returns the string s
"""
def breakecb(aesecboracle):
    # AES return 16 bytes blocks
    # So len / 2 is the number of bytes
    # numBlocks  represents the nubmer of bytes in s because empty string will send only s
    numBlocks = getNumBlocks (aesecboracle(""))
    # ciphertext[i][j] = The j block of calling to the oracle with p = i zero bytes
    ciphertexts = []
    pOptions = []
    sizeString = -1
    # Finding s
    s = ""
    for j in range(0,16):
        p = "00" * j
        pOptions.append(p)
        # Adding the ciphertext splitted by blocks
        ciphertexts.append(splitString(aesecboracle(p),32))

    # Find the real size of the string
    for j in reversed(range(0,16)):
        # When the size changes
        if (len(ciphertexts[j]) == numBlocks  and sizeString == -1):
            # minus 1 because the last index
            sizeString = 16 - j - 1
    sizeString = sizeString + 16 * (numBlocks - 1)
    countS = 0
    # Finding s
    for i in range(0, numBlocks + 1):
        if (countS == sizeString):
            break
        for j in reversed(range(0,16)):
            # Getting the desired block of the real ciphertext
            realCText =  ciphertexts[j][i]
            # Optional cipher texts
            # Checks all 256 options
            optionCtexts = []
            for k in range(0,256):
                optionsPlaintext = pOptions[j] + s + intToHexByte(k)
                # Getting the desired block from the plaintext
                optionCtexts.append(getBlockFromString(aesecboracle(optionsPlaintext),i))
            # Getting the real byte of k
            k = optionCtexts.index(realCText)
            s += intToHexByte(k)
            countS = countS + 1
            # Stop when getting the desired size
            if (countS == sizeString):
                break
    return s
# Remove last block of 16 bytes from string
def removeLastBlock(hexStr):
    lenHex = len(hexStr)
    # Remove the last block
    return hexStr[0:lenHex - 32]
# for example if hexByte = a1 and numbyte is 0 we want to xor the first byte of hexByte with numByte
def xorIByteHex(hexString,hexByte, numByte):
    size = len(hexString) / 2
    # Minus 1 because we have hexByte
    sendByte = hexByte + (size - numByte - 1) * "00"
    return xorHex(sendByte,hexString)

# Getting specific b
"""
# Question 3
@:param ivhex : hex-string IV of length 16 bytes represents initial vector
@:param cipherHex : hex-string C where |C|= 16 * c for some natural c
@:returns true if padded correctly according to the PKCS#7 standard.
  False returned otherwise
"""
def breakcbc(ivhex, cipherhex, aescbcoracle):
    # Adding the iv in order to find the first block.
    # With the "trick" of change iv bytes we can get the first block bytes
    ytag = ivhex + cipherhex
    # Remove the last block because we already know the last block of plaintext will be 10101010...
    ytag = removeLastBlock(ytag)
    numBlocks = getNumBlocks(ytag)
    plaintext = ""
    for i in range(0, numBlocks - 1):
        plainBlock = ""
        # Getting the i'th block for IV concatenationed with the ciphertext
        ytagk = getBlockFromString(ytag,i)
        # Moving on y_l-k bytes
        for k in reversed(range(0,16)):
            # Make ytag last bytes to be as padding for 16-k length
            # For example if k = 14 we want the two last bytes of plaintext will be 0x2
            # We already know the last byte of plaintext so we will xor with it and with 0x2
            # Then we will check options until the last two bytes will be 0x2
            modifiedYtagK = xorHex(ytagk,plainBlock)
            modifiedYtagK = xorHex(modifiedYtagK, intToHexByte(16 - k) * (15 - k))

            # Go over all possible 256 values of a byte b
            for b in range(0, 256):
                xored = xorIByteHex(modifiedYtagK,intToHexByte(b),k)
                # The oracle shows padding ok so the real byte will be 16-k xor b
                # Because 16-k caused the padding
                cipherCheck = xored + getBlockFromString(ytag,i + 1)
                if (aescbcoracle(ivhex,cipherCheck)):
                    plainBlock = xorHex(intToHexByte(16 - k),intToHexByte(b)) + plainBlock
                    # There is a small chance padding was successful.
                    # Since the value of this byte is 0x02 and the previous byte is also 0x02.
                    # It will hapappen if the real plaintext byte xor b will give 0x02
                    if k == 15:
                        # Xor the byte before with ff in order to change from 0x2 in the case it is 0x2
                        xored = xorIByteHex(xored,"ff", k -1)
                        cipherCheck = xored + getBlockFromString(ytag, i + 1)
                        if aescbcoracle(ivhex, cipherCheck) == False:
                            plainBlock =""
                            continue
                    break
        plaintext += plainBlock
    return plaintext


