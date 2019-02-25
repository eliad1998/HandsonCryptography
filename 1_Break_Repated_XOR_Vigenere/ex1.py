
from collections import Counter
from numpy import argmax
from math import sqrt
"""
Helping functions
"""

# Converts ascii string to hex string
def asciiToHex(str):
    return ''.join(x.encode('hex') for x in str)

# Converts hex string to ascii string
def hexStringToAscii(hexString):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(hexString[0::2],hexString[1::2])])


def getXoredAscii(ascii1,ascii2):
    ret = ""
    xorRes = hex(ord(ascii1) ^ ord(ascii2))
    if (xorRes > 0):
        xorRes = xorRes[2:]
    if int(xorRes, base=16) < 16:
        ret += "0"
    ret += xorRes
    return ret

# Write string into a binary file
def binFileWrite(str, fileName):
    with open(fileName, "wb") as file:
        file.write(str)

# Reads a binary file content
def binFileRead(fileName):
    with open(fileName, "rb") as file:
        return file.read()

# Getting the divisors of a number - function form the internet
def divisors(n):
    divs = [1]
    for i in xrange(2,int(sqrt(n))+1):
        if n%i == 0:
            divs.extend([i,n/i])
    divs.extend([n])
    return list(set(divs))


"""
Question 1 Area
"""
def xorAsciiStrings(len, ascii1,ascii2):
    ret = ""
    for i in range(0,len):
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
"""
* Question 1
* In order to calculate the xor between 2 hex string, I iterated the string and stored each character represented
  by hex value in an array.
* After it I converted to characters to int and did xor between the integers.
* In the end I returned string built from each the xor values.
"""

def my_xor(len, hex1, hex2):
    ascii1 = hexStringToAscii(hex1)
    ascii2 = hexStringToAscii(hex2)
    return xorAsciiStrings(len,ascii1=ascii1,ascii2=ascii2)


"""
Question 2 area
"""

"""
 * We want to find the key we do xor with.
 * We will do it by finding the most common letter which is e.
 * After it we will xor it with e and we will get the key.
 * @:param encryptedhex the encryptedhex
 * @:param regularCommon the most common char in text witout spaces is e
           and in regular text is space.
 * @:return the key
 """
def findXorKey(encryptedhex, regularCommon):
    #Counts the letters
    asciiText = hexStringToAscii(encryptedhex)
    mostCommonChar,count = Counter(asciiText).most_common(1)[0]
    # Xor between the most common character in our encrypted text and the regular
    return xorAsciiStrings(1,mostCommonChar,regularCommon)

"""
 * We want to find the original hex after encryption when we getting the most frequent char on the regular text.
 * After it we will xor it with e and we will get the key.
 * @:param encryptedhex the encryptedhex
 * @:param regularCommon the most common char in text witout spaces is e
           and in regular text is space.
 * @:return the key
 """
def originalHex(len, encryptedhex,regularCommon):
    #Find the key of the string
    key = findXorKey(encryptedhex,regularCommon)
    keys = key * len
    #Create string of the keys in order to make the xor easier
    return my_xor(len,keys,encryptedhex)
"""""
 # Question 2.1
 * The encrypted hex is the original hex xored with the key.
 * In order to find the key we will find the most common char (which is usually e in the original text).
 * We will xor it with the most common char and get the key.
 * After it we will xor each character with the key (equivalent to xor with string of keys with the length of the
  encrypted hex).
 * And then we will get the original hex.
 """
def originalhex1(len,encryptedhex):
    return originalHex(len,encryptedhex,"e")
"""
# Question 2.2
# In this version of the question the most frequent character is space so we will use the function with space
"""
def originalhex2(len, encryptedhex):
    return originalHex(len,encryptedhex," ")


"""
 * Question 3
 * @param plaintextlength the length of the plaintext.
 * @param plaintexhex an hex string representation fo a plaintext.
 * @param keylength the length of the key
 * @param keyhex the hex representation of the key
 * @return
"""

def repeatedxor(len, plaintexthex, keylen, keyhex):
    hexPlainLen = len * 2
    plaintextAscii = hexStringToAscii(plaintexthex)
    keyAscii = hexStringToAscii(keyhex)
    xored = ""
    for i in range(0,len):
        xored += getXoredAscii(plaintextAscii[i],keyAscii[i % keylen])
    return xored


"""
Question 4 area.

Finding the key length:
    # First we will find the length of the key by the algorithm of xoring adjacent ciphertext strings of
      length t, and count the frequency of obtaining zeroes.
    # We will get the t that will cause to maximum frequency of zeros and it will probably be the key.

Finding the plaintext:
    # After we found the key length we will run the algorithm from question2 in order to find the plaintext.
    # We will split out input text by the key length and apply each block question 2's algorithm.
"""

# Finding the key length by the algorithm told in the question's
def findKeyLength(asciiCipher,length):
    # We told the key will be at least 50 times greater then the text
    limit = length / 50
    zeroCounters = []
    zeroChar = unichr(0)
    for t in range(1, limit + 1):
        i = 0
        zeroCounters.append(0)
        # Getting adjacent substrings of length t
        while i + 2 * t <= length:
            str1 = asciiCipher[i:i + t]
            str2 = asciiCipher[i + t:i + 2 * t]
            xored = xorAsciiStrings(t, str1, str2)
            count = hexStringToAscii(xored).count(zeroChar)
            # We want zerocounters to be the frequency of getting zeroes
            zeroCounters[t - 1] += (count * 100.0) / length
            i += t
    # Checks if the size is ok and return the fixed size
    return checkSizeKey(argmax(zeroCounters) + 1,zeroCounters)


# Return the closest value bigger then the average case
def checkSizeKey(keyLen, zeroCounters):
    # The average case of zero getting
    averageCase = sum(zeroCounters) / len(zeroCounters)
    for i in divisors(keyLen):
        # Bigger a little bit from the average case
        if zeroCounters[i - 1] > averageCase + 2:
            return i
    return keyLen


# Finds the plaintext and the key length.
def breakVigener():
    # Reading the encryption
    asciiCipher = binFileRead("ciphertext.bin")
    hexCipher = asciiToHex(asciiCipher)
    length = len(asciiCipher)
    # Finding the key length
    keyLength = findKeyLength(asciiCipher,length)
    decryptedKey = ""
    limit = length / keyLength
    for i in range(0,keyLength):
        # Splitting the text by steps of the key length
        splitted = asciiToHex(asciiCipher[i:length:keyLength][0:limit])
        decryptedKey +=  hexStringToAscii(findXorKey(splitted,' '))

    # Decrypting the file
    plaintext = hexStringToAscii(repeatedxor(length,hexCipher,keyLength,asciiToHex(decryptedKey)))

    # Writing the decrypted string into the file
    binFileWrite(plaintext,"plaintext.bin")

    return keyLength
