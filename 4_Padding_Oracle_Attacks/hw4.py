# Eliad, Arzuan, 206482622
from Crypto.Util import number
from Crypto import Random
import hashlib
from decimal import Decimal, ROUND_CEILING, getcontext, ROUND_UP


######### Internal functions #############################################3

# Fixed values of genrsa valid output for e = 3
def genRSA3():
    p = 168580670972827084784844540179777742311643548375567629426021224544002294505717757026320927726349983841896268045696048269035276398126576948292385045996702400716305326303166917442229725914971673172839765203772704868954022563793131569064459442354427324226286586507383742856365322514203735365382751969804240253551L
    q = 150596961938932321367363770496841799145802520074627815549958864477492382066847142180469461638151883780771729911817947382071787711312576980006871958945100038874694015320304543879383895795762671801801716041980013233089566227101868263002774913623030586457905582870786596717207525284039492992728176464534237561663L
    N = 25387736890134513281271220178680040674767210881925520002955346322803947530709134732724873525133857127746305195489287471529693168620130411509293130460828794779805226652100957103469146277251742208116549681042486073085725014671176980150564060078990641401258756147740579164144664121184520218403548124605846500185467322047632969667511753858299407809668977933864984266849775502896202940704809609308190328293308573341813917327837767653839614922751835628146226871056101720784660328264361421523067689973926822708543894560145753833290393372620221287190844804104146969334874735526497208263826986953255845694158140159319117215313L
    phi = 25387736890134513281271220178680040674767210881925520002955346322803947530709134732724873525133857127746305195489287471529693168620130411509293130460828794779805226652100957103469146277251742208116549681042486073085725014671176980150564060078990641401258756147740579164144664121184520218403548124605846500185148144414721210261359545547622788268211531865414788821873795413874708264132244710101399938928806705719145919370323772002732550813312681699846969866114299281193660986640889960201454068263192477733902413314393035731246804581725221455123610448126689058650682566148326868690254139155012617336047211724980639400100L
    e = 3
    d = 16925157926756342187514146785786693783178140587950346668636897548535965020472756488483249016755904751830870130326191647686462112413420274339528753640552529853203484434733971402312764184834494805411033120694990715390483343114117986767042706719327094267505837431827052776096442747456346812269032083070564333456765429609814140174239697031748525512141021243609859214582530275916472176088163140067599959285871137146097279580215848001821700542208454466564646577409532854129107324427259973467636045508794985155934942209595357154164536387816814303415740298751126039100455044098884579126836092770008411557364807816653759600067L
    return (p, q, N, phi, e, d)

def gen_rsa(e=65537):
    if e == 3:
        return genRSA3()
    random_generator = Random.new().read
    p = primeNum = number.getPrime(1024, random_generator)
    q = primeNum = number.getPrime(1024, random_generator)
    # p = 61
    # q = 53

    n = p * q
    phi = (p - 1) * (q - 1)

    # Took from SO
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def modinv(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception('No modular inverse')
        return x % m

    d = modinv(e, phi)

    return (p, q, n, phi, e, d)


def _bits_of_n(n):
    """ Return the list of the bits in the binary
        representation of n, from LSB to MSB
    """
    bits = []
    while n:
        bits.append(n % 2)
        n /= 2
    return bits


def modexp_lr(a, b, n):
    """
        This is for a fast modular exponentiation.
        Returns a^b mod n
    """
    r = 1
    for bit in reversed(_bits_of_n(b)):
        r = r * r % n
        if bit == 1:
            r = r * a % n
    return r


def RSAEnc(plain, e, N):
    return modexp_lr(plain, e, N)


def RSADec(cipher, d, N):
    return modexp_lr(cipher, d, N)


######### Ex1 #############################################

def RSAOracle(cipher, dec_oracle_input):
    (d, N) = dec_oracle_input
    plain = RSADec(cipher, d, N)
    return plain % 2


"""
You have an access to the function RSAOracle().
You MUST NOT use RSADec(), d, phi, p or q in your code.
Whenever you call RSAOracle() you should also give it dec_oracle_input as a second parameter.

@:param cipher - A cipgertext
@:param e - The public key
@:param N - The big number (N = pq)
@:param dec_oracle_input - decryption oracle which works in the following way:
 the decryption oracle computes m = cd mod N and outputs the least signinificant bit of the result.
@:returns the original message m
"""


def BreakRSA(cipher, e, N, dec_oracle_input):
    """
    # As we explained in the class we did a kind of binary search.
    # Suppose m is in the range (a,b) (So a < m < b)
    # The i'th iteration we will check the oracle for c' = m^e * 2^ (i * e) modeN
    # If we get m is even we know that m is in the range (a, (a+b) / 2)
    # If m is odd we know that m is in the range ((a + b) / 2, b)
    # We will continue until a == b
    """
    # First 0<m<n so a is 0 and b is N
    a = 0
    b = N
    # The pow of 2^e - calculate for optimization
    twoPowE = modexp_lr(2, e, N)
    # The pow of 2 ^ (i * e)
    ePow = modexp_lr(2, e, N)
    # for i in range(0, limit):
    while a != b:
        # We want to represent the encryption of m * (2^i)
        cTag = (ePow * cipher) % N
        # Update ePow
        ePow = ePow * twoPowE
        # Calling the oracle
        oracleOutput = RSAOracle(cTag, dec_oracle_input)
        # Moving on by the oracle output of the current ctag before changing
        if (oracleOutput == 0):
            b = Decimal((a + b) / 2)
        else:
            a = Decimal((a + b) / 2)

    return int(round(a))


def Test1():
    """ This tests BreakRSA function. """
    (p, q, N, phi, e, d) = gen_rsa(e=3)  # these values are freshly generated when testing your implementation
    plain = 3679
    cipher = RSAEnc(plain, e, N)
    dec_oracle_input = (d, N)
    plain2 = BreakRSA(cipher, e, N, dec_oracle_input)
    if plain == plain2:
        print "Success"
    else:
        print "Failure"


######### Ex2 #############################################

KEYLEN = 2048 / 8  # the key length that we use for this exercise is 1024 bits, you may use this magic variable.
SIG_MAGIC = '0001'
HASH_MAGIC = '003021300906052B0E03021A05000414'


def VerifyRSASigOracle(msg, sig, e, N):
    '''
    msg is a hex string
    sig is a hex string that should be a 'signature' of msg
    N is the RSA modulo as returned from gen_rsa(e=3)
    e=3 is the "public exponent"
    '''
    # hash the message
    msg_digest = hashlib.sha1(msg)
    digest_hex = msg_digest.hexdigest()

    if not len(sig) == KEYLEN * 2:  # multiplied by 2 because every hex char represents only 4 bits
        print "Failure: length does not match"
        return -1

    # get the message. sig should be msg^d then (msg^d)^e=msg
    sig_int = int(sig, 16)
    msg2 = modexp_lr(sig_int, e, N)

    # take a hex string of the resulting msg
    hexstring = hex(msg2)[2:-1].zfill(KEYLEN * 2).strip('L')
    # hexstring = hex(msg2).strip('0x')
    if not SIG_MAGIC == hexstring[0:4]:
        print hexstring
        print hexstring[0:4]
        print "Failure: first two bytes are not 0x0001"
        return -1
    hexstring = hexstring[4:]

    # remove the ff bytes
    i = 0
    while 1:
        if not hexstring[i:i + 2] == 'ff':
            break
        i += 2
    hexstring = hexstring[i:]

    # strip the hash magic
    if not HASH_MAGIC.lower() == hexstring[0:len(HASH_MAGIC)]:
        print "Failure: malformed hash magic"
        return -1
    hexstring = hexstring[len(HASH_MAGIC):]

    # check that the next bytes equal sha1(msg)
    if not digest_hex == hexstring[0:40]:  # 20 bytes, each takes 2 hex characters
        print "Failure: message digest does not match"
        return -1

    print "success"
    return 0


"""
@:param x a number
@:returns the cube of the closest number y>=x such that y has a cubic root.
"""
def closest_cube(x):
    getcontext().prec = KEYLEN
    y = (Decimal(x) ** (Decimal(1) / Decimal(3))).to_integral_exact(ROUND_CEILING)
    return int(y)

def hexStringToInt(x):
    return int(x, 16)


"""
You need to access VerifyRSASigOracle(msg, sig, e, N) and "convince" it to return 0 (success).
When you access it you forward the parameters msg, N and e that you got as input.
The function should return a valid signature of msg according to VerifyRSASigOracle.

@:param msg - A message
@:param N is RSA modulu
@:param e - the public-key (the verification exponent),
@:returns a signature on the message msg that will be successfully veried by the
function VerifyRSASigOracle
"""

def ForgeSignature(msg, N, e):
    # Compute k - the length of N in bits
    # We told that k is 2048
    k = N.bit_length()
    # Compute h = SHA-1(msg) and convert to hex
    h = hashlib.sha1(msg).hexdigest()
    # ((0001FF || ANS.1) || h) * 2^8 * (k/8 - 39)
    # Namely, a k bit message starting with the padding of m with a single FF byte, and ending with zeroes.
    v = str(SIG_MAGIC) + "FF" + HASH_MAGIC + h
    # The length of v
    size = len(v)
    # We will add zeroes until 2 * KEYLEN size
    v = v + (2 * (k / 8) - size) * "0"
    v = hexStringToInt(v)
    # We will Search for a number v + d which is slightly larger than v  that has cubic root over the integers
    # We want slightly because we added zeroes at the and of 0001FF || ANS.1 || H(m) so after it there are garbage bits
    # So we want v will be on those garbage bits
    # We will return the cubic root of s + v
    # We do from 2 to -1 to strip 0x and L
    ret =  hex((closest_cube(v)))[2:-1]
    # Padding to 2 * KEYLEN length to pass the length test in validation
    ret = ret.zfill(2 * KEYLEN)
    return ret


def Test2():
    """ This tests the ForgeSignature() function"""
    (p, q, N, phi, e, d) = gen_rsa(e=3)  # these values are freshly generated when testing your implementation
    msg = "asasdad"
    sig = ForgeSignature(msg, N, e)
    if 0 == VerifyRSASigOracle(msg, sig, e, N):
        print "Success"
    else:
        print "Failure"


######### main #############################################
if __name__ == '__main__':
    print "Test 1 results:"
    Test1()
    print ""
    print "Test 2 results:"
    Test2()

