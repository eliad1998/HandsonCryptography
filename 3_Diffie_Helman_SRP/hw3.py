#Eliad, Arzuan, 206482622

import hashlib
import random
import math
# A large safe prime (N = 2q+1, where q is prime)
# All arithmetic is done modulo N
# (generated using "openssl dhparam -text 1024")
N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16)
print 2**1024 - N

g = 2        # A generator modulo N
k = -1 #H(N, g)  # Multiplier parameter (k=3 in legacy SRP-6)

# Use pwd for the password in your implementation.
# It will be changed when testing your implementation.
pwd = "123"

def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N

def gensalt():
    return cryptrand(64)

# note: str converts as is, str( [1,2,3,4] ) will convert to "[1,2,3,4]"
def H(*args):  # a one-way hash function
    a = ':'.join(str(a) for a in args)
    return int(hashlib.sha256(a.encode('utf-8')).hexdigest(), 16)

"""
Exercise 1
Will be tested with Test1() below.
Choose a random value a in [1,p-1]
A = g^a modN
@:param B a number
@:returns A and H(B^a)
"""
def DiffieHellmanClient(B):
    a = cryptrand()
    A = pow(g, a, N)
    return A, H(pow(B, a, N))

# Same as SRPClient but with parameter correct.
"""
@:param salt: salt from the server.
@:param B: B from the server
@:param correct: if true we will check if u  = 0modn and if B = 0 modn.
Otherwise we won't check it
@:return a tuple (c1,c2) where c1 is the A, c2=H(K,A)
"""
def SRPClientOptions(salt,B,pwd,correct):
    #3. Both client and server compute u = H(A,B).
    a = cryptrand()
    A = pow(g, a, N)
    u = H(A,B)
    # Checks only if correct is true
    if correct:
        # If one of this the client abots (these comparisons are done modulo p).
        if u % N == 0 or B % N == 0:
            return
    #5. The client computes x,S,H - all the calculates modulu n
    x = H(salt, pwd)
    S = (B - k * pow(g, x, N))
    S = pow(S, a + u * x, N)
    K = H(S)
    # Return a tuple
    return (A , H(K,A))
"""
#Exercise 2.3: Your implementation of the client
#should return a tuple (c1,c2) where c1=A and c2=H(K,A)

@:param salt,B : salt and B are the first messages that the server sends to the client.
@:param pwd: the password that the client should use in the implementation
@:return 2 values (as a tuple (c1; c2)),
the first is the value A as required by the first value.
And the second is the final value H(K;A) sent from the
client to the server.
"""
def SRPClient(salt,B,pwd):
    # The correct client
   return SRPClientOptions(salt,B,pwd,True)
"""
#Exercise 2.3: Your implementation of the server
@:param A : A from Step 1
@:param pwd: For simplicity, this function receives the user password pwd as a parameter.
@:return a tuple (c1,c2,c3) where c1 is the salt, c2=B and c3=H(K,B)
"""
def SRPServer(A,pwd):
    # Generating a salt
    salt = gensalt()
    b = cryptrand()
    # Calculate v = g^x where x = H(salt,pwd)
    # We now how correct v will look like because we get pwd
    x = H(salt,pwd)
    v = pow(g,x,N)

    B = (k * v + pow(g,b,N))
    u = H(A,B)
    # Stage 6
    # S = (A * v^u)^b mod N
    S = A * pow(v,u,N)
    S  = pow(S,b,N)
    K = H(S)
    # Return a tuple
    return (salt, B, H(K,B))


"""
#Exercise 2.4: Your implementation of an attacker communicating with a wrong server.
The server does not really check the correctness of the value A received from the client.
@:return a tuple (c1,c2) where c1 is the A, c2=H(K,A)
"""
def SRPClientAttacker(salt,B):
    # Because of our assumption that the server does not check anything about A we cant send A = 0.
    A = 0
    # So in the server S = (A*v**u) ** b - in our case A = 0 so S will be 0
    S = 0
    K = H(S)
    return (A , H(K,A))

"""
#This SRP client operates according to the change specified in Exercise 2.5
#Suppose the client does not check that B!=0 as specified in Step 4. Upon receiving B from the server, the
 client computes B = B mod p and proceeds to the rest of the protocol.
@:return (c1,c2) where c1=A and c2=H(K,A)
"""
def SRPIncorrectClient(salt,B):
    # Incorrect client does not check if B!=0
    return SRPClientOptions(salt,B,pwd,False)
"""
#Exercise 2.5: Your implementation of an attacker communicating with an incorrect client
# You should call (c1,c2)=SRPIncorrectClient(salt,B)

@:return the password used by the client
"""
def SRPServerAttacker1():
    #Generating a salt
    salt = gensalt()
    # The client does not check if B!=0 so we will send B = 0
    B = 0
    (A, HKA) = SRPIncorrectClient(salt, B)
    # We get A from the server and choose B to 0
    u = H(A,B)
    # To be able to solve Exercise 2.5 we set k = -1 for the whole assignment.
    # So in the client S = (B- k * g^x)^ (a+ux)
    # Because B = 0 and k = -1 we remains with S = (g^x) ^ (a+ux)
    # So S = (g^x) ^ a * (g^x) ^ (ux) = (g^a)^x * g^ (ux^2)
    # So S = A^x * g^(ux^2) (because A = g^a)
    # We told that the password is a number between 0 to 100000.
    # So in the end, we only have to check all the possible options for x until reaching H(K,A) = HKA from the client
    for password in range(0,100001):
        x = H(salt,password)
        #print "My x is ",x
        # A^x * g^(ux^2)
        S = pow(A,x,N)
        xSquare = pow(x,2,N)
        S = S *  pow(g, u * xSquare,N)
        # Every computation is modulu N
        S = S % N
        K = H(S)
        # Found the real password
        if (H(K,A) == HKA):
            return password


"""
#This SRP client operates according to the changes specified in Exercise 2.6
# The server sends B = g^b (instead of the other option)
#The client computes S = B^(a+u^x) (instead of S = (B-k*g^x)^(a+u*x).
@:return (c1,c2) where c1=A and c2=H(K,A)
"""
def SRPSimplifiedClient(salt,B):
    a = cryptrand()
    A = pow(g, a, N)
    # 3. Both client and server compute u = H(A,B).
    u = H(A, B)
    # If one of this the client abots (these comparisons are done modulo p).
    if u % N == 0 or B % N == 0:
        return
    # 5. The client computes x,S,H - all the calculates modulu n
    x = H(salt, pwd)
    # The client computes S = B^(a+u*x)
    S = pow(B, a + u*x ,N)
    K = H(S)
    # Return a tuple
    return (A, H(K, A))
"""
#Exercise 2.6: Your implementation of an attacker communicating with a simplified client
#You should call (c1,c2)=SRPSimplifiedClient(salt,B)
@:return the password used by the client

"""
def SRPServerAttacker2():
    # Random salt and b
    salt = gensalt()
    b = cryptrand()
    B = pow(g,b,N)
    # Getting data from client
    (A,HKA) = SRPSimplifiedClient(salt,B)
    # 3. Both client and server compute u = H(A,B).
    u = H(A, B)
    # In the client S = B^(a+ux) = (g^b)^a * g^(ux) = (g^a)^b * B^(ux) = A^b * B^(ux)
    # The serer knows everything except x so we will do dictionary attack now
    for password in range(0, 100001):
        x = H(salt, password)
        # S = A^b * B ^ (ux) mod N
        S = pow(A,b , N)
        S = S * pow(B, u * x,N)
        S = S % N
        K = H(S)
        # Correct password
        if (H(K,A) == HKA):
            return password


def Test1():
    '''This is the test for exercise 1, checking your DiffieHelmanClient impl.'''
    b = cryptrand()
    B = pow(g, b, N)
    (A,h) = DiffieHellmanClient(B)
    if H(pow(A,b,N)) != h:
        print "error"
    else:
        print "success"

