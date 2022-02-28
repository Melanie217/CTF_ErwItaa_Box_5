#!/usr/bin/python2
import os
import json
from pickle import FALSE, TRUE
import sys
import time

from Crypto.Cipher import AES



example_cookie = open("cookie", "r").read().strip()
CBC_key = open("key", "r").read().strip()
crypto_challenge_flag = open("flag", "r").read().strip()



welcome_text = """
Unser Admin Melli der Hobbygaertner Inc. wollte sich in ihrer Freizeit etwas mit Krypto beschaeftigen und hat neuerdings das CBC fuer sich entdeckt. 
Leider hat sie sich ausversehen selbst ausgesperrt und benoetigt nun einen gueltigen Cookie um sich bei ihrer privaten Seite anzumelden. 
Kannst du ihr eventuell zu Hand gehen? 
Hinweis: Oracle Padding
"""
def padding(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def isvalidpadding(s):
  return ord(s[-1])*s[-1:]==s[-ord(s[-1]):]

def unpad(s):
  return s[:-ord(s[len(s)-1:])]

def encrypt(m):
  IV="Das heisst IV456"
  cipher = AES.new(CBC_key.decode('hex'), AES.MODE_CBC, IV)
  return IV.encode("hex")+cipher.encrypt(padding(m)).encode("hex")

def decrypt(m):
  cipher = AES.new(CBC_key.decode('hex'), AES.MODE_CBC, m[0:32].decode("hex"))
  return cipher.decrypt(m[32:].decode("hex"))
  

# flush output immediately
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
print (welcome_text)
print ("Hier siehst du wie so ein Cookie aussehen soll: " + encrypt(example_cookie))

while TRUE:
    # Get their cookie
    print ("\n\n## Wie lautet der Cookie, welcher Melli den Zugriff ermoeglicht?\n > ")
    cookie2 = sys.stdin.readline()
    
    # decrypt, but remove the trailing newline first
    cookie2decoded = decrypt(cookie2[:-1])

    if isvalidpadding(cookie2decoded):
      d=json.loads(unpad(cookie2decoded))
      print ("Username: " + d["username"])
      print ("Adminflag gesetzt? " + d["is_admin"])
      exptime=time.strptime(d["expires"],"%Y-%m-%d")
      if exptime > time.localtime():
          print ("Cookie is gueltig")
      else:
          print ("Cookie ist abgelaufen")
      if d["is_admin"]=="true" and exptime > time.localtime():
          print ("Hier ist die flag: " + crypto_challenge_flag)
          break;
          
    else:
      print ("Ungueltiges Padding!")
