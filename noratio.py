#!/usr/bin/env python

# tcpdump -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

import sys, random, time, signal
import requests, hashlib, codecs
import bencoding

def sendAnnounce(event = ""):
    global announce_delay, announce_count
    announce_count += 1
    announce_params["event"] = event
    if (announce_params["event"] == ""):
        del announce_params["event"]
    r = requests.get(announce_url, params=announce_params, headers=announce_headers)
    body_decode = bencoding.bdecode(r.content)
    if (b'interval' in body_decode):
        announce_delay = int(body_decode[b'interval'])
    print("%s announce %02i" % (timestamp(), announce_count), end="")
    if ("event" in announce_params):
        print(" " + announce_params["event"], end="")
    print(" uploaded: %i/%iMB, downloaded: %i/%iMB" % (announce_params["uploaded"]/1024/1024, max_upload/1024/1024, announce_params["downloaded"]/1024/1024, max_down/1024/1024), end="")
    print(", delay %im%is" % (announce_delay//60, announce_delay%60))
   
def timestamp():
    current_time = time.localtime()
    return "[%02i:%02i:%02i]" % (current_time[3], current_time[4], current_time[5])

def ctrlc_handler(sig, frame):
    sendAnnounce("stopped")
    sys.exit()
signal.signal(signal.SIGINT, ctrlc_handler)

def peer_id():
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    peer_id = "-TR2940-"
    checksum = 0
    for x in range(11):
        i = random.randrange(0, len(alphabet))
        peer_id += alphabet[i]
        checksum += i
    if (checksum % len(alphabet)) != 0:
        peer_id += alphabet[len(alphabet) - checksum % len(alphabet)]
    else:
        peer_id += alphabet[0]
    return peer_id

announce_count = 0
announce_headers = {"User-Agent": "Transmission/2.94"}
announce_params = {}
announce_delay = 180

arguments = sys.argv
if (len(arguments) > 1):
    if ("--help" in arguments):
        print("-t <torrent file> -mu <max_upload in MB> -md <max_down in MB> -su <min_speed in KB/s> <max_speed in KB/s> -sd <min_speed in KB/s> <max_speed in KB/s>")
        sys.exit()
    else:
        max_down = 0
        max_upload = 0
        speed_up = (800, 3000)
        speed_down = (800, 2000)

        if ("-f" in arguments):
            torrent_file = open(arguments[arguments.index("-f") + 1], "rb")
            torrent_decoded = bencoding.bdecode(torrent_file.read())
            announce_params["info_hash"] = codecs.decode(hashlib.sha1(bencoding.bencode(torrent_decoded[b"info"])).hexdigest(), "hex")
            torrent_length = (len(torrent_decoded[b"info"][b"pieces"]) / 20) * torrent_decoded[b"info"][b"piece length"]
            announce_url = torrent_decoded[b"announce"]
            print("torrent size: %iMB" % (torrent_length // 1024 // 1024))
            max_upload = random.randrange(40, 80) * torrent_length // 100
            max_down = random.randrange(1, 8) * torrent_length // 100

        if ("-mu" in arguments):
            max_upload = int(arguments[arguments.index("-mu") + 1]) * 1024 * 1024
        if ("-md" in arguments):
            max_down = int(arguments[arguments.index("-md") + 1]) * 1024 * 1024
        if ("-su" in arguments):
            speed_up = (int(arguments[arguments.index("-su") + 1]), int(arguments[arguments.index("-su") + 2]))
        if ("-sd" in arguments):
            speed_down = (int(arguments[arguments.index("-sd") + 1]), int(arguments[arguments.index("-sd") + 2]))
else:
    sys.exit()

announce_params["peer_id"] = peer_id()
announce_params["port"] = random.randrange(10000, 64000)
announce_params["uploaded"] = 0
announce_params["downloaded"] = 0
announce_params["left"] = random.randrange(max_down, torrent_length)
announce_params["numwant"] = 80
# INT_MAX
announce_params["key"] = hex(random.randrange(0, 2147483647) % 2147483647)[2:]
announce_params["compact"] = 1
announce_params["supportcrypto"] = 1
# announce_params["no_peer_id"] = 1
sendAnnounce("started")
# announce_params["numwant"] = 0

while ((max_upload > announce_params["uploaded"]) or (max_down > announce_params["downloaded"])):
    time.sleep(announce_delay)
    if (max_upload > announce_params["uploaded"]):
        announce_params["uploaded"] += (((random.randrange(speed_up[0], speed_up[1])) * announce_delay) * 1024)
        if (announce_params["uploaded"] > max_upload):
            announce_params["uploaded"] = max_upload
    if (max_down > announce_params["downloaded"]):
        chunk = (((random.randrange(speed_down[0], speed_down[1])) * announce_delay) * 1024)
        if (chunk > (max_down - announce_params["downloaded"])):
            chunk = max_down - announce_params["downloaded"]
        announce_params["downloaded"] += chunk
        announce_params["left"] -+ chunk
    sendAnnounce()

sendAnnounce("stopped")
