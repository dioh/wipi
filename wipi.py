#!/usr/bin/python
#encoding utf-8

import subprocess
import sys
from datetime import datetime
import time

try:
    from scapy.sendrecv import sniff
    from scapy.layers.dot11 import *
except Exception as e:
    print "Install scapy, missing dependency "
    raise e

import string

if len(sys.argv) != 2:
   print "usage: wipi.py iface"
   print "iface must be provided"
   exit(1)

IFACE = sys.argv[1]

dot11_types = [ Dot11Addr3MACField,
        Dot11AssoReq,
        Dot11Beacon,
        Dot11ProbeResp,
        Dot11ReassoResp,
        Dot11ATIM,
        Dot11Addr4MACField,
        Dot11AssoResp,
        Dot11Deauth,
        Dot11PacketList,
        Dot11QoS,
        Dot11SCField, 
        Dot11Addr2MACField,
        Dot11AddrMACField, 
        Dot11Auth,
        Dot11Disas,
        Dot11ProbeReq,
        Dot11ReassoReq,
        Dot11WEP,
        ]

def pull_data():
    """
    Obtiene datos de la interfaz. Deberia delegar el pedido al manager de datos
    """
    sniff(iface = IFACE,
          prn = lambda package: process_sniffed_package(package, dict2log),
          lfilter = lambda package: package.haslayer(Dot11Elt) )

def process_sniffed_package(p, post_process):
    try:
        d = {}
        ssid  = p[Dot11Elt].info
        ssid  = filter(lambda x: x in string.printable, ssid)
        bssid = p[Dot11].addr3
        
        # Guardo el tipo de probe:
        lsublayers = [ i.name for i in filter( lambda x: p.haslayer(x), dot11_types ) ]

        d = {"ssid": ssid, "bssid": bssid, "layers" : lsublayers}

        d["layers"] = ", ".join(lsublayers).replace("802.11 ", "")
        d["size"] = p[Dot11Elt].len * 80 # we want the size in Bytes

        if p.haslayer(Dot11ProbeResp):
            d["ts"] = datetime.strptime(time.ctime(p[Dot11ProbeResp].time),"%a %b %d %H:%M:%S %Y") # TODO: Improve
        elif p.haslayer(Dot11Beacon):
            d["ts"] = datetime.strptime(time.ctime(p[Dot11Beacon].time),"%a %b %d %H:%M:%S %Y")
        else:
            d["ts"] = datetime.now()

        post_process(d)
    except Exception as e:
        print e

def dict_print(d):
    """
    Example implementation to print package's info
    """
    for k, v in d.items():
        print "%s \t=\t%s" % (k, v) 
import time
dict2log_template = '{mac} - - {ts} "GET {request}" {response_code} {request_size} "-" "-" "{access_point}"' 
def dict2log(kwargs):
    """
    Print sniffed package's info to a NCSA-like log format
    """
    access_point  = kwargs.get("ssid", "Unknown")
    mac           = kwargs.get("bssid", "Unknown")
    ts            = kwargs.get("ts", datetime.now())
    request_size  = kwargs.get("size", "100")
    response_code = kwargs.get("code", "200")
    request       = "%s TYPE" % access_point

    if access_point == mac == "Unknown":
        return

    print dict2log_template.format(mac=mac, ts=ts.strftime("[%d/%b/%Y:%H:%M:%S +0000]"), request=request,
                          response_code=response_code, request_size=request_size, access_point=access_point)

if __name__ == '__main__':
    #subprocess.Popen(["airmon-ng", "start", IFACE ]) #TODO: implement monitor mode detection (or externalize?)
    pull_data()

