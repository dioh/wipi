import subprocess
import sys
from datetime import datetime
try:
    from scapy.sendrecv import sniff
    from scapy.layers.dot11 import *
except Exception as e:
    print "Install scapy, dependency not met"
    raise e

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
        Dot11WEP]
        #Dot11Elt,


def pull_data():
    """ Obtiene datos de la interfaz. Deberia delegar el pedido al manager
        de datos """
    sniff(iface=IFACE,prn = lambda x: process_sniffed_package(x, dict2log), lfilter=lambda x: x.haslayer(Dot11Elt) )

def process_sniffed_package(p, post_process):

    d = {}

    try:
        ssid        = p[Dot11Elt].info
        d["ssid"]   = ssid
        bssid       = p[Dot11].addr3		
        d["bssid"]  = bssid

        # Guardo el tipo de probe:
        lsublayers = [ i.name for i in filter( lambda x: p.haslayer(x), dot11_types ) ]

        d = {"ssid": ssid, "bssid": bssid, "layers" : lsublayers}

        d["req"] = lsublayers[-1]
        d["size"] = p[Dot11Elt].len * 8

        if p.haslayer(Dot11ProbeResp):
            d["ts"] = p[Dot11ProbeResp].timestamp

        if p.haslayer(Dot11Beacon):
            d["ts"] = p[Dot11Beacon].timestamp

        d["ts"] = datetime.now()
        #strptime

        post_process(d)
    except Exception as e:
        print e

def dict_print(d):
    for k, v in d.items():
        print "%s \t=\t%s" % (k, v) 

def post_process_package_action(d):
    if d: print d

def dict2log(kwargs):
    access_point = kwargs.get("ssid", "Unknown")
    mac = kwargs.get("bssid", "Unknown")
    ts = kwargs.get("ts", "[0/0/00:0:0]")
    request_size = kwargs.get("size", "100") 
    response_code = kwargs.get("code", "200") 
    
    # TODO: lo armamos en el process o en el post process?
    request         = kwargs.get("req", "frula")

    if access_point == mac == "Unknown":
        return
    
    template =  '{mac} - - {ts} "{request}" {response_code} {request_size} "-" "-" "{access_point}"' 

    print template.format(mac=mac, ts=ts.strftime("[%d/%b/%Y:%H:%M:%S]"), request=request, response_code=200,
            request_size=request_size, access_point=access_point)


if __name__ == '__main__':
    #subprocess.Popen(["airmon-ng", "start", IFACE ])
    pull_data()
