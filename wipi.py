import subprocess
try:
    from scapy.sendrecv import sniff
    from scapy.layers.dot11 import *
except Exception as e:
    print "Install scapy, dependency not met"
    raise e

IFACE = "mon0"

dot11_types = [Dot11,
        Dot11Addr3MACField,
        Dot11AssoReq,
        Dot11Beacon,
        Dot11Elt,
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


def pull_data():
    """ Obtiene datos de la interfaz. Deberia delegar el pedido al manager
        de datos """
    sniff(iface=IFACE, prn=lambda x: (x, dict_print))

@staticmethod
def process_sniffed_package(p, post_process):

    d = {}
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) ):

        ssid        = p[Dot11Elt].info
        d["ssid"]   = ssid
        bssid       = p[Dot11].addr3		
        d["bssid"]  = bssid

        # Guardo el tipo de probe:
        lsublayers = [ i.name for i in filter( lambda x: p.haslayer(x), dot11_types ) ]

        channel    = str(ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        #power      = p.sprintf("{PrismHeader:%PrismHeader.signal%}")

        # Check for encrypted networks
        #enc  = 'OPN'
        #penc = re.compile("privacy")
        #if penc.search(capability):enc = 'WEP'

        # Display discovered AP		
        #print ssid+spacing+bssid+"\t"+channel+"\t"+enc+"\t"+power

        # Save discovered AP
        #ap[p[Dot11].addr3] = p[Dot11Elt].info	

        d = {"ssid": ssid, "bssid": bssid, "layers" : lsublayers}

    post_process(d)

@staticmethod
def dict_print(d):
    for k, v in d.items():
        print "%s \t=\t%s" % (k, v) 

@staticmethod
def post_process_package_action(d):
    if d: print d

if __name__ == '__main__':
    #subprocess.Popen(["airmon-ng", "start", IFACE ])
    pull_data()
