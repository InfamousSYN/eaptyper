#!/usr/bin/python3
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

import argparse
from scapy.all import *
import settings as config

parser = argparse.ArgumentParser(description='Automated Wireless Supported EAP-Method Fingerprinting Tool')
eapSettingsOptions = parser.add_argument_group(description='EEAP Settings')
eapPeapOptions = parser.add_argument_group(description='EAP-PEAP Specific Settings')
eapInnerAuthOptions = parser.add_argument_group(description='Inner Auth Settings (PEAP/TTLS)')

parser.add_argument('--version', action='version', version=config.__version__)
parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true', help='toggle verbosity')
parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=config.argpaser_timeout, help='Control timeout for wpa_supplicant connection length. Default: {}'.format(config.argpaser_timeout))

sourceMode = parser.add_argument_group(description='Specify source for targeting information')
sourceMode.add_argument('-m', choices=[0,1], dest='mode', type=int, help='0 = live, 1 = pcap', required=True)

liveCaptureOptions = parser.add_argument_group(description='Specify targeting information for live extration. Used when -m 0 source mode is chosen')
liveCaptureOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
liveCaptureOptions.add_argument('-c', '--channel', dest='channel', help='set interface channel to use')
liveCaptureOptions.add_argument('-sl', dest='ssid', help='select target SSID')
liveCaptureOptions.add_argument('-bl', dest='bssid', nargs='+', default=[], help='select BSSID')
liveCaptureOptions.add_argument('-bL', dest='bssid_file', default=None, help='provide file containing BSSIDs')

args, leftover = parser.parse_known_args()
options = args.__dict__

class EapTyper():

    class _interfaceManagement():

        @classmethod
        def __init__(self, interface=None, channel=None, revert_interfaces=None, verbose=False):
            self.verbose = verbose
            self.revert_interfaces = revert_interfaces
    
            self.interface=interface
            self.channel=channel

        @classmethod
        def getRevertInterfaceStatus(self):
            return self.revert_interfaces
    
        @staticmethod
        def ifaceUp(interface):
            import os
            os.system('ifconfig {} up'.format(interface))
            return
    
        @staticmethod
        def ifaceDown(interface):
            import os
            os.system('ifconfig {} down'.format(interface))
            return
    
        @staticmethod
        def testIfaceOpMode(interface):
            import os
            return os.popen('iwconfig {}'.format(interface)).read()
    
        @staticmethod
        def ifaceMonitor(interface):
            import os
            os.system('iwconfig {} mode monitor'.format(interface))
            return
    
        @staticmethod
        def ifaceManaged(interface):
            import os
            os.system('iwconfig {} mode managed'.format(interface))
            return
    
        @staticmethod
        def ifaceChannel(interface, channel):
            import os
            os.system('iwconfig {} channel {}'.format(interface, channel))
            return
    
        @staticmethod
        def getSenderAddress(interface):
            import os
            try:
                return os.popen('cat /sys/class/net/{}/address'.format(interface)).read().strip('\n')
            except Exception as e:
                print('[!]\tInterface \'{}\' not found!'.format(interface))
                if(self.verbose):
                    print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
    
        @staticmethod
        def nmcliDisable(interface):
            import os
            try:
                os.system('nmcli device set {} managed no'.format(interface))
            except Exception as e:
                if(self.verbose):
                    print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
            return
    
        @staticmethod
        def nmcliEnable(interface):
            import os
            try:
                os.system('nmcli device set {} managed yes'.format(interface))
            except Exception as e:
                if(self.verbose):
                    print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
            return
    
        @staticmethod
        def testIfaceConMode(interface):
            import os
            return os.popen('nmcli device show {}'.format(interface)).read()
    
        @classmethod
        def disable_nmcli_interface(self, interface):
            if(self.verbose):
                print('[-]\tDisabling nmcli\'s management of interface: {}'.format(interface))
            self.nmcliDisable(interface=interface)
    
        @classmethod
        def enable_nmcli_interface(self, interface):
            if(self.verbose):
                print('[-]\tEnabling nmcli\'s management of interface: {}'.format(interface))
            self.nmcliEnable(interface=interface)
    
        @classmethod
        def check_interface_control_mode(self, interface, keyword='unmanaged'):
            res = self.testIfaceConMode(interface=interface)
            for line in res.splitlines():
                if( "GENERAL.STATE:" in line and "{}".format(keyword) not in line ):
                    return True
                else:
                    return False
    
        @classmethod
        def set_interface_monitor(self, interface):
            if(self.verbose):
                print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'monitor\''.format(interface))
            self.ifaceDown(interface=interface)
            self.ifaceMonitor(interface=interface)
            self.ifaceUp(interface=interface)
    
        @classmethod
        def set_interface_managed(self, interface):
            if(self.verbose):
                print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'managed\''.format(interface))
            self.ifaceDown(interface=interface)
            self.ifaceManaged(interface=interface)
            self.ifaceUp(interface=interface)
    
        @classmethod
        def check_interface_operational_mode(self, interface, keyword='Monitor'):
            res = self.testIfaceOpMode(interface=interface)
            return True if 'Mode:{}'.format(keyword) in res else False
    
        @classmethod
        def set_interface_channel(self, interface, channel):
            if(self.verbose):
                print('[-]\tInterface Channel: changing \'{}\' channel to \'{}\''.format(interface, channel))
            self.ifaceChannel(interface=interface, channel=channel)

    class _80211FrameManagement():

        @staticmethod
        def sendFrame(pkt, interface, verbose=False, count=3, inter=1):
            if(verbose):
                print('[-]\tPacket Emission ({}):\r\n[-]\t\tcount: {}\r\n[-]\t\tPacket:\r\n[-]\t\t{}\r\n[-]'.format(interface, count, pkt.summary))
            junk = sendp(pkt, iface=interface, inter=inter, count=count)
            return

        @staticmethod
        def currentTime(boottime):
            import time
            return (time.time()-boottime*1000000)

        @classmethod
        def __init__(self,interface=None,ssid=None,bssid=None,senderAddress=None,retry=3,pause=1,timeout=3,verbose=False):
            self.verbose = verbose
            self.interface=interface
            self.ssid=ssid
            self.bssid=bssid
            self.senderAddress = senderAddress
            self.retry = retry
            self.pause = pause
            self.timeout = timeout
            self.RadioTap_layer = RadioTap()

            self.state_machine_state = 'probe'
            self.probeResponsePacket = None
            self.associationResponsePacket = None
            self.authenticationRespPacket = None

        @classmethod
        def getStateMachineStatus(self):
            return self.state_machine_state

        @classmethod
        def setTargetBssid(self, bssid=None):
            self.bssid = bssid

        @classmethod
        def sniffThread(self):
            if(self.state_machine_state == 'probe'):
                packets = sniff(iface=self.interface,timeout=self.timeout)
                for packet in packets:
                    self.findProbeResponse(packet=packet)
                del packets

            if(self.state_machine_state == 'authenticate'):
                packets = sniff(iface=self.interface,timeout=self.timeout)
                for packet in packets:
                    self.findAuthenticationResponse(packet=packet)
                del packets

            if(self.state_machine_state == 'associate'):
                packets = sniff(iface=self.interface,timeout=self.timeout)
                for packet in packets:
                    self.findAssociationResponse(packet=packet)
                del packets

        @classmethod
        def deauthenticationFrame(self):
            from datetime import datetime
            import time
            boottime=time.time()
            dst=bssid=self.bssid
            print('[-]\t802.11 Frame Crafting: Deauthentication\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(self.ssid, self.senderAddress.lower(), bssid.lower(), dst.lower()))
            packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Deauth(reason=7)
            packet.timestamp = self.currentTime(boottime)
            self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
            return 0

        @classmethod
        def createProbeRequestFrame(self):
            from datetime import datetime
            import time
            boottime=time.time()
            loop = 1
            dst=bssid=self.bssid
    
            self.state_machine_state == 'probe'
            while loop <= self.retry:
                print('[-]\t802.11 Frame Crafting: Probe Request Attempt {}\r\n[-]\t\tssid: {}\r\n[-]\t\tSTA: {}\r\n[-]\t\tBSSID: {}\r\n[-]\t\tDST: {}'.format(
                    loop, 
                    self.ssid, 
                    self.senderAddress.lower(), 
                    bssid.lower(), 
                    dst.lower()
                ))
    
                packet = self.RadioTap_layer/Dot11(type=0, subtype=4, addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11ProbeReq()/Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))/Dot11EltRates()
                packet.timestamp = self.currentTime(boottime)
                t = threading.Thread(target=self.sniffThread, daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
                t.join()
                if(self.probeResponsePacket is None and loop < self.retry):
                    print('[!]\tProbe Request: No response detected!\r\n[-]')
                    loop += 1
                elif(self.probeResponsePacket is None and loop == self.retry):
                    print('[!]\tProbe Request: No response detected!\r\n[-]')
                    self.deauthenticationFrame()
                    return 1
                elif(self.probeResponsePacket is not None):
                    print('[!]\tProbe Request: Probe response detected!\r\n[-]')
                    break
                else:
                    pass
            return 0

        @classmethod
        def findProbeResponse(self, packet=None):
            if( (packet.haslayer(Dot11ProbeResp)) and (packet.info.decode('utf-8') == self.ssid) and (packet.addr1 == self.senderAddress) ):
                self.state_machine_state = 'authenticate'
                self.probeResponsePacket = packet
                self.bssid=packet.addr3
                self.real_capability = int(self.probeResponsePacket.getlayer(Dot11ProbeResp).cap)
                self.real_bssid = (self.probeResponsePacket.getlayer(Dot11).addr3)
                self.packet_probe_response_dot11elt_layer = packet.getlayer(Dot11Elt)

        @classmethod
        def createAuthenticationFrame(self):
            from datetime import datetime
            import time
            boottime=time.time()
            dst=bssid=self.bssid
            loop = 1 
            while loop <= self.retry:
                print('[-]\t802.11 Frame Crafting: Authentication Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(
                    loop, 
                    self.ssid, 
                    self.senderAddress.lower(), 
                    bssid.lower(), 
                    dst.lower()
                ))
    
                packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
                packet.timestamp = self.currentTime(boottime)
                t = threading.Thread(target=self.sniffThread, daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
                t.join()
                if(self.authenticationRespPacket is None and loop != self.retry):
                    print('[!]\tAuthentication Request: No response detected!')
                    loop += 1
                elif(self.authenticationRespPacket is None and loop == self.retry):
                    print('[!]\tAuthentication Request: No response detected!')
                    self.deauthenticationFrame()
                    return 1
                elif(self.authenticationRespPacket is not None):
                    print('[!]\tAuthentication Request: Authentication response detected!')
                    break
                else:
                    pass
            return 0

        @classmethod
        def findAuthenticationResponse(self, packet=None):
            if( (packet.haslayer(Dot11Auth)) and (packet.addr3 == self.bssid.lower()) and 
                (packet.addr1 == self.senderAddress.lower())):
                self.state_machine_state = 'associate'
                self.authenticationRespPacket = packet
                return packet
            return None

        @classmethod
        def createAssociationFrame(self, addr1=None):
            from datetime import datetime
            import time
            boottime=time.time()
            dst=bssid=self.bssid
            loop = 1 
            while loop <= self.retry:
                print('[-]\t802.11 Frame Crafting: Association Request Attempt {}\r\n\t\tssid: {}\r\n\t\tSTA: {}\r\n\t\tBSSID: {}\r\n\t\tDST: {}'.format(
                    loop, 
                    self.ssid, 
                    self.senderAddress.lower(), 
                    bssid.lower(), 
                    dst.lower()
                ))
    
                packet = self.RadioTap_layer/Dot11(addr1=dst, addr2=self.senderAddress, addr3=bssid)/Dot11AssoReq(cap=self.real_capability, listen_interval=0x0001)/self.packet_probe_response_dot11elt_layer
                packet.timestamp = self.currentTime(boottime)
                t = threading.Thread(target=self.sniffThread, daemon=True)
                t.start()
                time.sleep(self.pause)
                self.sendFrame(pkt=packet, interface=self.interface, verbose=self.verbose, count=1)
                t.join()
                if(self.associationResponsePacket is None and loop != self.retry):
                    print('[!]\tAssocation Request: No response detected!')
                    loop += 1
                elif(self.associationResponsePacket is None and loop == self.retry):
                    print('[!]\tAssocation Response: No response detected!')
                    self.deauthenticationFrame()
                    return 1
                elif(self.associationResponsePacket is not None):
                    print('[!]\tAssociation Request: Association response detected!')
                    break
                else:
                    pass
            return 0

        @classmethod
        def findAssociationResponse(self, packet=None):
            if( (packet.haslayer(Dot11AssoResp)) and (packet.addr3 == self.bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
                self.associationResponsePacket = packet
                return packet
            elif( (self.associationResponsePacket is not None) and (packet.haslayer(EAP)) and (packet.addr3 == self.bssid.lower()) and (packet.addr1 == self.senderAddress.lower()) ):
                self.eapIdentityPacket = packet
                return packet
            return None

    @classmethod
    def __init__(self, interface=None, channel=None, ssid=None, bssids=None, identity=None, revert_interfaces=False, verbose=False):
        self.verbose = verbose
        self.revert_interfaces = revert_interfaces

        self.interface=interface
        self.channel=channel
        self.ssid=ssid
        self.bssids=bssids
        self.identity=identity
        self._interfaceManagementObject = self._interfaceManagement(
            interface=self.interface,
            channel=self.interface,
            revert_interfaces=self.revert_interfaces)
        self.FrameManagementObject = self._80211FrameManagement(
            interface=self.interface,
            ssid=self.ssid,
            senderAddress=self._interfaceManagementObject.getSenderAddress(
                interface=self.interface
                ))

    @classmethod
    def main(self):
        try:
            if(self.verbose):
                print('[-]\tSetting \'{}\' to operational mode to monitor'.format(self.interface))
            if(not self._interfaceManagementObject.check_interface_operational_mode(interface=self.interface, keyword='unamanged')):
                self._interfaceManagementObject.disable_nmcli_interface(interface=self.interface)

            if(not self._interfaceManagementObject.check_interface_operational_mode(interface=self.interface, keyword='Monitor')):
                self._interfaceManagementObject.set_interface_monitor(interface=self.interface)

            if(self.channel is not None):
                self._interfaceManagementObject.set_interface_channel(interface=self.interface, channel=self.channel)

            for bssid in self.bssids:
                self._80211FrameManagement.setTargetBssid(bssid=bssid)
                self._80211FrameManagement.createProbeRequestFrame()
                if(self._80211FrameManagement.getStateMachineStatus() == 'authenticate'):
                    self._80211FrameManagement.createAuthenticationFrame()
                if(self._80211FrameManagement.getStateMachineStatus() == 'associate'):
                    self._80211FrameManagement.createAssociationFrame()

            if(self._interfaceManagementObject.getRevertInterfaceStatus()):
                self._interfaceManagementObject.set_interface_managed(interface=self.interface)
                self._interfaceManagementObject.enable_nmcli_interface(interface=self.interface)

        except Exception as e:
            print('[!] Error: {}'.format(e))
            if(self._interfaceManagementObject.getRevertInterfaceStatus()):
                self._interfaceManagementObject.set_interface_managed(interface=self.interface)
                self._interfaceManagementObject.enable_nmcli_interface(interface=self.interface)
        return 0

if __name__ == '__main__':
    import os

    try:
        if(not os.geteuid() == 0):
            print('You need to be root to run this tool')
            exit(0)
        else:
            if(options['mode'] == 0):
                print('[+] Entering \'live fingerprinting mode\'\r\n[-]')
                bssidList = list()
                if( (not options['bssid']) and (options['bssid_file'] is None) ):
                    bssidList.append('ff:ff:ff:ff:ff:ff')
                else:
                    if(options['bssid'] is not None):
                        for bssid in options['bssid']:
                            bssidList.append(bssid)
                    elif(options['bssid_file'] is not None):
                        with open(options['bssid_file'], 'r') as f:
                            bssidList.append(f.readlines().strip('\n'))
                        f.close()
                    else:
                        pass
                EapTyper(
                    interface=options['interface'], 
                    channel=options['channel'], 
                    ssid=options['ssid'], 
                    bssids=bssidList
                ).main()
    except Exception as e:
        print('Error: {}'.format(e))
        exit(1)
