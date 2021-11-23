#!/usr/bin/python3

import argparse, subprocess, os
import time, datetime, signal

from lib import conf_manager
import settings as config

parser = argparse.ArgumentParser(description='Automated Wireless Supported EAP-Method Fingerprinting Tool')
eapSettingsOptions = parser.add_argument_group(description='EEAP Settings')
eapPeapOptions = parser.add_argument_group(description='EAP-PEAP Specific Settings')
eapInnerAuthOptions = parser.add_argument_group(description='Inner Auth Settings (PEAP/TTLS)')

parser.add_argument('--version', action='version', version=config.__version__)
parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true', help='toggle verbosity')
parser.add_argument('-i', '--interface', dest='interface', help='Specify interface')
parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=config.argpaser_timeout, help='Control timeout for wpa_supplicant connection length. Default: {}'.format(config.argpaser_timeout))
parser.add_argument('-s', '--ssid', dest='ssid', help='Specify target SSID.')
parser.add_argument('--hidden', dest='hidden', action='store_true', default=False, help='Toggle for hidden network detection. Default: False')

eapSettingsOptions.add_argument('--pairwise', dest='pairwise', default=config.argparser_pairwise_encryption, choices=['CCMP TKIP', 'TKIP CCMP'], help='Specify pairwise encryption order. Default: {}'.format(config.argparser_pairwise_encryption))
eapSettingsOptions.add_argument('--group', dest='group', default=config.argparser_group_encryption, choices=['CCMP TKIP', 'TKIP CCMP'], help='Specify group encryption order. Default: {}'.format(config.argparser_group_encryption))
eapSettingsOptions.add_argument('--identity', dest='identity', default=config.argparser_eap_username, help='Specify EAP identity. Default: {}'.format(config.argparser_eap_username))
eapSettingsOptions.add_argument('--password', dest='password', default=config.argparser_eap_password, help='Specify EAP identity Password. Default: {}'.format(config.argparser_eap_password))
eapSettingsOptions.add_argument('--client-cert', dest='client_cert', default=config.argparser_default_client_cert_location, help='Specify Client public certificate. Default: {}'.format(config.argparser_default_client_cert_location))
eapSettingsOptions.add_argument('--private-key', dest='private_key', default=config.argparser_default_client_private_key_location, help='Specify Client private key location. Default: {}'.format(config.argparser_default_client_private_key_location))
eapSettingsOptions.add_argument('--private-passwd', dest='private_passwd', default=config.argparser_default_client_private_password, help='Specify Client private password. Default: {}'.format(config.argparser_default_client_private_password))

# PEAP
eapPeapOptions.add_argument('--phase1', dest='phase1', default=0, help='')

# Inner Auth
eapInnerAuthOptions.add_argument('--phase2', dest='phase2', default='MSCHAPV2', choices=['MD5', 'MSCHAPV1', 'MSCHAPV2'], help='Select inner EAP tunnel authentication method')

args, leftover = parser.parse_known_args()
options = args.__dict__

class wpaSupplicantWrapper():

    @classmethod
    def __init__(self, target_ssid):
        self.supported_eap_methods_list = list()
        self.unsupported_eap_methods_list = list()
        self.untested_eap_methods_list = list()
        self.proposedMethod=''
        self.target_ssid=target_ssid

    @classmethod
    def wpaSupplicantReporter(self):
        print('[-]  Target network "{}" proposed EAP method: {}'.format(self.target_ssid, self.proposedMethod))
        print('[-]  Following methods are supported by target network:')
        for supported in self.supported_eap_methods_list:
            print('[-]    {}'.format(supported))
        print('[-]  Following methods were rejected by target network:')
        for rejected in self.unsupported_eap_methods_list:
            print('[-]    {}'.format(rejected))
        print('[-]  Following methods are not supported by wpa_supplicant client:')
        for untested in self.untested_eap_methods_list:
            print('[-]    {}'.format(untested))
        print('[-]')
        return


    @classmethod
    def wpaSupplicantOutput(self, wsRawOutput, target_method):
        import re

        # https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml
        eapMethod_dict = {
            4:'md5',    25:'peap',  52:'pwd',
            43:'fast',  21:'ttls',  13:'tls',
            17:'leap',  6:'gtc'
        }
        try:
            clientProposedMethodSelected = []
            clientProposedMethodFailure = []

            # quick logic check to make sure EAP method is supported by wpa_supplicant client
            wsCheckMethodSupport = []
            wsCheckMethodSupport = [ s for s in wsRawOutput.decode('utf-8').split('\n') if 'unknown EAP' in s ]
            if(wsCheckMethodSupport):
                self.untested_eap_methods_list.append(target_method)
                return 1

            # Checks for what is being proposed by the Base Station
            proposedMethod = [ s for s in wsRawOutput.decode('utf-8').split('\n') if 'CTRL-EVENT-EAP-PROPOSED-METHOD' in s ]
            if(not proposedMethod):
                proposedMethod = [None]

            ## Dirty logic to clean up junk in proposed-method message
            if(int(proposedMethod[0].split('=')[2][0]) == 4):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=4']
            elif(int(proposedMethod[0].split('=')[2][0]) == 6):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=6']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 13):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=13']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 17):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=17']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 21):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 25):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 43):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=43']
            elif(int(proposedMethod[0].split('=')[2][0:2]) == 52):
                proposedMethod = ['wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=52']

            ## method look up func
            for key in eapMethod_dict.keys():
                if((key == int(proposedMethod[0].split('=')[2])) and (self.proposedMethod == '')):
                    self.proposedMethod = eapMethod_dict[key]

            # Checks for the acceptance of client proposed EAP method
            clientMethodSelected = [ s for s in wsRawOutput.decode('utf-8').split('\n') if 'selected' in s ]
            if(clientMethodSelected):
                if(target_method not in self.supported_eap_methods_list):
                    self.supported_eap_methods_list.append(target_method)
            else:
                if(target_method not in self.unsupported_eap_methods_list):
                    self.unsupported_eap_methods_list.append(target_method)
        except Exception as e:
            print('[!] Error: {}'.format(e))
            print('wpa_supplicant output:\r\n{}'.format(wsRawOutput.decode('utf-8')))
            return 1
        return 0

    @classmethod
    def wpaSupplicantCtrl(self, target_method):
        command = [
                    'wpa_supplicant',
                    '-i{}'.format(options['interface']),
                    '-c{}'.format(config.wpa_supplicant_conf_file_location),
                    '-f{}/{}_{}_wpa_supplicant.log'.format(config.wpa_supplicant_logfile_location, self.target_ssid, target_method)
        ]
        if(options['verbose']):
            print('[+] Executing wpa_supplicant command: {}'.format(command))
        try:
            # http://howto.philippkeller.com/2007/02/18/set-timeout-for-a-shell-command-in-python/
            start = datetime.datetime.now()
            ps = subprocess.Popen(command,
                            shell=False,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
            )
            while(ps.poll() is None):
                time.sleep(0.1)
                now = datetime.datetime.now()
                if((now-start).seconds > options['timeout']):
                    os.kill(ps.pid, signal.SIGKILL)
                    os.waitpid(-1, os.WNOHANG)
            #print(ps.stdout.read())
            self.wpaSupplicantOutput(wsRawOutput=ps.stdout.read(), target_method=target_method)
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1
        return 0

if __name__ == '__main__':
    try:
        if(os.path.isfile(config.default_ca_cert_location) is not True):
            print('[!] You\'ve forgotten about creating the radius.pem file in: {}'.format(config.default_ca_cert_location))
            exit(1)
        w = wpaSupplicantWrapper(
            target_ssid=options['ssid']
        )
        print('[+]  Connecting to target "{}" network'.format(options['ssid']))
        options['hidden'] = 1 if options['hidden'] else 0
        for method in config.supported_eap_methods:
            if(method == 'peap'):
                conf_manager.wpa_supplicant_conf_peap.configure(
                    verbose=options['verbose'],
                    ssid=options['ssid'],
                    scan_ssid=options['hidden'],
                    identity=options['identity'],
                    password=options['password'],
                    phase1=options['phase1'],
                    phase2=options['phase2']
                )
            if(method == 'md5'):
                conf_manager.wpa_supplicant_conf_md5.configure(
                    verbose=options['verbose'],
                    ssid=options['ssid'],
                    scan_ssid=options['hidden'],
                    identity=options['identity'],
                    password=options['password']
                )
            if(method == 'ttls'):
                conf_manager.wpa_supplicant_conf_ttls.configure(
                    verbose=options['verbose'],
                    ssid=options['ssid'],
                    scan_ssid=options['hidden'],
                    identity=options['identity'],
                    password=options['password'],
                    phase2=options['phase2']
                    )
            if(method == 'tls'):
                conf_manager.wpa_supplicant_conf_tls.configure(
                    verbose=options['verbose'],
                    ssid=options['ssid'],
                    scan_ssid=options['hidden'],
                    identity=options['identity'],
                    client_cert=options['client_cert'],
                    private_key=options['private_key'],
                    private_passwd=options['private_passwd']
                    )
            w.wpaSupplicantCtrl(target_method=method)
        w.wpaSupplicantReporter()
        print('[-] Finished!')
    except Exception as e:
        print('Error: {}'.format(e))
        exit(1)
