#!/usr/bin/python3
import settings as config
from lib.templates import eap_cnf

class wpa_supplicant_conf_peap(object):
    path = config.wpa_supplicant_conf_file_location
    template = eap_cnf.wpa_supplicant_conf_peap_template

    @classmethod
    def configure(cls, verbose, ssid, scan_ssid, identity, password, phase1, phase2):
        try:
            if(verbose):
                print('[+] Creating wpa_supplicant.conf file: {}'.format(cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        scan_ssid,
                        identity,
                        password,
                        phase1,
                        phase2
                    )
                )
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1

class wpa_supplicant_conf_md5(object):
    path = config.wpa_supplicant_conf_file_location
    template = eap_cnf.wpa_supplicant_conf_md5_template

    @classmethod
    def configure(cls, verbose, ssid, scan_ssid, identity, password):
        try:
            if(verbose):
                print('[+] Creating wpa_supplicant.conf file: {}'.format(cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        scan_ssid,
                        identity,
                        password
                    )
                )
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1

class wpa_supplicant_conf_tls(object):
    path = config.wpa_supplicant_conf_file_location
    template = eap_cnf.wpa_supplicant_conf_tls_template

    @classmethod
    def configure(cls, verbose, ssid, scan_ssid, identity, client_cert, private_key, private_passwd):
        try:
            if(verbose):
                print('[+] Creating wpa_supplicant.conf file: {}'.format(cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        scan_ssid,
                        identity,
                        client_cert,
                        private_key,
                        private_passwd
                    )
                )
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1

class wpa_supplicant_conf_ttls(object):
    path = config.wpa_supplicant_conf_file_location
    template = eap_cnf.wpa_supplicant_conf_ttls_template

    @classmethod
    def configure(cls, verbose, ssid, scan_ssid, identity, password, phase2):
        try:
            if(verbose):
                print('[+] Creating wpa_supplicant.conf file: {}'.format(cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        scan_ssid,
                        identity,
                        password,
                        phase2
                    )
                )
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1
