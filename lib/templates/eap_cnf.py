#!/usr/bin/python3
# https://manpages.debian.org/experimental/wpasupplicant/wpa_supplicant.conf.5.en.html

wpa_supplicant_conf_peap_template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
  ssid="{}"
  scan_ssid={}
  key_mgmt=WPA-EAP
  eap=PEAP
  identity="{}"
  password="{}"
  phase1="peapver={}"
  phase2="auth={}"
}}
'''


wpa_supplicant_conf_md5_template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
  ssid="{}"
  scan_ssid={}
  key_mgmt=WPA-EAP
  eap=MD5
  identity="{}"
  password="{}"
}}
'''

wpa_supplicant_conf_tls_template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
  ssid="{}"
  scan_ssid={}
  key_mgmt=WPA-EAP
  eap=TLS
  identity="{}"
  client_cert="{}"
  private_key="{}"
  private_key_passwd="{}"
}}
'''

wpa_supplicant_conf_ttls_template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
  ssid="{}"
  scan_ssid={}
  key_mgmt=WPA-EAP
  eap=TTLS
  identity="{}"
  password="{}"
  phase2="auth={}"
}}
'''
