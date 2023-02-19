#!/usr/bin/python3
# python modules
import os

__version__ = "2.0.0-dev"

# Directory Mapping
root_dir, conf_file = os.path.split(os.path.abspath(__file__))
working_dir = root_dir + '/tmp'

# File Mapping
wpa_supplicant_conf_file_location = working_dir + '/wpa_supplicant.conf'
wpa_supplicant_logfile_location = working_dir
default_ca_cert_location = working_dir + '/radius.pem'
argparser_default_client_cert_location = working_dir + '/client.pem'
argparser_default_client_private_key_location = working_dir + '/private.key'

# Default Argument Options
argparser_eap_username = 'infamoussyn'
argparser_eap_password = 'infamoussyn'
argparser_pairwise_encryption = 'CCMP TKIP'
argparser_group_encryption = 'CCMP TKIP'
argparser_default_client_private_password = 'infamoussyn'
argpaser_timeout = 15

#
supported_eap_methods = [
    'md5',
    'peap',
    'tls',
    'ttls'
]

# Do not modify
wpa_supplicant_lock = '/var/run/wpa_supplicant'
