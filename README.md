# eaptyper
Eaptyper is an automated auditing tool designed to actively fingerprint which all EAP methods (not just the preferred method) that are supported by the target WPA2-Enterprise wireless infrastructure. By enumerating all methods supported, it is possible to detect potential misconfigurations in the server infrastructure which could mean the client stations can connect to the infrastructure using insecure settings. 

## Example
### Usage
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/eaptyper]
└─$ sudo python3 eaptyper.py -s rogue -i wlan0
[+]  Connecting to target "rogue" network
[-]  Target network "rogue" proposed EAP method: md5
[-]  Following methods are supported by target network:
[-]    md5
[-]    peap
[-]    ttls
[-]  Following methods were rejected by target network:
[-]    tls
[-]  Following methods are not supported by wpa_supplicant client:

```

## Dependencies
1. `wpa_supplicant`
