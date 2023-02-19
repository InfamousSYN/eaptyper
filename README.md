# eaptyper
Eaptyper is an automated auditing tool designed to actively fingerprint which all EAP methods (not just the preferred method) that are supported by the target WPA2-Enterprise wireless infrastructure. By enumerating all methods supported, it is possible to detect potential misconfigurations in the server infrastructure which could mean the client stations can connect to the infrastructure using insecure settings. 

## Usage

### Live fingerprinting mode

```Bash
sudo python3 eaptyper.py -m 0 -i wlan1 -s rogue
```

## Dependenciess
1. TBC
