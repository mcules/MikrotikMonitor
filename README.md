# MikrotikMonitor
This Go module creates an SNMP (Simple Network Management Protocol) monitor for MikroTik devices. It utilizes the SNMP protocol to retrieve information from the devices and collects this information in a structured form.

Here are some of the key functionalities and methods of this module
- GetProtocol: This method returns the SNMPv3 authentication protocol based on the value of the Protocol field in the Authentication struct.
- GetConfig: This method reads a configuration file and populates the Devices slice with Device objects.
- GetDevice: This method sends SNMP requests to collect device information such as the version number, model, and name.
- ResultJson: This method converts the Devices data structure to JSON and returns it as a string. Passwords and the protocols used for authentication are not part of the output.

```
package main

import "github.com/mcules/MikrotikMonitor"

func main() {
    var devices MikrotikMonitor.Devices
    devices.GetConfig("config.yaml")
    for i, _ := range devices {
        _ = devices[i].GetDevice()
    }
    jsonData := devices.ResultJson()
    println(jsonData)
}
```

This is a simple code snippet that demonstrates how to use this package. It reads the configuration information from the config.yaml file, retrieves device information, and prints it as a JSON string. This code is sufficient to fetch the current device information. You can use the JSON string to display device information on a console, write it to a file, render it in a web service, or for other types of processing and analysis.

## Config Example
You need a config file with your devices as an yaml array like the example.

Filename: `devices.yml`
```
devices:
    - host: myhost.xxxxxxxx.xyz
      snmp:
        version: "3"
        community: public
        authentication:
          active: true
          protocol: SHA1
          passphrase: MyVerySecurePassphrase
        privacy:
          active: true
          protocol: DES
          passphrase: MyVerySecurePassphrase

    - host: myhost2.xxxxxxxx.xyz
      snmp:
        version: "2"
        community: public
```
