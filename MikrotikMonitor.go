package MikrotikMonitor

import (
	"encoding/json"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
	"time"
)

type Authentication struct {
	Active     bool
	Protocol   string `json:"-"`
	Passphrase string `json:"-"`
}

type Privacy struct {
	Active     bool
	Protocol   string `json:"-"`
	Passphrase string `json:"-"`
}

type SNMP struct {
	Version        string
	Community      string `json:"-"`
	Authentication Authentication
	Privacy        Privacy
}

type Version struct {
	RouterOS   string
	Bootloader string
	Latest     string
}

type Device struct {
	Reached bool
	Host    string
	Model   string
	Name    string
	SNMP    SNMP
	Version Version
}

type Devices []Device

// GetProtocol returns the SNMPv3 authentication protocol based on the value of the Protocol field in the Authentication struct.
// If Protocol is known, it returns gosnmp constant
// Otherwise, it returns gosnmp.SHA.
func (auth *Authentication) GetProtocol() gosnmp.SnmpV3AuthProtocol {
	switch auth.Protocol {
	case "SHA1":
		return gosnmp.SHA
	case "MD5":
		return gosnmp.MD5
	default:
		return gosnmp.SHA
	}
}

// GetProtocol returns the SNMPv3 privacy protocol based on the value of the Protocol field in the Privacy struct.
// If Protocol is known, it returns gosnmp constant
// Otherwise, it returns gosnmp.DES.
func (priv *Privacy) GetProtocol() gosnmp.SnmpV3PrivProtocol {
	switch priv.Protocol {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	default:
		return gosnmp.DES
	}
}

// GetConfig reads a configuration file and populates the Devices slice with Device objects.
// It takes a filename string as the input parameter and does not return any value.
// It uses the yaml.Unmarshal function to parse the content of the file and assigns the parsed Devices to the receiver devices.
func (devices *Devices) GetConfig(filename string) {
	var parser struct {
		Devices []Device `yaml:"devices"`
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read config file, %v", err)
	}

	err = yaml.Unmarshal(content, &parser)
	if err != nil {
		log.Fatalf("unable to parse config file, %v", err)
	}

	*devices = parser.Devices
}

// GetDevice sends SNMP requests to retrieve device information such as version, model, and name.
// It configures the SNMP connection with the device's host and SNMP settings.
// It retrieves the device information using a list of OIDs and updates the Device struct accordingly.
// If any SNMP errors occur during the retrieval process, an error is returned.
func (device *Device) GetDevice() error {
	device.SNMPConfigure()
	oids := []string{".1.3.6.1.4.1.14988.1.1.4.4.0", ".1.3.6.1.4.1.14988.1.1.7.4.0", ".1.3.6.1.4.1.14988.1.1.7.7.0", ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0"}

	err := gosnmp.Default.Connect()
	if err != nil {
		return fmt.Errorf("fehler beim Verbinden: %v", err)
	}
	defer func() {
		if err := gosnmp.Default.Conn.Close(); err != nil {
			log.Printf("Error closing connection: %v\n", err)
		}
	}()

	result, err2 := gosnmp.Default.Get(oids)
	if err2 != nil {
		return fmt.Errorf("%s Fehler bei der SNMP-Anfrage: %v", device.Host, err2)
	}

	device.Reached = true

	if len(result.Variables) > 0 {
		for _, variable := range result.Variables {
			switch variable.Name {
			case ".1.3.6.1.4.1.14988.1.1.4.4.0":
				device.Version.RouterOS = string(variable.Value.([]byte))
			case ".1.3.6.1.4.1.14988.1.1.7.7.0":
				device.Version.Latest = string(variable.Value.([]byte))
			case ".1.3.6.1.4.1.14988.1.1.7.4.0":
				device.Version.Bootloader = string(variable.Value.([]byte))
			case ".1.3.6.1.2.1.1.1.0":
				device.Model = strings.Replace(string(variable.Value.([]byte)), "RouterOS", "", 1)
			case ".1.3.6.1.2.1.1.5.0":
				device.Name = string(variable.Value.([]byte))
			default:
				fmt.Println(variable.Name, ":", string(variable.Value.([]byte)))
			}
		}
	}

	return nil
}

// ResultJson marshals the Devices struct to JSON and returns it as a string.
// If there is an error during marshaling, the error will be logged and an empty string will be returned.
func (devices *Devices) ResultJson() string {
	d, err := json.Marshal(devices)
	if err != nil {
		log.Println(err.Error())
	}

	return string(d)
}

// SNMPConfigure configures the gosnmp.Default object for SNMP communication with the device.
func (device *Device) SNMPConfigure() {
	gosnmp.Default.Timeout = 3 * time.Second // Timeout für SNMP-Anfragen
	gosnmp.Default.Target = device.Host
	gosnmp.Default.Community = device.SNMP.Community

	switch device.SNMP.Version {
	case "2c":
		gosnmp.Default.Version = gosnmp.Version2c
	case "3":
		gosnmp.Default.Version = gosnmp.Version3
		gosnmp.Default.SecurityModel = gosnmp.UserSecurityModel
		gosnmp.Default.MsgFlags = gosnmp.AuthPriv
	}

	if device.SNMP.Authentication.Active || device.SNMP.Privacy.Active {
		usmSecurityParameters := gosnmp.UsmSecurityParameters{
			UserName: device.SNMP.Community,
		}

		if device.SNMP.Authentication.Active {
			usmSecurityParameters.AuthenticationProtocol = device.SNMP.Authentication.GetProtocol()
			usmSecurityParameters.AuthenticationPassphrase = device.SNMP.Authentication.Passphrase
		}

		if device.SNMP.Privacy.Active {
			usmSecurityParameters.PrivacyProtocol = device.SNMP.Privacy.GetProtocol()
			usmSecurityParameters.PrivacyPassphrase = device.SNMP.Privacy.Passphrase
		}

		gosnmp.Default.SecurityParameters = &usmSecurityParameters
	}
}
