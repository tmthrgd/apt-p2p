package main

type configStruct struct {
	_ struct{} // to prevent unkeyed literals

	Verbose bool
	Quiet   bool

	Archives     []string
	ArchiveFiles []string

	Trusted map[string]struct {
		_ struct{} // to prevent unkeyed literals

		SPKI string
	}

	Storage struct {
		_ struct{} // to prevent unkeyed literals

		Address string

		CertFile string
		KeyFile  string
	}

	Proxy struct {
		_ struct{} // to prevent unkeyed literals

		Address string

		CertFile string
		KeyFile  string
	}
}

const (
	configDir = "/etc/apt-p2p"

	configPeerCertPath = configDir + "/peer-cert.pem"
	configPeerKeyPath  = configDir + "/peer-key.pem"

	configProxyCertPath = configDir + "/proxy-cert.pem"
	configProxyKeyPath  = configDir + "/proxy-key.pem"
)

var configPath = configDir + "/apt-p2p.conf"

var config configStruct
