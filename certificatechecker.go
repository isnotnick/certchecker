//
// My First SSL Checker in Go
// Nick France - nick@nickf.net
// 
// Reads in a text file containing a list of IPs and/or domains and attempts an SSL/TLS connection to each.
// Port is assumed as 443 unless added to the list in format - 'domain-or-IP:port'
// 



package certificatechecker

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/dsa"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"
	"regexp"
	"net"
	"time"
	"encoding/pem"
	_"strconv"
	"github.com/bogdanovich/dns_resolver"
)

//	Global regular expressions
var reg *regexp.Regexp
var serverReg *regexp.Regexp


func init() {
	// Compile regular expressions for IP-address check and HTTP-Header server-token parsing
	reg = regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")
	serverReg = regexp.MustCompile("(?:Server: )(.*)\\r\\n")
}


//	Certificate structure
type CertResult struct {
	ScanTime int
	ScanDuration int
	Description string

	ScanInput string
	RawAddress string
	PortNumber string
	IPAddress string
	HostName string

	PEMCertificate string
	PEMChain string

	NotBefore int
	NotAfter int
	KeySize int
	KeyType string
	HashType string
	OCSPStaple string

	CertIssuerCN string

	CertSubjectCN string
	CertCountry string

	CertSubject string

	// *
	IssuerOrg string
	Thumbprint string
	SerialNumber string

	CertIssuer string
	CertSANS string
	CertOrg string
	PolicyOIDS string
	ServerType string

	// *
	ValidationType string
	Validity string
	NameMismatch string

	InternalName string
	RevocationStatus string

	// *
	KU string
	EKU string
	AIAUrl string
	OCSPUrl string
	CRLUrl string

	ScanTimings string

	ErrorMessage string
}


func CheckCertificate(address string) CertResult {
	// EV policy OIDs
	evIssuers := make(map[string]string)
	evIssuers["1.3.159.1.17.1"] = "Actalis"
	evIssuers["1.3.6.1.4.1.17326.10.14.2.1.2"] = "AC Camerfirma S.A. Chambers of Commerce Root"
	evIssuers["1.3.6.1.4.1.17326.10.14.2.2.2"] = "AC Camerfirma S.A. Chambers of Commerce Root"
	evIssuers["1.3.6.1.4.1.17326.10.8.12.1.2"] = "AC Camerfirma S.A. Chambers of Commerce Root"
	evIssuers["1.3.6.1.4.1.17326.10.8.12.2.2"] = "AC Camerfirma S.A. Chambers of Commerce Root"
	evIssuers["1.2.40.0.17.1.22"] = "A-Trust"
	evIssuers["1.3.6.1.4.1.34697.2.1"] = "AffirmTrust Commercial"
	evIssuers["1.3.6.1.4.1.34697.2.2"] = "AffirmTrust Networking"
	evIssuers["1.3.6.1.4.1.34697.2.3"] = "AffirmTrust Premium"
	evIssuers["1.3.6.1.4.1.34697.2.4"] = "AffirmTrust Premium ECC"
	evIssuers["2.16.578.1.26.1.3.3"] = "Buypass"
	evIssuers["1.3.6.1.4.1.22234.2.5.2.3.1"] = "CertPlus Class 2 Primary CA (KEYNECTIS)"
	evIssuers["1.2.616.1.113527.2.5.1.1"] = "Certum Trusted Network CA"
	evIssuers["1.3.6.1.4.1.6449.1.2.1.5.1"] = "COMODO Certification Authority"
	evIssuers["1.3.6.1.4.1.6334.1.100.1"] = "Cybertrust Global Root"
	evIssuers["2.16.840.1.114412.2.1"] = "DigiCert High Assurance EV Root CA"
	evIssuers["2.16.840.1.114412.1.3.0.2"] = "DigiCert High Assurance EV Root CA"
	evIssuers["1.3.6.1.4.1.4788.2.202.1"] = "D-TRUST Root Class 3 CA 2 EV 2009"
	evIssuers["2.16.840.1.114028.10.1.2"] = "Entrust.net Secure Server Certification Authority"
	evIssuers["2.16.792.3.0.4.1.1.4"] = "E-Tugra"
	evIssuers["1.3.6.1.4.1.14370.1.6"] = "Equifax Secure Certificate Authority (GeoTrust)"
	evIssuers["1.3.6.1.4.1.4146.1.1"] = "GlobalSign Root CA"
	evIssuers["2.16.840.1.114413.1.7.23.3"] = "GoDaddy Class 2 Certification Authority"
	evIssuers["1.3.6.1.4.1.14777.6.1.1"] = "Izenpe.com"
	evIssuers["1.3.6.1.4.1.14777.6.1.2"] = "Izenpe.com"
	evIssuers["1.3.6.1.4.1.782.1.2.1.8.1"] = "Network Solutions Certificate Authority"
	evIssuers["1.3.6.1.4.1.8024.0.2.100.1.2"] = "QuoVadis Root CA"
	evIssuers["2.16.840.1.114404.1.1.2.4.1"] = "SecureTrust Root - Trustwave"
	evIssuers["1.2.392.200091.100.721.1"] = "SECOMTRUST Root"
	evIssuers["1.3.6.1.4.1.23223.1.1.1"] = "StartCom Certification Authority"
	evIssuers["2.16.840.1.114414.1.7.23.3"] = "Starfield Certification Authority"
	evIssuers["2.16.756.1.89.1.2.1.1"] = "SwissSign CA"
	evIssuers["2.16.840.1.113733.1.7.48.1"] = "Thawte CA"
	evIssuers["1.3.6.1.4.1.40869.1.1.22.3"] = "TWCA Root Certification Authority"
	evIssuers["1.3.6.1.4.1.7879.13.24.1"] = "T-Telesec GlobalRoot"
	evIssuers["2.16.840.1.113733.1.7.23.6"] = "VeriSign / Symantec"
	evIssuers["2.16.840.1.114171.500.9"] = "Wells Fargo WellsSecure Public Root CA"



	//	Some variables and input-cleaning to begin with, and of course the start time marker
	startTime := int(time.Now().Unix())
	accurateStartTime := time.Now()
	var domainName, port, finalConnection string
	var thisCertificate CertResult
	thisCertificate.ScanTime = startTime
	address = strings.TrimSpace(address)
	thisCertificate.ScanInput = address

	//	address = 'raw' address from the input file
	//	we need to determine if it's an FQDN, IPv4 address, IPv6 address or any combination thereof with a ':port' appended...
	var hostPort = strings.Split(address, ":")
	//	Length of result is 1: No colons, hence no specified port. Assume 443.
	//	2: 1 colon, assume IPv4 or FQDN with specified hostname.
	//	>2: So many colons! Let's assume an IPv6 address. [Need to work out later about host to determine port - presumably > 7 colons = port specified?]
	if len(hostPort) == 1 {
		domainName = hostPort[0]
		port = "443"
	} else if len(hostPort) == 2 {
		domainName = hostPort[0]
		port = hostPort[1]
	} else {
		domainName = address
		port = "443"
	}
	
	//	Determine if the 'HostName' part is an IP address or not - if it's a domain, attempt a DNS lookup
	//	If we do DNS here (via a couple of packages including the amazing miekg's DNS) - then we hopefully avoid the cgo/host lookup threading problems
	//	Determination is done with a regexp. Yes, yes. I know.
	if reg.FindString(domainName) == "" {
		resolver := dns_resolver.New([]string{"8.8.8.8"})
		resolver.RetryTimes = 3
		ipAdd, err := resolver.LookupHost(domainName)
		//ipAdd, err := net.LookupIP(domainName)
		//ip, err := net.LookupHost(domainName)
		if err != nil {
			thisCertificate.ErrorMessage = "Failed DNS lookup"
			return thisCertificate
		}
		if len(ipAdd) >= 1 {
			resolvedIP := ipAdd[0].String()
			finalConnection = resolvedIP + ":" + port
			thisCertificate.IPAddress = resolvedIP
		} else {
			thisCertificate.ErrorMessage = "Failed DNS lookup"
			return thisCertificate
		}
	} else {
		finalConnection = domainName + ":" + port
		thisCertificate.IPAddress = domainName
	}

	thisCertificate.RawAddress = address
	thisCertificate.PortNumber = port
	thisCertificate.HostName = domainName

	dnsLookupTime := time.Now()
	
	//	Make connection to the IP:port combination with set timeout - retry, too
	ipConn, err := net.DialTimeout("tcp", finalConnection, 3 * time.Second)
	if err != nil {
		for connCount := 0; connCount < 2; connCount++ {
			ipConn, err = net.DialTimeout("tcp", finalConnection, 3 * time.Second)
			if err != nil {
				thisCertificate.ErrorMessage = "Failed TCP connection / Connection refused"
				return thisCertificate
			}
		}
	}
	err = ipConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		fmt.Println("Failed to set deadline", err)
		thisCertificate.ErrorMessage = "Failed TCP connection / Connection refused"
		return thisCertificate
	}

	defer ipConn.Close()

	ipConnTime := time.Now()

	// Disable normal certificate validation checking, attempt TLS connection to host - also use 'servername' to support SNI
	tlsConfig := tls.Config{ServerName: domainName, InsecureSkipVerify: true}
	conn := tls.Client(ipConn, &tlsConfig)
	hsErr := conn.Handshake()
	if hsErr != nil {
		thisCertificate.ErrorMessage = "Failed SSL/TLS handshake"
		conn.Close()
		return thisCertificate
	}

	tlsHandshakeTime := time.Now()

	// Try and determine the HTTPS server 'server token' - ie what kind of software it is. Should use http.get and the headers, but still...
	getString := fmt.Sprintf("GET / HTTP/1.1\r\nHost:%v\r\n\r\n", domainName)
	_, err = conn.Write([]byte(getString))
	if err != nil {
		thisCertificate.ServerType = ""
	} else {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			thisCertificate.ServerType = ""
		} else {
			findServerToken := serverReg.FindStringSubmatch(string(buf))
			if findServerToken != nil {
				thisCertificate.ServerType = serverReg.FindStringSubmatch(string(buf))[1]
			} else {
				thisCertificate.ServerType = ""
			}
		}
	}

	httpHeaderTime := time.Now()
	
	//	Log the OCSP response (in base64) if we are given one
	if len(conn.OCSPResponse()) != 0 {
		thisCertificate.OCSPStaple = base64.StdEncoding.EncodeToString(conn.OCSPResponse())
	}
	defer conn.Close()
	
	//	Loop each certificate in the PeerCertificates (from the server) and analyse each - grab subject info, SANs, key & KeySize, PEM version
	checkedCert := make(map[string]bool)
	i := 0
	certChain := ""
	for _, cert := range conn.ConnectionState().PeerCertificates {
		// Ensure that each unique certificate is checked only once per host.
		if _, checked := checkedCert[string(cert.Signature)]; checked {
			continue
		}
		checkedCert[string(cert.Signature)] = true
		
		if i == 0 {
			//	Put the whole subject (well, what is already formatted into a pkix.Name) into one string
			thisCertificate.CertSubject = fmt.Sprintf("%+v", cert.Subject.Names)
			thisCertificate.CertIssuer = fmt.Sprintf("%+v", cert.Issuer.Names)

			//	Other informational bits
			thisCertificate.CertSubjectCN = cert.Subject.CommonName
			thisCertificate.CertIssuerCN = cert.Issuer.CommonName
			thisCertificate.CertCountry = strings.Join(cert.Subject.Country, "")
			thisCertificate.CertSANS = strings.Join(cert.DNSNames, ",")
			thisCertificate.NotBefore = int(cert.NotBefore.Unix())
			thisCertificate.NotAfter = int(cert.NotAfter.Unix())
			thisCertificate.CertOrg = strings.Join(cert.Subject.Organization, "")

			//fmt.Printf("subject: %+v\n", cert.Subject)

			// Policy OIDs for EV checking
			PolicyOIDSString := fmt.Sprintf("%d", cert.PolicyIdentifiers)
			PolicyOIDS := strings.Replace(PolicyOIDSString, "[[", "", -1)
			PolicyOIDS = strings.Replace(PolicyOIDS, "]]", "", -1)
			PolicyOIDS = strings.Replace(PolicyOIDS, " ", ".", -1)
			thisCertificate.PolicyOIDS = strings.TrimSpace(PolicyOIDS)
			
			switch cert.PublicKeyAlgorithm {
				case 0:
					thisCertificate.KeyType = "Unknown"
					thisCertificate.KeySize = 0
				case 1:
					thisCertificate.KeyType = "RSA"
					rsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
					if err == nil {
						rsaPub := rsaKey.(*rsa.PublicKey)
						KeySize := rsaPub.N
						thisCertificate.KeySize = KeySize.BitLen()
					}
				case 2:
					thisCertificate.KeyType = "DSA"
					dsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
					if err == nil {
						dsaPub := dsaKey.(*dsa.PublicKey)
						KeySize := dsaPub.Y
						thisCertificate.KeySize = KeySize.BitLen()
					}
				case 3:
					thisCertificate.KeyType = "ECDSA"
					ecdsaKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
					if err == nil {
						ecdsaPub := ecdsaKey.(*ecdsa.PublicKey)
						KeySize := ecdsaPub.X
						thisCertificate.KeySize = KeySize.BitLen()
					}
				default:
					thisCertificate.KeyType = "Unknown"
					thisCertificate.KeySize = 0
			}

			switch cert.SignatureAlgorithm {
				case 0:
					thisCertificate.HashType = "UnknownSignatureAlgorithm"
				case 1:
					thisCertificate.HashType = "MD2WithRSA"
				case 2:
					thisCertificate.HashType = "MD5WithRSA"
				case 3:
					thisCertificate.HashType = "SHA1WithRSA"
				case 4:
					thisCertificate.HashType = "SHA256WithRSA"
				case 5:
					thisCertificate.HashType = "SHA384WithRSA"
				case 6:
					thisCertificate.HashType = "SHA512WithRSA"
				case 7:
					thisCertificate.HashType = "DSAWithSHA1"
				case 8:
					thisCertificate.HashType = "DSAWithSHA256"
				case 9:
					thisCertificate.HashType = "ECDSAWithSHA1"
				case 10:
					thisCertificate.HashType = "ECDSAWithSHA256"
				case 11:
					thisCertificate.HashType = "ECDSAWithSHA384"
				case 12:
					thisCertificate.HashType = "ECDSAWithSHA512"
			}
			
			thisCertificate.PEMCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		} else {
			certChain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
		
		i++
	}
	
	//	Add the chain of all certs provided by the server
	thisCertificate.PEMChain = certChain

	// Cert validation type - SS DV OV EV
	if (thisCertificate.CertSubjectCN == thisCertificate.CertIssuerCN) {
		thisCertificate.ValidationType = "SS"
	} else if (thisCertificate.CertOrg == "") {
		thisCertificate.ValidationType = "DV"
	} else {
		_, evOID := evIssuers[thisCertificate.PolicyOIDS]
		if (evOID) {
			thisCertificate.ValidationType = "EV"
		} else {
			thisCertificate.ValidationType = "OV"
		}
	}

	// Naming mis-match - WILDCARDS!
	if (thisCertificate.HostName == thisCertificate.CertSubjectCN) {
		thisCertificate.NameMismatch = "N"
	} else if (strings.Contains(thisCertificate.CertSANS, thisCertificate.HostName) == true) {
		thisCertificate.NameMismatch = "N"
	} else {
		thisCertificate.NameMismatch = "Y"
	}

	// Dates
	if (thisCertificate.NotAfter < int(time.Now().Unix())) {
		thisCertificate.Validity = "Expired"
	} else if (thisCertificate.NotBefore > int(time.Now().Unix())) {
		thisCertificate.Validity = "Not yet valid"
	} else {
		thisCertificate.Validity = "Valid"
	}

	scanTime := time.Now()
	accurateScanDuration := int(scanTime.Sub(accurateStartTime) / time.Millisecond)
	thisCertificate.ScanDuration = accurateScanDuration

	timeForDNSLookup := int(dnsLookupTime.Sub(accurateStartTime) / time.Millisecond)
	timeForIPConnection := int(ipConnTime.Sub(dnsLookupTime) / time.Millisecond)
	timeForTLSHandshake := int(tlsHandshakeTime.Sub(ipConnTime) / time.Millisecond)
	timeForHTTPHeader := int(httpHeaderTime.Sub(tlsHandshakeTime) / time.Millisecond)

	scanTimings := fmt.Sprintf("Timings - DNS Lookup: %d, IP Connection: %d, TLS Handshake: %d, HTTP Header: %d, Scan processing: %d \n", timeForDNSLookup, timeForIPConnection, timeForTLSHandshake, timeForHTTPHeader, accurateScanDuration)
	thisCertificate.ScanTimings = scanTimings
	
	return thisCertificate
}