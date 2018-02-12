
package certificatechecker

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
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

//	Trust stores
var mozStore *x509.CertPool
var msStore *x509.CertPool
var appleStore *x509.CertPool
//	Trust store files
var mozFile string = "Mozilla-16-Jan-18.pem"
var msFile string = "MS-16-Jan-18.pem"
var appleFile string = "Apple-16-Jan-18.pem"

//	Symantec deprecation - public key hashes (SHA-256)
var symantecBadKeys = map[string]bool {
	"023c81cce8e7c64fa942d3c15048707d35d9bb5b87f4f544c5bf1bc5643af2fa": true,
	"0999bf900bd5c297865e21e1aade6cf6bb3a94d11ae5ea798442a4e2f813241f": true,
	"0bdd5abe940caaabe8b2bba88348fb6f4aa4cc84436f880bece66b48bda913d8": true,
	"16a9e012d32329f282b10bbf57c7c0b42ae80f6ac9542eb409bc1c2cde50d322": true,
	"17755a5c295f3d2d72e6f031a1f07f400c588b9e582b22f17eae31a1590d1185": true,
	"1906c6124dbb438578d00e066d5054c6c37f0fa6028c05545e0994eddaec8629": true,
	"1916f3508ec3fad795f8dc4bd316f9c6085a64de3c4153ac6d62d5ea19515d39": true,
	"1d75d0831b9e0885394d32c7a1bfdb3dbc1c28e2b0e8391fb135981dbc5ba936": true,
	"22076e5aef44bb9a416a28b7d1c44322d7059f60feffa5caf6c5be8447891303": true,
	"25b41b506e4930952823a6eb9f1d31def645ea38a5c6c6a96d71957e384df058": true,
	"26c18dc6eea6f632f676bceba1d8c2b48352f29c2d5fcda878e09dcb832dd6e5": true,
	"2dc9470be63ef4acf1bd828609402bb7b87bd99638a643934e88682d1be8c308": true,
	"2dee5171596ab8f3cd3c7635fea8e6c3006aa9e31db39d03a7480ddb2428a33e": true,
	"3027a298fa57314dc0e3dd1019411b8f404c43c3f934ce3bdf856512c80aa15c": true,
	"31512680233f5f2a1f29437f56d4988cf0afc41cc6c5da6275928e9c0beade27": true,
	"43b3107d7342165d406cf975cd79b36ed1645048f05d7ff6ea0096e427b7db84": true,
	"463dbb9b0a26ed2616397b643125fbd29b66cf3a46fdb4384b209e78237a1aff": true,
	"479d130bf3fc61dc2f1d508d239a13276ae7b3c9841011a02c1402c7e677bd5f": true,
	"4905466623ab4178be92ac5cbd6584f7a1e17f27652d5a85af89504ea239aaaa": true,
	"495a96ba6bad782407bd521a00bace657bb355555e4bb7f8146c71bba57e7ace": true,
	"4ba6031ca305b09e53bde3705145481d0332b651fe30370dd5254cc4d2cb32f3": true,
	"5192438ec369d7ee0ce71f5c6db75f941efbf72e58441715e99eab04c2c8acee": true,
	"567b8211fd20d3d283ee0cd7ce0672cb9d99bc5b487a58c9d54ec67f77d4a8f5": true,
	"5c4f285388f38336269a55c7c12c0b3ca73fef2a5a4df82b89141e841a6c4de4": true,
	"67dc4f32fa10e7d01a79a073aa0c9e0212ec2ffc3d779e0aa7f9c0f0e1c2c893": true,
	"6b86de96a658a56820a4f35d90db6c3efdd574ce94b909cb0d7ff17c3c189d83": true,
	"7006a38311e58fb193484233218210c66125a0e4a826aed539ac561dfbfbd903": true,
	"781f1c3a6a42e3e915222db4967702a2e577aeb017075fa3c159851fddd0535e": true,
	"7caa03465124590c601e567e52148e952c0cffe89000530fe0d95b6d50eaae41": true,
	"809f2baae35afb4f36bd6476ce75c2001077901b6af5c4dab82e188c6b95c1a1": true,
	"81a98fc788c35f557645a95224e50cd1dac8ffb209dc1e5688aa29205f132218": true,
	"860a7f19210d5ead057a78532b80951453cb2907315f3ba7aa47b69897d70f3f": true,
	"87af34d66fb3f2fdf36e09111e9aba2f6f44b207f3863f3d0b54b25023909aa5": true,
	"95735473bd67a3b95a8d5f90c5a21ace1e0d7947320674d4ab847972b91544d2": true,
	"967b0cd93fcef7f27ce2c245767ae9b05a776b0649f9965b6290968469686872": true,
	"9699225c5de52e56cdd32df2e96d1cfea5aa3ca0bb52cd8933c23b5c27443820": true,
	"9c6f6a123cbaa4ee34dbeceee24c97d738878cb423f3c2273903424f5d1f6dd5": true,
	"a6f1f9bf8a0a9ddc080fb49b1efc3d1a1c2c32dc0e136a5b00c97316f2a3dc11": true,
	"ab3876c3da5de0c9cf6736868ee5b88bf9ba1dff9c9d72d2fe5a8d2f78302166": true,
	"ab39a4b025955691a40269f353fa1d5cb94eaf6c7ea9808484bbbb62fd9f68f3": true,
	"ab5cdb3356397356d6e691973c25b8618b65d76a90486ea7a8a5c17767f4673a": true,
	"ab98495276adf1ecaff28f35c53048781e5c1718dab9c8e67a504f4f6a51328f": true,
	"acf65e1d62cb58a2bafd6ffab40fb88699c47397cf5cb483d42d69cad34cd48b": true,
	"af207c61fd9c7cf92c2afe8154282dc3f2cbf32f75cd172814c52b03b7ebc258": true,
	"b1124142a5a1a5a28819c735340eff8c9e2f8168fee3ba187f253bc1a392d7e2": true,
	"b2def5362ad3facd04bd29047a43844f767034ea4892f80e56bee690243e2502": true,
	"bcfb44aab9ad021015706b4121ea761c81c9e88967590f6f94ae744dc88b78fb": true,
	"c07135f6b452398264a4776dbd0a6a307c60a36f967bd26321dcb817b5c0c481": true,
	"cab482cd3e820c5ce72aa3b6fdbe988bb8a4f0407ecafd8c926e36824eab92dd": true,
	"d2f91a04e3a61d4ead7848c8d43b5e1152d885727489bc65738b67c0a22785a7": true,
	"d3a25da80db7bab129a066ab41503dddffa02c768c0589f99fd71193e69916b6": true,
	"d4af6c0a482310bd7c54bb7ab121916f86c0c07cd52fcac32d3844c26005115f": true,
	"da800b80b2a87d399e66fa19d72fdf49983b47d8cf322c7c79503a0c7e28feaf": true,
	"f15f1d323ed9ca98e9ea95b33ec5dda47ea4c329f952c16f65ad419e64520476": true,
	"f2e9365ea121df5eebd8de2468fdc171dc0a9e46dadc1ab41d52790ba980a7c2": true,
	"f53c22059817dd96f400651639d2f857e21070a59abed9079400d9f695506900": true,
	"f6b59c8e2789a1fd5d5b253742feadc6925cb93edc345e53166e12c52ba2a601": true,
	"ff5680cd73a5703da04817a075fd462506a73506c4b81a1583ef549478d26476": true,
}
var symantecExceptions = map[string]bool {
	"56e98deac006a729afa2ed79f9e419df69f451242596d2aaf284c74a855e352e": true,
	"7289c06dedd16b71a7dcca66578572e2e109b11d70ad04c2601b6743bc66d07b": true,
	"8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26": true,
	"b5cf82d47ef9823f9aa78f123186c52e8879ea84b0f822c91d83e04279b78fd5": true,
	"b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97": true,
	"c0554bde87a075ec13a61f275983ae023957294b454caf0a9724e3b21b7935bc": true,
	"e24f8e8c2185da2f5e88d4579e817c47bf6eafbc8505f0f960fd5a0df4473ad3": true,
	"ec722969cb64200ab6638f68ac538e40abab5b19a6485661042a1061c4612776": true,
	"fae46000d8f7042558541e98acf351279589f83b6d3001c18442e4403d111849": true,
}
var symantecManagedExceptions = map[string]bool {
	"7cac9a0ff315387750ba8bafdb1c2bc29b3f0bba16362ca93a90f84da2df5f3e": true,
	"ac50b5fb738aed6cb781cc35fbfff7786f77109ada7c08867c04a573fd5cf9ee": true,
}



func init() {
	//	Compile regular expressions for IP-address check and HTTP-Header server-token parsing
	reg = regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")
	serverReg = regexp.MustCompile("(?:Server: )(.*)\\r\\n")

	//	Load the root stores from the PEM files
	mozCerts, _ := ioutil.ReadFile(mozFile)
	mozStore = x509.NewCertPool()
	mozStore.AppendCertsFromPEM(mozCerts)
	
	appleCerts, _ := ioutil.ReadFile(appleFile)
	appleStore = x509.NewCertPool()
	appleStore.AppendCertsFromPEM(appleCerts)
	
	msCerts, _ := ioutil.ReadFile(msFile)
	msStore = x509.NewCertPool()
	msStore.AppendCertsFromPEM(msCerts)
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
	SigAlg string
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

	MozTrust string
	MSTrust string
	AppleTrust string

	SymantecError string

	ErrorMessage string
}

func StoreSummaries() {
	fmt.Printf("Apple Root Store loaded from [%v] - number of certs : %v\n", appleFile, len(appleStore.Subjects()))
	fmt.Printf("Microsoft Root Store loaded from [%v] - number of certs : %v\n", msFile, len(msStore.Subjects()))
	fmt.Printf("Moz Root Store loaded from [%v] - number of certs : %v\n", mozFile, len(mozStore.Subjects()))
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

	// CertPool for the server-provided chain
	providedIntermediates := x509.NewCertPool()

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

	var trustTestCert *x509.Certificate
	var symantecFailure int = 0
	
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
					thisCertificate.SigAlg = "UnknownSignatureAlgorithm"
				case 1:
					thisCertificate.SigAlg = "MD2WithRSA"
				case 2:
					thisCertificate.SigAlg = "MD5WithRSA"
				case 3:
					thisCertificate.SigAlg = "SHA1WithRSA"
				case 4:
					thisCertificate.SigAlg = "SHA256WithRSA"
				case 5:
					thisCertificate.SigAlg = "SHA384WithRSA"
				case 6:
					thisCertificate.SigAlg = "SHA512WithRSA"
				case 7:
					thisCertificate.SigAlg = "DSAWithSHA1"
				case 8:
					thisCertificate.SigAlg = "DSAWithSHA256"
				case 9:
					thisCertificate.SigAlg = "ECDSAWithSHA1"
				case 10:
					thisCertificate.SigAlg = "ECDSAWithSHA256"
				case 11:
					thisCertificate.SigAlg = "ECDSAWithSHA384"
				case 12:
					thisCertificate.SigAlg = "ECDSAWithSHA512"
			}
			
			thisCertificate.PEMCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			trustTestCert = cert
		} else {
			certChain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			providedIntermediates.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
		i++
	}

	//	Trust store checking
	if mozStore != nil {
		opts := x509.VerifyOptions{
			DNSName: thisCertificate.HostName,
			Roots: mozStore,
			Intermediates: providedIntermediates,
		}

		if mozBuiltChain, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.MozTrust = "N"
		} else {
			thisCertificate.MozTrust = "Y"

			//	Check each cert in each possible completed chain against SYMC blacklist(s)
			for _, certChainMoz := range mozBuiltChain {
				for _, certFromMozChain := range certChainMoz {
					sha256Hash := sha256.New()
					sha256Hash.Write(certFromMozChain.RawSubjectPublicKeyInfo)
					thisCertKeyHash := hex.EncodeToString(sha256Hash.Sum(nil))
					if symantecBadKeys[thisCertKeyHash] {
						symantecFailure++
					}
					if symantecExceptions[thisCertKeyHash] || symantecManagedExceptions[thisCertKeyHash] {
						symantecFailure--
					}
				}
			}

		}
	}
	if msStore != nil {
		opts := x509.VerifyOptions{
			DNSName: thisCertificate.HostName,
			Roots: msStore,
			Intermediates: providedIntermediates,
		}

		if msBuiltChain, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.MSTrust = "N"
		} else {
			thisCertificate.MSTrust = "Y"

			//	Check each cert in each possible completed chain against SYMC blacklist(s)
			for _, certChainMS := range msBuiltChain {
				for _, certFromMSChain := range certChainMS {
					sha256Hash := sha256.New()
					sha256Hash.Write(certFromMSChain.RawSubjectPublicKeyInfo)
					thisCertKeyHash := hex.EncodeToString(sha256Hash.Sum(nil))
					if symantecBadKeys[thisCertKeyHash] {
						symantecFailure++
					}
					if symantecExceptions[thisCertKeyHash] || symantecManagedExceptions[thisCertKeyHash] {
						symantecFailure--
					}
				}
			}

		}
	}
	if appleStore != nil {
		opts := x509.VerifyOptions{
			DNSName: thisCertificate.HostName,
			Roots: appleStore,
			Intermediates: providedIntermediates,
		}

		if appleBuiltChain, err := trustTestCert.Verify(opts); err != nil {
			thisCertificate.AppleTrust = "N"
		} else {
			thisCertificate.AppleTrust = "Y"

			//	Check each cert in each possible completed chain against SYMC blacklist(s)
			for _, certChainApple := range appleBuiltChain {
				for _, certFromAppleChain := range certChainApple {
					sha256Hash := sha256.New()
					sha256Hash.Write(certFromAppleChain.RawSubjectPublicKeyInfo)
					thisCertKeyHash := hex.EncodeToString(sha256Hash.Sum(nil))
					if symantecBadKeys[thisCertKeyHash] {
						symantecFailure++
					}
					if symantecExceptions[thisCertKeyHash] || symantecManagedExceptions[thisCertKeyHash] {
						symantecFailure--
					}
				}
			}
		}
	}

	//fmt.Printf("SYMCFail value: %v\n", symantecFailure)

	//	Symantec distrust checking
	if symantecFailure >= 1 {
		if thisCertificate.NotBefore < 1464739200 || thisCertificate.NotBefore >= 1512086400 {
			thisCertificate.SymantecError = "Y"
		} else {
			thisCertificate.SymantecError = "N"
		}
	} else {
		thisCertificate.SymantecError = "N"
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

	scanTimings := fmt.Sprintf("Timings - DNS Lookup: %dms, IP Connection: %dms, TLS Handshake: %dms, HTTP Header: %dms, Scan processing: %dms \n", timeForDNSLookup, timeForIPConnection, timeForTLSHandshake, timeForHTTPHeader, accurateScanDuration)
	thisCertificate.ScanTimings = scanTimings
	
	return thisCertificate
}