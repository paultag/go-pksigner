package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/tcnksm/go-input"
	"pault.ag/go/pksigner"
)

// ErrInvalidPath is an invalid path error
type ErrInvalidPath struct {
	Path string
}

// Error is an error return
func (e *ErrInvalidPath) Error() string {
	return fmt.Sprintf("invalid path %q", e.Path)
}

// ErrInvalidLabel is an invalid label error
type ErrInvalidLabel struct {
	Cert string
	Key  string
}

// Error is an error return
func (e *ErrInvalidLabel) Error() string {
	return fmt.Sprintf("invalid cert label %q or key label %q", e.Cert, e.Key)
}

const (
	// CACFlag indicates that a CAC should be used
	CACFlag string = "cac"
	// PKCS11ModuleFlag is the location of the PCKS11 module to use with the smart card
	PKCS11ModuleFlag string = "pkcs11module"
	// TokenLabelFlag is the Token Label to use with the smart card
	TokenLabelFlag string = "tokenlabel"
	// CertLabelFlag is the Certificate Label to use with the smart card
	CertLabelFlag string = "certlabel"
	// KeyLabelFlag is the Key Label to use with the smart card
	KeyLabelFlag string = "keylabel"
	// CertPathFlag is the path to the certificate to use for TLS
	CertPathFlag string = "certpath"
	// KeyPathFlag is the path to the key to use for TLS
	KeyPathFlag string = "keypath"
	// URIFlag is the URI to connect to
	URIFlag string = "uri"
	// MethodFlag is the HTTP Method to use
	MethodFlag string = "method"
	// InsecureFlag indicates that TLS verification and validation can be skipped
	InsecureFlag string = "insecure"
	// VerboseFlag holds string identifier for command line usage
	VerboseFlag string = "verbose"
)

var pkcs11Modules = []string{
	"opensc-pkcs11.so",
	"cackey.dylib",
}

func stringSliceContains(stringSlice []string, value string) bool {
	for _, x := range stringSlice {
		if value == x {
			return true
		}
	}
	return false
}

// GetCACStore retrieves the CAC store
// Call 'defer store.Close()' after retrieving the store
func GetCACStore(v *viper.Viper) (*pksigner.Store, error) {
	pkcs11ModulePath := v.GetString(PKCS11ModuleFlag)
	tokenLabel := v.GetString(TokenLabelFlag)
	certLabel := v.GetString(CertLabelFlag)
	keyLabel := v.GetString(KeyLabelFlag)
	pkcsConfig := pksigner.Config{
		Module:           pkcs11ModulePath,
		CertificateLabel: certLabel,
		PrivateKeyLabel:  keyLabel,
		TokenLabel:       tokenLabel,
	}

	store, errPKCS11New := pksigner.New(pkcsConfig)
	if errPKCS11New != nil {
		return nil, errPKCS11New
	}

	inputUI := &input.UI{
		Writer: os.Stderr,
		Reader: os.Stdin,
	}

	pin, errUIAsk := inputUI.Ask("CAC PIN", &input.Options{
		Default:     "",
		HideOrder:   true,
		HideDefault: true,
		Required:    true,
		Loop:        true,
		Mask:        true,
		ValidateFunc: func(input string) error {
			matched, matchErr := regexp.Match("^\\d+$", []byte(input))
			if matchErr != nil {
				return matchErr
			}
			if !matched {
				return errors.New("Invalid PIN format")
			}
			return nil
		},
	})
	if errUIAsk != nil {
		return nil, errUIAsk
	}

	errLogin := store.Login(pin)
	if errLogin != nil {
		return nil, errLogin
	}
	return store, nil
}

// initializeFlags sets up CLI flags
func initFlags(flag *pflag.FlagSet) {

	// CAC Flags
	flag.Bool(CACFlag, false, "Use a CAC for authentication")
	flag.String(PKCS11ModuleFlag, "/usr/local/lib/pkcs11/opensc-pkcs11.so", "Smart card: Path to the PKCS11 module to use")
	flag.String(TokenLabelFlag, "", "Smart card: name of the token to use")
	flag.String(CertLabelFlag, "Certificate for PIV Authentication", "Smart card: label of the public cert")
	flag.String(KeyLabelFlag, "PIV AUTH key", "Smart card: label of the private key")

	// Cert Flags
	flag.String(CertPathFlag, "local.cer", "Path to the public cert")
	flag.String(KeyPathFlag, "local.key", "Path to the private key")

	// URI Flags
	flag.String(URIFlag, "https://localhost:8443", "The URI to connect to")
	flag.String(MethodFlag, "GET", "The HTTP method to use")
	flag.Bool(InsecureFlag, false, "Skip TLS verification and validation")

	// Other Flags
	flag.BoolP(VerboseFlag, "v", false, "Show extra output for debugging")
	flag.SortFlags = false
}

// checkConfig checks the config
func checkConfig(v *viper.Viper, logger *log.Logger) error {

	if v.GetBool(CACFlag) {
		pkcs11ModulePath := v.GetString(PKCS11ModuleFlag)
		if pkcs11ModulePath == "" {
			return fmt.Errorf("%q is invalid: %w", PKCS11ModuleFlag, &ErrInvalidPath{Path: pkcs11ModulePath})
		} else if _, err := os.Stat(pkcs11ModulePath); err != nil {
			return fmt.Errorf("%q is invalid: %w", PKCS11ModuleFlag, &ErrInvalidPath{Path: pkcs11ModulePath})
		}
		if pkcs11Base := path.Base(pkcs11ModulePath); !stringSliceContains(pkcs11Modules, pkcs11Base) {
			return fmt.Errorf("invalid PKCS11 module %s, expecting one of %q", pkcs11ModulePath, pkcs11Modules)
		}

		certLabel := v.GetString(CertLabelFlag)
		keyLabel := v.GetString(KeyLabelFlag)
		if certLabel == "" || keyLabel == "" {
			return fmt.Errorf("%q or %q is invalid: %w", CertLabelFlag, KeyLabelFlag, &ErrInvalidLabel{Cert: certLabel, Key: keyLabel})
		}
	}

	if !v.GetBool(CACFlag) {
		certPath := v.GetString(CertPathFlag)
		if certPath == "" {
			return fmt.Errorf("%q is invalid: %w", CertPathFlag, &ErrInvalidPath{Path: certPath})
		} else if _, err := os.Stat(certPath); err != nil {
			return fmt.Errorf("%q is invalid: %w", CertPathFlag, &ErrInvalidPath{Path: certPath})
		}

		keyPath := v.GetString(KeyPathFlag)
		if keyPath == "" {
			return fmt.Errorf("%q is invalid: %w", KeyPathFlag, &ErrInvalidPath{Path: keyPath})
		} else if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("%q is invalid: %w", KeyPathFlag, &ErrInvalidPath{Path: keyPath})
		}
	}
	return nil
}

func main() {
	flag := pflag.CommandLine
	initFlags(flag)
	err := flag.Parse(os.Args[1:])
	if err != nil {
		fmt.Println("Arg parse failed")
		return
	}

	v := viper.New()
	err = v.BindPFlags(flag)
	if err != nil {
		fmt.Println("Arg binding failed")
		return
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	//Create the logger
	//Remove the prefix and any datetime data
	logger := log.New(os.Stdout, "", log.LstdFlags)

	verbose := v.GetBool(VerboseFlag)
	if !verbose {
		// Disable any logging that isn't attached to the logger unless using the verbose flag
		log.SetOutput(ioutil.Discard)
		log.SetFlags(0)

		// Remove the flags for the logger
		logger.SetFlags(0)
	}

	err = checkConfig(v, logger)
	if err != nil {
		logger.Fatal(err)
	}

	// Use command line inputs
	insecure := v.GetBool(InsecureFlag)

	// The client certificate comes from a smart card
	var tlsConfig *tls.Config
	var tlsCertificate *tls.Certificate
	var errTLSCert error
	if v.GetBool(CACFlag) {
		store, errStore := GetCACStore(v)
		if errStore != nil {
			log.Fatal(errStore)
		}
		defer func() {
			errClose := store.Close()
			if errClose != nil {
				log.Fatal(errClose)
			}
		}()
		tlsCertificate, errTLSCert = store.TLSCertificate()

	} else if !v.GetBool(CACFlag) {
		certPath := v.GetString(CertPathFlag)
		keyPath := v.GetString(KeyPathFlag)
		var cert tls.Certificate
		cert, errTLSCert = tls.LoadX509KeyPair(certPath, keyPath)
		tlsCertificate = &cert
	}

	if errTLSCert != nil {
		log.Fatal(errTLSCert)
	}

	// #nosec b/c gosec triggers on InsecureSkipVerify
	tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{*tlsCertificate},
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	var body bytes.Buffer
	uri := v.GetString(URIFlag)
	method := v.GetString(MethodFlag)
	req, err := http.NewRequest(method, uri, &body)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v\n", resp)
}
