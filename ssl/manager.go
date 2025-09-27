package ssl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

type Manager struct {
	logger                  *zap.Logger
	certDir                 string
	dnsProvider             DNS01Provider
	acmeClient              *lego.Client
	email                   string
	staging                 bool
	dnsResolvers            []string
	propagationTimeout      int
	disablePropagationCheck bool
}

type DNS01Provider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

type Certificate struct {
	Domain      string
	CertPath    string
	KeyPath     string
	Certificate tls.Certificate
	Expires     time.Time
}

func NewManager(logger *zap.Logger, dnsProvider DNS01Provider, email string, staging bool, dnsResolvers []string, propagationTimeout int, disablePropagationCheck bool) (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	certDir := filepath.Join(homeDir, ".dnsscale", "certs")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certificate directory: %w", err)
	}

	if email == "" {
		email = "dnsscale@localhost"
	}

	// Set defaults for DNS resolver configuration
	if len(dnsResolvers) == 0 {
		dnsResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if propagationTimeout <= 0 {
		propagationTimeout = 120
	}

	manager := &Manager{
		logger:                  logger,
		certDir:                 certDir,
		dnsProvider:             dnsProvider,
		email:                   email,
		staging:                 staging,
		dnsResolvers:            dnsResolvers,
		propagationTimeout:      propagationTimeout,
		disablePropagationCheck: disablePropagationCheck,
	}

	if err := manager.initACMEClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize ACME client: %w", err)
	}

	return manager, nil
}

func (m *Manager) initACMEClient() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	config := lego.NewConfig(&acmeUser{
		email: m.email,
		key:   privateKey,
	})

	if m.staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	// Use default HTTP client for ACME server communication
	config.HTTPClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Configure DNS-01 challenge options
	var dns01Options []dns01.ChallengeOption

	// Use configured DNS resolvers for challenge verification
	dns01Options = append(dns01Options, dns01.AddRecursiveNameservers(m.dnsResolvers))

	// Configure propagation settings
	if m.disablePropagationCheck {
		dns01Options = append(dns01Options, dns01.DisableCompletePropagationRequirement())
	}

	// Set DNS propagation timeout
	if m.propagationTimeout > 0 {
		dns01Options = append(dns01Options, dns01.AddDNSTimeout(time.Duration(m.propagationTimeout)*time.Second))
	}

	err = client.Challenge.SetDNS01Provider(m.dnsProvider, dns01Options...)
	if err != nil {
		return fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register with ACME server: %w", err)
	}

	m.logger.Debug("Registered with ACME server", zap.String("uri", reg.URI))
	m.acmeClient = client
	return nil
}

func (m *Manager) ObtainCertificate(ctx context.Context, domain string) (*Certificate, error) {
	m.logger.Info("Starting certificate obtainment process",
		zap.String("domain", domain),
		zap.Strings("dns_resolvers", m.dnsResolvers),
		zap.Int("propagation_timeout", m.propagationTimeout),
		zap.Bool("disable_propagation_check", m.disablePropagationCheck))

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	m.logger.Info("Submitting certificate request to ACME server", zap.String("domain", domain))
	certificates, err := m.acmeClient.Certificate.Obtain(request)
	if err != nil {
		m.logger.Error("ACME certificate obtainment failed",
			zap.String("domain", domain),
			zap.Error(err))
		return nil, fmt.Errorf("failed to obtain certificate for %s: %w", domain, err)
	}

	m.logger.Info("ACME certificate obtained successfully", zap.String("domain", domain))

	cert, err := m.saveCertificate(domain, certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	m.logger.Info("Successfully obtained certificate",
		zap.String("domain", domain),
		zap.Time("expires", cert.Expires))

	return cert, nil
}

func (m *Manager) LoadCertificate(domain string) (*Certificate, error) {
	certPath := filepath.Join(m.certDir, domain+".crt")
	keyPath := filepath.Join(m.certDir, domain+".key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate not found for domain %s", domain)
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &Certificate{
		Domain:      domain,
		CertPath:    certPath,
		KeyPath:     keyPath,
		Certificate: tlsCert,
		Expires:     x509Cert.NotAfter,
	}, nil
}

func (m *Manager) RenewCertificate(ctx context.Context, domain string) (*Certificate, error) {
	m.logger.Debug("Renewing certificate", zap.String("domain", domain))

	cert, err := m.LoadCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load existing certificate: %w", err)
	}

	certBytes, err := os.ReadFile(cert.CertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyBytes, err := os.ReadFile(cert.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	renewedCert, err := m.acmeClient.Certificate.Renew(certificate.Resource{
		Domain:      domain,
		Certificate: certBytes,
		PrivateKey:  keyBytes,
	}, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	newCert, err := m.saveCertificate(domain, renewedCert)
	if err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	m.logger.Info("Successfully renewed certificate",
		zap.String("domain", domain),
		zap.Time("expires", newCert.Expires))

	return newCert, nil
}

func (m *Manager) NeedsRenewal(cert *Certificate) bool {
	return time.Until(cert.Expires) < 30*24*time.Hour
}

func (m *Manager) saveCertificate(domain string, certificates *certificate.Resource) (*Certificate, error) {
	certPath := filepath.Join(m.certDir, domain+".crt")
	keyPath := filepath.Join(m.certDir, domain+".key")

	if err := os.WriteFile(certPath, certificates.Certificate, 0600); err != nil {
		return nil, fmt.Errorf("failed to write certificate file: %w", err)
	}

	if err := os.WriteFile(keyPath, certificates.PrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key file: %w", err)
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load saved certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse saved certificate: %w", err)
	}

	return &Certificate{
		Domain:      domain,
		CertPath:    certPath,
		KeyPath:     keyPath,
		Certificate: tlsCert,
		Expires:     x509Cert.NotAfter,
	}, nil
}

type acmeUser struct {
	email string
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return nil
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}