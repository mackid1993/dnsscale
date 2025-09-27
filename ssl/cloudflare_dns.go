package ssl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jaxxstorm/dnsscale/providers"
	"go.uber.org/zap"
)

type CloudflareDNSProvider struct {
	apiToken string
	zoneID   string
	logger   *zap.Logger
	cfClient providers.DNSProvider
}

type DNSRecord struct {
	Name  string
	Type  string
	Value string
	TTL   int64
}

// Convert ssl.DNSRecord to providers.DNSRecord
func (r DNSRecord) toProvidersRecord() providers.DNSRecord {
	return providers.DNSRecord{
		Name:  r.Name,
		Type:  r.Type,
		Value: r.Value,
		TTL:   r.TTL,
	}
}

// Convert providers.DNSRecord to ssl.DNSRecord
func fromProvidersRecord(r providers.DNSRecord) DNSRecord {
	return DNSRecord{
		Name:  r.Name,
		Type:  r.Type,
		Value: r.Value,
		TTL:   r.TTL,
	}
}

func NewCloudflareDNSProvider(apiToken, zoneID string, logger *zap.Logger, cfClient providers.DNSProvider) *CloudflareDNSProvider {
	return &CloudflareDNSProvider{
		apiToken: apiToken,
		zoneID:   zoneID,
		logger:   logger,
		cfClient: cfClient,
	}
}

func (c *CloudflareDNSProvider) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	record := DNSRecord{
		Name:  recordName,
		Type:  "TXT",
		Value: keyAuth, // Don't add extra quotes - the provider handles quoting
		TTL:   60, // Minimum TTL allowed by Cloudflare for ACME challenges
	}

	c.logger.Info("Creating ACME challenge TXT record",
		zap.String("domain", domain),
		zap.String("record_name", recordName),
		zap.String("challenge_value", keyAuth),
		zap.String("token", token))

	if err := c.cfClient.CreateRecord(ctx, extractZone(domain), record.toProvidersRecord()); err != nil {
		c.logger.Error("Failed to create ACME challenge TXT record",
			zap.String("domain", domain),
			zap.String("record_name", recordName),
			zap.Error(err))
		return fmt.Errorf("failed to create DNS challenge record: %w", err)
	}

	c.logger.Info("Successfully created ACME challenge TXT record",
		zap.String("domain", domain),
		zap.String("record_name", recordName))

	// Wait longer for Cloudflare propagation to authoritative nameservers
	c.logger.Info("Waiting for TXT record propagation to Cloudflare nameservers",
		zap.String("record_name", recordName))
	time.Sleep(120 * time.Second) // Increased to 2 minutes for better propagation
	return nil
}

func (c *CloudflareDNSProvider) CleanUp(domain, token, keyAuth string) error {
	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	c.logger.Info("Skipping ACME challenge TXT record cleanup to allow for retries",
		zap.String("domain", domain),
		zap.String("record_name", recordName))

	// Don't cleanup TXT records - let them persist for retry attempts
	// This allows SSL certificate generation to retry without having to recreate DNS records
	return nil
}

func extractZone(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}