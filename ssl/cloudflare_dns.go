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
		Value: fmt.Sprintf("\"%s\"", keyAuth),
		TTL:   120,
	}

	c.logger.Debug("Creating ACME challenge TXT record",
		zap.String("domain", domain),
		zap.String("record_name", recordName),
		zap.String("token", token))

	if err := c.cfClient.CreateRecord(ctx, extractZone(domain), record.toProvidersRecord()); err != nil {
		return fmt.Errorf("failed to create DNS challenge record: %w", err)
	}

	time.Sleep(10 * time.Second)
	return nil
}

func (c *CloudflareDNSProvider) CleanUp(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	record := DNSRecord{
		Name:  recordName,
		Type:  "TXT",
		Value: fmt.Sprintf("\"%s\"", keyAuth),
		TTL:   120,
	}

	c.logger.Debug("Cleaning up ACME challenge TXT record",
		zap.String("domain", domain),
		zap.String("record_name", recordName))

	if err := c.cfClient.DeleteRecord(ctx, extractZone(domain), record.toProvidersRecord()); err != nil {
		c.logger.Warn("Failed to cleanup DNS challenge record",
			zap.String("domain", domain),
			zap.Error(err))
	}

	return nil
}

func extractZone(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}