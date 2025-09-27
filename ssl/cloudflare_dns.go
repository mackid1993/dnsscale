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
	time.Sleep(60 * time.Second)
	return nil
}

func (c *CloudflareDNSProvider) CleanUp(domain, token, keyAuth string) error {
	recordName := fmt.Sprintf("_acme-challenge.%s", domain)

	c.logger.Info("Cleaning up ACME challenge TXT record",
		zap.String("domain", domain),
		zap.String("record_name", recordName))

	record := DNSRecord{
		Name:  recordName,
		Type:  "TXT",
		Value: fmt.Sprintf("\"%s\"", keyAuth),
		TTL:   120,
	}

	// Retry cleanup up to 3 times with increasing delays
	maxAttempts := 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := c.cfClient.DeleteRecord(ctx, extractZone(domain), record.toProvidersRecord())
		cancel()

		if err == nil {
			c.logger.Info("Successfully cleaned up ACME challenge TXT record",
				zap.String("domain", domain),
				zap.String("record_name", recordName),
				zap.Int("attempt", attempt))
			return nil
		}

		c.logger.Warn("Failed to cleanup DNS challenge record",
			zap.String("domain", domain),
			zap.String("record_name", recordName),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(err))

		if attempt < maxAttempts {
			delay := time.Duration(attempt) * 5 * time.Second
			c.logger.Debug("Retrying TXT record cleanup",
				zap.String("domain", domain),
				zap.Duration("delay", delay))
			time.Sleep(delay)
		}
	}

	// Log final failure but don't return error to avoid breaking certificate flow
	c.logger.Error("Failed to cleanup ACME challenge TXT record after all attempts",
		zap.String("domain", domain),
		zap.String("record_name", recordName),
		zap.Int("attempts", maxAttempts))

	return nil // Don't fail the certificate process due to cleanup failure
}

func extractZone(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}