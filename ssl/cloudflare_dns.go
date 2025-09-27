package ssl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

type CloudflareDNSProvider struct {
	apiToken string
	zoneID   string
	logger   *zap.Logger
	cfClient interface {
		CreateRecord(ctx context.Context, zone string, record DNSRecord) error
		DeleteRecord(ctx context.Context, zone string, record DNSRecord) error
	}
}

type DNSRecord struct {
	Name  string
	Type  string
	Value string
	TTL   int64
}

func NewCloudflareDNSProvider(apiToken, zoneID string, logger *zap.Logger, cfClient interface{}) *CloudflareDNSProvider {
	return &CloudflareDNSProvider{
		apiToken: apiToken,
		zoneID:   zoneID,
		logger:   logger,
		cfClient: cfClient.(interface {
			CreateRecord(ctx context.Context, zone string, record DNSRecord) error
			DeleteRecord(ctx context.Context, zone string, record DNSRecord) error
		}),
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

	if err := c.cfClient.CreateRecord(ctx, extractZone(domain), record); err != nil {
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

	if err := c.cfClient.DeleteRecord(ctx, extractZone(domain), record); err != nil {
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