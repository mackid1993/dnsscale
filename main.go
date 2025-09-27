package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/dnsscale/providers"
	"github.com/jaxxstorm/dnsscale/ssl"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/util/workqueue"
)

// TailscaleDevice represents a device in the Tailscale network
// This matches the Tailscale API response format
type TailscaleDevice struct {
	ID                        string    `json:"id"`
	Name                      string    `json:"name"`
	Hostname                  string    `json:"hostname"`
	ClientVersion             string    `json:"clientVersion"`
	UpdateAvailable           bool      `json:"updateAvailable"`
	OS                        string    `json:"os"`
	Created                   time.Time `json:"created"`
	LastSeen                  time.Time `json:"lastSeen"`
	KeyExpiryDisabled         bool      `json:"keyExpiryDisabled"`
	Expires                   time.Time `json:"expires"`
	Authorized                bool      `json:"authorized"`
	IsExternal                bool      `json:"isExternal"`
	MachineKey                string    `json:"machineKey"`
	NodeKey                   string    `json:"nodeKey"`
	BlocksIncomingConnections bool      `json:"blocksIncomingConnections"`
	EnabledRoutes             []string  `json:"enabledRoutes"`
	AdvertisedRoutes          []string  `json:"advertisedRoutes"`
	Tags                      []string  `json:"tags"`
	TailnetLockError          string    `json:"tailnetLockError,omitempty"`
	TailnetLockKey            string    `json:"tailnetLockKey,omitempty"`
	Addresses                 []string  `json:"addresses"`
	User                      string    `json:"user,omitempty"`
}

// TailscaleDevicesResponse represents the API response for listing devices
type TailscaleDevicesResponse struct {
	Devices []TailscaleDevice `json:"devices"`
}

// TailscaleNode is a simplified representation for internal use
type TailscaleNode struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hostname  string    `json:"hostname"`
	Addresses []string  `json:"addresses"`
	Tags      []string  `json:"tags"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
}

// ToTailscaleNode converts a TailscaleDevice to a simplified TailscaleNode
func (d *TailscaleDevice) ToTailscaleNode() TailscaleNode {
	// Consider a device online if it was seen within the last 5 minutes
	online := time.Since(d.LastSeen) < 5*time.Minute

	// Extract just the device name (first part before any dots)
	name := d.Name
	if name == "" {
		name = d.Hostname
	}

	// Remove the Tailscale domain suffix to get just the device name
	// e.g., "lbr-macbook-pro.tail4cf751.ts.net" -> "lbr-macbook-pro"
	if dotIndex := strings.Index(name, "."); dotIndex > 0 {
		name = name[:dotIndex]
	}

	return TailscaleNode{
		ID:        d.ID,
		Name:      name,
		Hostname:  d.Hostname,
		Addresses: d.Addresses,
		Tags:      d.Tags,
		Online:    online,
		LastSeen:  d.LastSeen,
	}
}

// TailscaleClient handles Tailscale API interactions
type TailscaleClient struct {
	apiKey     string
	tailnet    string
	logger     *zap.Logger
	httpClient *http.Client
	baseURL    string
}

func NewTailscaleClient(apiKey, tailnet string, logger *zap.Logger) *TailscaleClient {
	return &TailscaleClient{
		apiKey:     apiKey,
		tailnet:    tailnet,
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.tailscale.com",
	}
}

func (t *TailscaleClient) ListNodes(ctx context.Context) ([]TailscaleNode, error) {
	// URL encode the tailnet name to handle email addresses and special characters
	encodedTailnet := url.QueryEscape(t.tailnet)
	apiURL := fmt.Sprintf("%s/api/v2/tailnet/%s/devices", t.baseURL, encodedTailnet)

	t.logger.Debug("Calling Tailscale API",
		zap.String("url", apiURL),
		zap.String("tailnet", t.tailnet))

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication header
	req.Header.Set("Authorization", "Bearer "+t.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnsscale/1.0")

	// Make the request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	// Check for API errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	// Parse the response
	var devicesResp TailscaleDevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResp); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Convert devices to nodes
	nodes := make([]TailscaleNode, 0, len(devicesResp.Devices))
	for _, device := range devicesResp.Devices {
		// Only include authorized devices
		if !device.Authorized {
			t.logger.Debug("Skipping unauthorized device",
				zap.String("device_name", device.Name),
				zap.String("device_id", device.ID))
			continue
		}

		node := device.ToTailscaleNode()
		nodes = append(nodes, node)

		t.logger.Debug("Found device",
			zap.String("device_name", node.Name),
			zap.String("device_id", node.ID),
			zap.Strings("addresses", node.Addresses),
			zap.Bool("online", node.Online),
			zap.Strings("tags", node.Tags))
	}

	t.logger.Info("Retrieved devices from Tailscale API",
		zap.Int("total_devices", len(devicesResp.Devices)),
		zap.Int("authorized_devices", len(nodes)))

	return nodes, nil
}

// DNSReconciler is the main reconciliation controller
type DNSReconciler struct {
	tailscale    *TailscaleClient
	dnsProvider  providers.DNSProvider
	domain       string
	queue        workqueue.RateLimitingInterface
	nodeCache    map[string]TailscaleNode
	cacheMutex   sync.RWMutex
	pollInterval time.Duration
	annotations  map[string]string // For filtering based on tags
	logger       *zap.Logger
	sslEnabled   bool
	sslManager   *ssl.Manager
	proxyManager *ssl.ProxyManager
	sslQueue     workqueue.RateLimitingInterface // Separate queue for SSL certificate processing
	sslFailures  map[string]time.Time           // Track SSL failures for retry logic
	failureMutex sync.RWMutex                   // Protect sslFailures map
}

func NewDNSReconciler(ts *TailscaleClient, dns providers.DNSProvider, domain string, pollInterval time.Duration, logger *zap.Logger, sslEnabled bool, sslManager *ssl.Manager, proxyManager *ssl.ProxyManager) *DNSReconciler {
	return &DNSReconciler{
		tailscale:    ts,
		dnsProvider:  dns,
		domain:       domain,
		queue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		nodeCache:    make(map[string]TailscaleNode),
		pollInterval: pollInterval,
		annotations:  make(map[string]string),
		logger:       logger,
		sslEnabled:   sslEnabled,
		sslManager:   sslManager,
		proxyManager: proxyManager,
		sslQueue:     workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		sslFailures:  make(map[string]time.Time),
	}
}

// Run starts the reconciliation loop
func (r *DNSReconciler) Run(ctx context.Context, workers int) error {
	defer r.queue.ShutDown()
	defer r.sslQueue.ShutDown()
	defer func() {
		if r.proxyManager != nil {
			r.proxyManager.StopAll()
		}
	}()

	r.logger.Info("Starting DNS reconciler",
		zap.Int("workers", workers),
		zap.String("domain", r.domain),
		zap.Duration("poll_interval", r.pollInterval),
		zap.Bool("ssl_enabled", r.sslEnabled))

	// Start the Tailscale watcher
	go r.watchTailscale(ctx)

	// Start certificate renewal if SSL is enabled
	if r.sslEnabled && r.sslManager != nil {
		go r.certificateRenewalLoop(ctx)
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r.logger.Debug("Starting DNS worker", zap.Int("worker_id", workerID))
			r.worker(ctx)
		}(i)
	}

	// Start SSL certificate workers (separate from DNS workers)
	if r.sslEnabled && r.sslManager != nil && r.proxyManager != nil {
		sslWorkers := 2 // Use fewer SSL workers since they're slower
		for i := 0; i < sslWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				r.logger.Debug("Starting SSL worker", zap.Int("worker_id", workerID))
				r.sslWorker(ctx)
			}(i)
		}
	}

	<-ctx.Done()
	r.logger.Info("Shutting down reconciler")
	wg.Wait()
	return ctx.Err()
}

// watchTailscale polls Tailscale API for changes
func (r *DNSReconciler) watchTailscale(ctx context.Context) {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	// Initial sync
	r.syncNodes(ctx)

	for {
		select {
		case <-ticker.C:
			r.syncNodes(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// syncNodes fetches current state from Tailscale and queues changes
func (r *DNSReconciler) syncNodes(ctx context.Context) {
	nodes, err := r.tailscale.ListNodes(ctx)
	if err != nil {
		r.logger.Error("Error listing Tailscale nodes", zap.Error(err))
		return
	}

	r.logger.Debug("Syncing nodes", zap.Int("node_count", len(nodes)))

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	currentNodes := make(map[string]bool)

	// Check for new or updated nodes
	for _, node := range nodes {
		currentNodes[node.ID] = true

		if existingNode, exists := r.nodeCache[node.ID]; !exists || !nodesEqual(existingNode, node) {
			r.nodeCache[node.ID] = node
			r.queue.Add(node.ID)
			r.logger.Info("Queuing node for reconciliation",
				zap.String("node_name", node.Name),
				zap.String("node_id", node.ID),
				zap.Bool("online", node.Online),
				zap.Strings("addresses", node.Addresses))
		}
	}

	// Check for deleted nodes
	for id := range r.nodeCache {
		if !currentNodes[id] {
			delete(r.nodeCache, id)
			r.queue.Add(id + ":delete")
			r.logger.Info("Queuing node for deletion", zap.String("node_id", id))
		}
	}
}

// worker processes items from the queue
func (r *DNSReconciler) worker(ctx context.Context) {
	for {
		item, shutdown := r.queue.Get()
		if shutdown {
			return
		}

		func() {
			defer r.queue.Done(item)

			if err := r.reconcile(ctx, item.(string)); err != nil {
				r.logger.Error("Error reconciling item",
					zap.String("item", item.(string)),
					zap.Error(err))
				r.queue.AddRateLimited(item)
			} else {
				r.queue.Forget(item)
			}
		}()
	}
}

// reconcile handles a single reconciliation
func (r *DNSReconciler) reconcile(ctx context.Context, key string) error {
	// Check if this is a deletion
	if strings.HasSuffix(key, ":delete") {
		nodeID := strings.TrimSuffix(key, ":delete")
		return r.deleteNodeDNS(ctx, nodeID)
	}

	r.cacheMutex.RLock()
	node, exists := r.nodeCache[key]
	r.cacheMutex.RUnlock()

	if !exists {
		return fmt.Errorf("node %s not found in cache", key)
	}

	// Check if node should be managed based on tags
	if !r.shouldManageNode(node) {
		r.logger.Debug("Skipping node due to tag filters",
			zap.String("node_name", node.Name),
			zap.Strings("node_tags", node.Tags))
		return nil
	}

	// Create DNS records for the node
	recordName := fmt.Sprintf("%s.%s", node.Name, r.domain)

	// ALWAYS create DNS A/AAAA records first - SSL is separate
	for _, addr := range node.Addresses {
		recordType := "A"
		if strings.Contains(addr, ":") {
			recordType = "AAAA"
		}

		record := providers.DNSRecord{
			Name:  recordName,
			Type:  recordType,
			Value: addr,
			TTL:   300,
		}

		if err := r.dnsProvider.UpdateRecord(ctx, r.domain, record); err != nil {
			return fmt.Errorf("failed to update DNS record: %w", err)
		}

		r.logger.Info("Updated DNS record",
			zap.String("record_type", recordType),
			zap.String("record_name", record.Name),
			zap.String("record_value", addr),
			zap.String("node_name", node.Name))
	}

	// If SSL is enabled, queue this domain for SSL certificate generation
	// This happens in the background and doesn't block DNS record creation
	if r.sslEnabled && r.sslManager != nil && r.proxyManager != nil {
		r.queueSSLCertificate(recordName)
	}

	// Create TXT ownership record to indicate this record is managed by dnsscale
	txtRecord := providers.DNSRecord{
		Name:  recordName,
		Type:  "TXT",
		Value: fmt.Sprintf("\"dnsscale-managed node_id=%s\"", node.ID),
		TTL:   300,
	}

	if err := r.dnsProvider.UpdateRecord(ctx, r.domain, txtRecord); err != nil {
		r.logger.Warn("Failed to create TXT ownership record",
			zap.String("record_name", txtRecord.Name),
			zap.Error(err))
		// Don't fail the entire reconciliation if TXT record fails
	} else {
		r.logger.Info("Updated TXT ownership record",
			zap.String("record_name", txtRecord.Name),
			zap.String("record_value", txtRecord.Value))
	}

	return nil
}

// deleteNodeDNS removes DNS records for a deleted node
func (r *DNSReconciler) deleteNodeDNS(ctx context.Context, nodeID string) error {
	// In production, you'd need to track which records were created
	// For now, we'll list and delete matching records
	records, err := r.dnsProvider.ListRecords(ctx, r.domain)
	if err != nil {
		return err
	}

	for _, record := range records {
		// Check if this is a TXT record managed by us with the specific node ID
		if record.Type == "TXT" && strings.Contains(record.Value, fmt.Sprintf("node_id=%s", nodeID)) {
			// This is our ownership record, delete all records with this name
			recordName := record.Name
			r.logger.Info("Found dnsscale-managed record to delete",
				zap.String("record_name", recordName),
				zap.String("node_id", nodeID))

			// Delete all records (A, AAAA, TXT) with this name
			for _, recordToDelete := range records {
				if recordToDelete.Name == recordName {
					if err := r.dnsProvider.DeleteRecord(ctx, r.domain, recordToDelete); err != nil {
						r.logger.Error("Failed to delete DNS record",
							zap.String("record_name", recordToDelete.Name),
							zap.String("record_type", recordToDelete.Type),
							zap.Error(err))
					} else {
						r.logger.Info("Deleted DNS record",
							zap.String("record_name", recordToDelete.Name),
							zap.String("record_type", recordToDelete.Type))
					}
				}
			}
			break // We found our record, no need to continue
		}
	}

	return nil
}

// shouldManageNode determines if a node should have DNS records created
func (r *DNSReconciler) shouldManageNode(node TailscaleNode) bool {
	// Example: only manage nodes with specific tags
	if len(r.annotations) > 0 {
		for _, tag := range node.Tags {
			if _, exists := r.annotations[tag]; exists {
				return true
			}
		}
		return false
	}
	return true
}

// waitForDNSPropagation checks if DNS record has propagated using configured resolvers
// It keeps trying until success - no timeout
func (r *DNSReconciler) waitForDNSPropagation(recordName, expectedIP string) error {
	// Use default resolvers if not available (fallback)
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}

	attempt := 1
	for {
		// Try each configured resolver
		for _, resolverAddr := range resolvers {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 10,
					}
					return d.DialContext(ctx, network, resolverAddr)
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			ips, err := resolver.LookupIPAddr(ctx, recordName)
			cancel()

			if err == nil {
				for _, ip := range ips {
					if ip.IP.String() == expectedIP {
						r.logger.Info("DNS propagation confirmed",
							zap.String("record", recordName),
							zap.String("ip", expectedIP),
							zap.String("resolver", resolverAddr),
							zap.Int("attempt", attempt))
						return nil
					}
				}
			}
		}

		r.logger.Info("DNS propagation not yet complete, retrying",
			zap.String("record", recordName),
			zap.String("expected_ip", expectedIP),
			zap.Int("attempt", attempt))

		attempt++
		time.Sleep(15 * time.Second) // Wait 15 seconds between attempts
	}
}

// shouldRetrySSL checks if enough time has passed since the last SSL failure
func (r *DNSReconciler) shouldRetrySSL(recordName string) bool {
	r.failureMutex.RLock()
	defer r.failureMutex.RUnlock()

	lastFailure, exists := r.sslFailures[recordName]
	if !exists {
		return true // No previous failure, try SSL
	}

	// Wait 30 minutes before retrying SSL after a failure
	retryDelay := 30 * time.Minute
	return time.Since(lastFailure) > retryDelay
}

// recordSSLFailure records when SSL setup failed for a domain
func (r *DNSReconciler) recordSSLFailure(recordName string) {
	r.failureMutex.Lock()
	defer r.failureMutex.Unlock()

	r.sslFailures[recordName] = time.Now()
	r.logger.Info("Recorded SSL failure, will retry later",
		zap.String("record", recordName),
		zap.Duration("retry_delay", 30*time.Minute))
}

// clearSSLFailure removes a domain from the failure tracking
func (r *DNSReconciler) clearSSLFailure(recordName string) {
	r.failureMutex.Lock()
	defer r.failureMutex.Unlock()

	delete(r.sslFailures, recordName)
	r.logger.Debug("Cleared SSL failure record", zap.String("record", recordName))
}

// certificateRenewalLoop handles automatic certificate renewal
func (r *DNSReconciler) certificateRenewalLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.checkAndRenewCertificates(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// checkAndRenewCertificates checks all certificates and renews if needed
func (r *DNSReconciler) checkAndRenewCertificates(ctx context.Context) {
	r.cacheMutex.RLock()
	nodes := make([]TailscaleNode, 0, len(r.nodeCache))
	for _, node := range r.nodeCache {
		nodes = append(nodes, node)
	}
	r.cacheMutex.RUnlock()

	for _, node := range nodes {
		if !r.shouldManageNode(node) {
			continue
		}

		recordName := fmt.Sprintf("%s.%s", node.Name, r.domain)
		cert, err := r.sslManager.LoadCertificate(recordName)
		if err != nil {
			r.logger.Debug("Certificate not found for renewal check",
				zap.String("domain", recordName),
				zap.Error(err))
			continue
		}

		if r.sslManager.NeedsRenewal(cert) {
			r.logger.Info("Renewing certificate",
				zap.String("domain", recordName),
				zap.Time("expires", cert.Expires))

			newCert, err := r.sslManager.RenewCertificate(ctx, recordName)
			if err != nil {
				r.logger.Error("Failed to renew certificate",
					zap.String("domain", recordName),
					zap.Error(err))
				continue
			}

			// Reload certificate in proxy
			if err := r.proxyManager.ReloadCertificate(recordName); err != nil {
				r.logger.Error("Failed to reload certificate in proxy",
					zap.String("domain", recordName),
					zap.Error(err))
			}

			r.logger.Info("Successfully renewed certificate",
				zap.String("domain", recordName),
				zap.Time("new_expires", newCert.Expires))
		}
	}
}

// Helper function to compare nodes
func nodesEqual(a, b TailscaleNode) bool {
	if a.Name != b.Name || a.Online != b.Online || len(a.Addresses) != len(b.Addresses) {
		return false
	}

	for i, addr := range a.Addresses {
		if addr != b.Addresses[i] {
			return false
		}
	}

	return true
}

// setupLogger creates a Zap logger with the specified config
func setupLogger(config *LoggingConfig) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch config.Level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	var zapConfig zap.Config
	if config.Format == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}

	zapConfig.Level = zap.NewAtomicLevelAt(zapLevel)
	return zapConfig.Build()
}

// createDNSProvider creates the appropriate DNS provider based on configuration
func createDNSProvider(ctx context.Context, config *Config, logger *zap.Logger) (providers.DNSProvider, error) {
	switch config.DNS.Provider {
	case "route53":
		logger.Info("Initializing Route53 DNS provider", zap.String("zone_id", config.DNS.ZoneID))
		return providers.NewRoute53Provider(ctx, config.DNS.ZoneID)
	case "cloudflare":
		if config.DNS.Cloudflare.APIToken == "" {
			return nil, fmt.Errorf("cloudflare API token is required when using cloudflare provider")
		}
		logger.Info("Initializing Cloudflare DNS provider", zap.String("zone_id", config.DNS.ZoneID))
		return providers.NewCloudflareProvider(config.DNS.Cloudflare.APIToken, config.DNS.ZoneID)
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", config.DNS.Provider)
	}
}

// runDNSScale is the main application logic
func runDNSScale(config *Config) error {
	// Setup logger
	logger, err := setupLogger(&config.Logging)
	if err != nil {
		return fmt.Errorf("failed to setup logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("Starting dnsscale",
		zap.String("dns_provider", config.DNS.Provider),
		zap.String("dns_domain", config.DNS.Domain),
		zap.Int("workers", config.App.Workers),
		zap.Duration("poll_interval", config.App.PollInterval),
		zap.String("log_level", config.Logging.Level))

	ctx := context.Background()

	// Initialize Tailscale client
	tsClient := NewTailscaleClient(config.Tailscale.APIKey, config.Tailscale.Tailnet, logger)

	// Initialize DNS provider
	dnsProvider, err := createDNSProvider(ctx, config, logger)
	if err != nil {
		logger.Fatal("Failed to initialize DNS provider", zap.Error(err))
	}

	// Initialize SSL components if enabled
	var sslManager *ssl.Manager
	var proxyManager *ssl.ProxyManager

	if config.SSL.Enabled {
		logger.Info("SSL enabled, initializing certificate manager")

		// Create DNS provider for ACME challenges
		if config.DNS.Provider != "cloudflare" {
			logger.Fatal("SSL is only supported with Cloudflare DNS provider")
		}

		// Create SSL DNS provider for ACME challenges
		sslDNSProvider := ssl.NewCloudflareDNSProvider(
			config.DNS.Cloudflare.APIToken,
			config.DNS.ZoneID,
			logger,
			dnsProvider,
		)

		// DNS resolvers will be configured in the SSL manager and propagation checks
		logger.Info("Using custom DNS resolvers for SSL",
			zap.Strings("resolvers", config.SSL.DNSResolvers))

		// Initialize SSL manager
		var err error
		sslManager, err = ssl.NewManager(
			logger,
			sslDNSProvider,
			config.SSL.Email,
			false, // Use production Let's Encrypt
			config.SSL.DNSResolvers,
			config.SSL.PropagationTimeout,
			config.SSL.DisablePropagationCheck,
		)
		if err != nil {
			logger.Fatal("Failed to initialize SSL manager", zap.Error(err))
		}

		// Initialize proxy manager
		proxyManager = ssl.NewProxyManager(logger, sslManager, ":443")

		logger.Info("SSL components initialized successfully")
	}

	// Create and run reconciler
	reconciler := NewDNSReconciler(tsClient, dnsProvider, config.DNS.Domain, config.App.PollInterval, logger, config.SSL.Enabled, sslManager, proxyManager)

	// Set tag filters if specified
	for _, tag := range config.App.RequiredTags {
		reconciler.annotations[tag] = "true"
		logger.Info("Added required tag filter", zap.String("tag", tag))
	}

	if err := reconciler.Run(ctx, config.App.Workers); err != nil {
		logger.Fatal("Reconciler failed", zap.Error(err))
	}

	return nil
}

// queueSSLCertificate adds a domain to the SSL certificate processing queue
func (r *DNSReconciler) queueSSLCertificate(domain string) {
	if r.shouldRetrySSL(domain) {
		r.logger.Info("Queuing SSL certificate generation", zap.String("domain", domain))
		r.sslQueue.Add(domain)
	} else {
		r.logger.Debug("Skipping SSL queue due to recent failure", zap.String("domain", domain))
	}
}

// sslWorker processes SSL certificate requests from the queue
func (r *DNSReconciler) sslWorker(ctx context.Context) {
	for {
		item, shutdown := r.sslQueue.Get()
		if shutdown {
			return
		}

		domain := item.(string)
		r.logger.Info("Processing SSL certificate request", zap.String("domain", domain))

		// Keep trying until success - no immediate failure/cleanup
		err := r.processSSLCertificate(ctx, domain)
		if err != nil {
			r.logger.Warn("SSL certificate generation failed, will retry",
				zap.String("domain", domain),
				zap.Error(err))

			// Requeue with exponential backoff
			r.sslQueue.AddRateLimited(item)
		} else {
			r.logger.Info("SSL certificate generated successfully", zap.String("domain", domain))
			r.clearSSLFailure(domain)
			r.sslQueue.Forget(item)
		}

		r.sslQueue.Done(item)
	}
}

// processSSLCertificate handles the actual SSL certificate generation
func (r *DNSReconciler) processSSLCertificate(ctx context.Context, domain string) error {
	// Get the node to find the target IP
	var targetNode TailscaleNode
	found := false

	r.cacheMutex.RLock()
	for _, node := range r.nodeCache {
		expectedDomain := fmt.Sprintf("%s.%s", node.Name, r.domain)
		if expectedDomain == domain {
			targetNode = node
			found = true
			break
		}
	}
	r.cacheMutex.RUnlock()

	if !found {
		return fmt.Errorf("node not found for domain %s", domain)
	}

	// Find IPv4 address
	var nodeIPv4 string
	for _, addr := range targetNode.Addresses {
		if !strings.Contains(addr, ":") {
			nodeIPv4 = addr
			break
		}
	}

	if nodeIPv4 == "" {
		return fmt.Errorf("no IPv4 address found for node %s", targetNode.Name)
	}

	// Try to load existing certificate first
	cert, err := r.sslManager.LoadCertificate(domain)
	if err != nil {
		// Certificate doesn't exist, obtain a new one
		r.logger.Info("Obtaining new SSL certificate", zap.String("domain", domain))
		cert, err = r.sslManager.ObtainCertificate(ctx, domain)
		if err != nil {
			// Don't clean up - just return error for retry
			return fmt.Errorf("failed to obtain certificate for %s: %w", domain, err)
		}
		r.logger.Info("Successfully obtained SSL certificate", zap.String("domain", domain))
	} else if r.sslManager.NeedsRenewal(cert) {
		// Certificate exists but needs renewal
		r.logger.Info("Certificate needs renewal",
			zap.String("domain", domain),
			zap.Time("expires", cert.Expires))
		cert, err = r.sslManager.RenewCertificate(ctx, domain)
		if err != nil {
			// Don't clean up - just return error for retry
			return fmt.Errorf("failed to renew certificate for %s: %w", domain, err)
		}
		r.logger.Info("Successfully renewed SSL certificate", zap.String("domain", domain))
	} else {
		// Certificate exists and is valid
		r.logger.Info("Using existing valid SSL certificate",
			zap.String("domain", domain),
			zap.Time("expires", cert.Expires))
	}

	// Start SSL proxy pointing to the node
	targetAddr := fmt.Sprintf("%s:80", nodeIPv4)
	if err := r.proxyManager.StartProxy(domain, targetAddr); err != nil {
		return fmt.Errorf("failed to start proxy for %s: %w", domain, err)
	}

	r.logger.Info("SSL proxy started successfully",
		zap.String("domain", domain),
		zap.String("target", targetAddr))

	return nil
}

func main() {
	Execute()
}
