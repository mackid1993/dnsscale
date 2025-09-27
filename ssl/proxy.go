package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type ProxyManager struct {
	logger   *zap.Logger
	proxies  map[string]*Proxy
	mutex    sync.RWMutex
	certMgr  *Manager
	bindAddr string
}

type Proxy struct {
	domain    string
	target    string
	server    *http.Server
	logger    *zap.Logger
	certMgr   *Manager
	bindAddr  string
	running   bool
	mutex     sync.RWMutex
}

func NewProxyManager(logger *zap.Logger, certMgr *Manager, bindAddr string) *ProxyManager {
	if bindAddr == "" {
		bindAddr = ":443"
	}

	return &ProxyManager{
		logger:   logger,
		proxies:  make(map[string]*Proxy),
		certMgr:  certMgr,
		bindAddr: bindAddr,
	}
}

func (pm *ProxyManager) StartProxy(domain, targetAddr string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if existing, exists := pm.proxies[domain]; exists {
		if existing.IsRunning() {
			pm.logger.Debug("Proxy already running", zap.String("domain", domain))
			return nil
		}
	}

	proxy := &Proxy{
		domain:   domain,
		target:   targetAddr,
		logger:   pm.logger,
		certMgr:  pm.certMgr,
		bindAddr: pm.bindAddr,
	}

	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy for %s: %w", domain, err)
	}

	pm.proxies[domain] = proxy
	pm.logger.Info("Started SSL proxy",
		zap.String("domain", domain),
		zap.String("target", targetAddr),
		zap.String("bind_addr", pm.bindAddr))

	return nil
}

func (pm *ProxyManager) StopProxy(domain string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	proxy, exists := pm.proxies[domain]
	if !exists {
		return nil
	}

	if err := proxy.Stop(); err != nil {
		return fmt.Errorf("failed to stop proxy for %s: %w", domain, err)
	}

	delete(pm.proxies, domain)
	pm.logger.Info("Stopped SSL proxy", zap.String("domain", domain))
	return nil
}

func (pm *ProxyManager) ReloadCertificate(domain string) error {
	pm.mutex.RLock()
	proxy, exists := pm.proxies[domain]
	pm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("proxy not found for domain %s", domain)
	}

	return proxy.ReloadCertificate()
}

func (pm *ProxyManager) StopAll() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for domain, proxy := range pm.proxies {
		if err := proxy.Stop(); err != nil {
			pm.logger.Error("Failed to stop proxy",
				zap.String("domain", domain),
				zap.Error(err))
		}
	}
	pm.proxies = make(map[string]*Proxy)
}

func (p *Proxy) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
		return nil
	}

	cert, err := p.certMgr.LoadCertificate(p.domain)
	if err != nil {
		return fmt.Errorf("failed to load certificate for %s: %w", p.domain, err)
	}

	targetURL, err := url.Parse(fmt.Sprintf("http://%s", p.target))
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Error("Proxy error",
			zap.String("domain", p.domain),
			zap.String("target", p.target),
			zap.Error(err))
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Host, p.domain) && r.Host != p.domain {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != p.domain {
				return nil, fmt.Errorf("unknown domain: %s", hello.ServerName)
			}

			currentCert, err := p.certMgr.LoadCertificate(p.domain)
			if err != nil {
				return nil, err
			}

			return &currentCert.Certificate, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	p.server = &http.Server{
		Addr:      p.bindAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.bindAddr, err)
	}

	p.running = true

	go func() {
		defer func() {
			p.mutex.Lock()
			p.running = false
			p.mutex.Unlock()
		}()

		if err := p.server.ServeTLS(listener, "", ""); err != http.ErrServerClosed {
			p.logger.Error("SSL proxy server error",
				zap.String("domain", p.domain),
				zap.Error(err))
		}
	}()

	return nil
}

func (p *Proxy) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.running || p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := p.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	p.running = false
	return nil
}

func (p *Proxy) IsRunning() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.running
}

func (p *Proxy) ReloadCertificate() error {
	if !p.IsRunning() {
		return fmt.Errorf("proxy not running")
	}

	_, err := p.certMgr.LoadCertificate(p.domain)
	if err != nil {
		return fmt.Errorf("failed to reload certificate: %w", err)
	}

	p.logger.Debug("Certificate reloaded", zap.String("domain", p.domain))
	return nil
}