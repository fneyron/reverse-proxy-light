package main

import (
    "bufio"
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/pem"
    "flag"
    "fmt"
    "log"
    "math/big"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/elazarl/goproxy"
    "gopkg.in/yaml.v3"
)

type Rule struct {
    Match       string `yaml:"match"`

    // If set: rewrite HTTPS traffic for this host to this origin (requires MITM).
    RewriteTo   string `yaml:"rewrite_to"`

    // Upstream proxy selection for this host: "http://proxy:3128", "DIRECT", or empty.
    UpstreamProxy string `yaml:"upstream_proxy"`

    // Optional auth header injection when RewriteTo is used:
    Token       string `yaml:"token"`        // literal token (optional)
    TokenEnv    string `yaml:"token_env"`    // env var name holding token (optional)
    TokenHeader string `yaml:"token_header"` // default "x-proxy-token"
}

type Config struct {
    DefaultUpstreamProxy string `yaml:"default_upstream_proxy"`
    Rules                []Rule `yaml:"rules"`
}

func loadConfig(path string) (*Config, error) {
    if strings.TrimSpace(path) == "" {
        return nil, nil
    }
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var cfg Config
    if err := yaml.Unmarshal(b, &cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}

func hostOnly(hostport string) string {
    if h, _, err := net.SplitHostPort(hostport); err == nil {
        return h
    }
    return hostport
}

func matchHost(pattern, host string) bool {
    p := strings.ToLower(strings.TrimSpace(pattern))
    h := strings.ToLower(strings.TrimSpace(host))
    if p == "" || h == "" {
        return false
    }
    if strings.HasPrefix(p, "*.") {
        suffix := strings.TrimPrefix(p, "*") // ".example.com"
        return strings.HasSuffix(h, suffix)
    }
    return p == h
}

func findRule(cfg *Config, host string) (Rule, bool) {
    if cfg == nil {
        return Rule{}, false
    }
    for _, r := range cfg.Rules {
        if matchHost(r.Match, host) {
            return r, true
        }
    }
    return Rule{}, false
}

func parseOrigin(raw string) (*url.URL, bool) {
    v := strings.TrimSpace(raw)
    if v == "" {
        return nil, false
    }
    if !strings.Contains(v, "://") {
        v = "https://" + v
    }
    u, err := url.Parse(v)
    if err != nil || u.Host == "" {
        return nil, false
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return nil, false
    }
    if u.User != nil || u.Port() != "" {
        return nil, false
    }
    return u, true
}

func shouldMitmHost(cfg *Config, host string) bool {
    r, ok := findRule(cfg, host)
    if !ok {
        return false
    }
    _, ok = parseOrigin(r.RewriteTo)
    return ok
}

func mustParseProxyURL(raw string) *url.URL {
    addr := strings.TrimSpace(raw)
    if addr == "" {
        return nil
    }
    if strings.EqualFold(addr, "DIRECT") {
        return nil
    }
    if !strings.Contains(addr, "://") {
        addr = "http://" + addr
    }
    u, err := url.Parse(addr)
    if err != nil || u.Host == "" {
        log.Fatalf("Invalid proxy URL: %q (%v)", raw, err)
    }
    return u
}

func sameProxyURL(a string, base *url.URL) bool {
    if base == nil || strings.TrimSpace(a) == "" {
        return false
    }
    ua := mustParseProxyURL(a)
    if ua == nil {
        return false
    }
    if !strings.EqualFold(ua.Scheme, base.Scheme) || !strings.EqualFold(ua.Host, base.Host) {
        return false
    }
    uaUser := ""
    baseUser := ""
    if ua.User != nil {
        uaUser = ua.User.String()
    }
    if base.User != nil {
        baseUser = base.User.String()
    }
    return uaUser == baseUser
}

func dialViaProxy(ctx context.Context, network, addr string, via *url.URL) (net.Conn, error) {
    dialer := &net.Dialer{}
    var conn net.Conn
    var err error

    if strings.EqualFold(via.Scheme, "https") {
        tlsDialer := &tls.Dialer{NetDialer: dialer}
        conn, err = tlsDialer.DialContext(ctx, network, via.Host)
    } else {
        conn, err = dialer.DialContext(ctx, network, via.Host)
    }
    if err != nil {
        return nil, err
    }

    connectReq := &http.Request{
        Method: "CONNECT",
        URL:    &url.URL{Opaque: addr},
        Host:   addr,
        Header: make(http.Header),
    }
    if via.User != nil {
        user := via.User.Username()
        pass, _ := via.User.Password()
        auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
        connectReq.Header.Set("Proxy-Authorization", "Basic "+auth)
    }

    if err := connectReq.Write(conn); err != nil {
        conn.Close()
        return nil, err
    }

    br := bufio.NewReader(conn)
    resp, err := http.ReadResponse(br, connectReq)
    if err != nil {
        conn.Close()
        return nil, err
    }
    resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        conn.Close()
        return nil, fmt.Errorf("proxy CONNECT %s via %s failed: %s", addr, via.Host, resp.Status)
    }

    return conn, nil
}

// ---- Stable CA persistence ----

func loadOrCreateCA(caDir string) (certPath, keyPath string, cert tls.Certificate) {
    certPath = filepath.Join(caDir, "ca.pem")
    keyPath = filepath.Join(caDir, "ca.key")

    // Load if exists
    if certPEM, e1 := os.ReadFile(certPath); e1 == nil {
        if keyPEM, e2 := os.ReadFile(keyPath); e2 == nil {
            c, err := tls.X509KeyPair(certPEM, keyPEM)
            if err == nil {
                leaf, err2 := x509.ParseCertificate(c.Certificate[0])
                if err2 == nil {
                    c.Leaf = leaf
                    return certPath, keyPath, c
                }
            }
            log.Printf("CA exists but cannot be loaded, regenerating.")
        }
    }

    if err := os.MkdirAll(caDir, 0700); err != nil {
        log.Fatalf("Failed to create CA dir %s: %v", caDir, err)
    }

    priv, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        log.Fatalf("Failed to generate CA key: %v", err)
    }

    serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        log.Fatalf("Failed to generate serial: %v", err)
    }

    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject: pkix.Name{
            CommonName:   "Local MITM CA (light-proxy)",
            Organization: []string{"light-proxy"},
        },
        NotBefore:             time.Now().Add(-time.Hour),
        NotAfter:              time.Now().AddDate(5, 0, 0),
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLenZero:        true,
    }

    der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
    if err != nil {
        log.Fatalf("Failed to create CA cert: %v", err)
    }

    if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
        log.Fatalf("Failed to write CA cert: %v", err)
    }
    if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0600); err != nil {
        log.Fatalf("Failed to write CA key: %v", err)
    }

    c, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        log.Fatalf("Failed to reload CA keypair: %v", err)
    }
    leaf, err := x509.ParseCertificate(c.Certificate[0])
    if err != nil {
        log.Fatalf("Failed to parse CA leaf: %v", err)
    }
    c.Leaf = leaf
    return certPath, keyPath, c
}

func resolveToken(r Rule) (headerName string, token string) {
    headerName = strings.TrimSpace(r.TokenHeader)
    if headerName == "" {
        headerName = "x-proxy-token"
    }
    if strings.TrimSpace(r.Token) != "" {
        return headerName, strings.TrimSpace(r.Token)
    }
    if strings.TrimSpace(r.TokenEnv) != "" {
        return headerName, strings.TrimSpace(os.Getenv(strings.TrimSpace(r.TokenEnv)))
    }
    return headerName, ""
}

func main() {
    portFlag := flag.String("port", "", "Local port (default 8080)")
    configFlag := flag.String("config", "", "YAML config file")
    flag.Parse()

    configPath := *configFlag
    if configPath == "" {
        configPath = os.Getenv("PROXY_CONFIG")
    }
    if configPath == "" {
        log.Fatal("Missing config file: use -config config.yaml or set PROXY_CONFIG")
    }

    listenPort := *portFlag
    if listenPort == "" {
        listenPort = os.Getenv("LOCAL_PROXY_PORT")
    }
    if listenPort == "" {
        listenPort = "8080"
    }

    cfg, err := loadConfig(configPath)
    if err != nil {
        log.Fatalf("Failed to read config: %v", err)
    }

    // Stable CA for MITM
    caCertPath, caKeyPath, ca := loadOrCreateCA(".goproxy")
    goproxy.GoproxyCa = ca
    sum := sha256.Sum256(goproxy.GoproxyCa.Certificate[0])

    // Default upstream proxy
    var defaultProxyURL *url.URL
    if cfg != nil && strings.TrimSpace(cfg.DefaultUpstreamProxy) != "" {
        defaultProxyURL = mustParseProxyURL(cfg.DefaultUpstreamProxy)
    }

    // Transports
    directTransport := http.DefaultTransport.(*http.Transport).Clone()
    directTransport.Proxy = nil

    envTransport := http.DefaultTransport.(*http.Transport).Clone()
    envTransport.Proxy = http.ProxyFromEnvironment

    envRT := goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
        return envTransport.RoundTrip(req)
    })
    directRT := goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
        return directTransport.RoundTrip(req)
    })

    proxyCache := map[string]goproxy.RoundTripper{}

    getRTForProxy := func(proxyAddr string, via *url.URL) (goproxy.RoundTripper, error) {
        if strings.TrimSpace(proxyAddr) == "" || strings.EqualFold(strings.TrimSpace(proxyAddr), "DIRECT") {
            return directRT, nil
        }
        cacheKey := strings.TrimSpace(proxyAddr)
        if via != nil {
            cacheKey += "|via=" + via.String()
        }
        if rt, ok := proxyCache[cacheKey]; ok {
            return rt, nil
        }

        parsed := mustParseProxyURL(proxyAddr)
        if parsed == nil {
            return directRT, nil
        }

        upstreamTransport := http.DefaultTransport.(*http.Transport).Clone()
        upstreamTransport.Proxy = http.ProxyURL(parsed)

        // Chain through default proxy if provided (proxy via proxy)
        if via != nil {
            upstreamTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
                return dialViaProxy(ctx, network, addr, via)
            }
        }

        rt := goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
            return upstreamTransport.RoundTrip(req)
        })
        proxyCache[cacheKey] = rt
        return rt, nil
    }

    var baseRT goproxy.RoundTripper = envRT
    if defaultProxyURL != nil {
        baseRT, err = getRTForProxy(defaultProxyURL.String(), nil)
        if err != nil {
            log.Fatalf("Invalid default upstream proxy: %v", err)
        }
    }

    proxy := goproxy.NewProxyHttpServer()
    proxy.Verbose = false

    // CONNECT: MITM only for rewrite hosts, tunnel otherwise.
    proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
        h := hostOnly(host)
        if shouldMitmHost(cfg, h) {
            return goproxy.MitmConnect, host
        }
        return goproxy.OkConnect, host
    }))

    // HTTP handler (runs for normal HTTP and for HTTPS after MITM)
    proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
        host := hostOnly(req.Host)

        // Choose upstream proxy for this host (rule override > default)
        chosen := ""
        if r, ok := findRule(cfg, host); ok {
            chosen = strings.TrimSpace(r.UpstreamProxy)
        }
        if chosen == "" && cfg != nil {
            chosen = strings.TrimSpace(cfg.DefaultUpstreamProxy)
        }

        if strings.EqualFold(chosen, "DIRECT") {
            chosen = ""
        }
        if chosen != "" && sameProxyURL(chosen, defaultProxyURL) {
            chosen = ""
        }

        if chosen != "" {
            rt, err := getRTForProxy(chosen, defaultProxyURL)
            if err == nil {
                ctx.RoundTripper = rt
            } else {
                log.Printf("Invalid upstream proxy for %s: %v", host, err)
                ctx.RoundTripper = baseRT
            }
        } else {
            ctx.RoundTripper = baseRT
        }

        // Rewrite (if configured)
        if r, ok := findRule(cfg, host); ok {
            if targetURL, ok2 := parseOrigin(r.RewriteTo); ok2 {
                basePath := strings.TrimRight(targetURL.Path, "/")

                // rewrite URL
                req.URL.Scheme = targetURL.Scheme
                req.URL.Host = targetURL.Host
                if basePath != "" {
                    req.URL.Path = basePath + req.URL.Path
                }

                // rewrite host headers
                req.Host = targetURL.Host
                req.Header.Set("Host", targetURL.Host)
                req.Header.Del("Origin")

                // optional token injection
                hdr, tok := resolveToken(r)
                if tok != "" {
                    req.Header.Set(hdr, tok)
                }
            }
        }

        return req, nil
    })

    addr := fmt.Sprintf("127.0.0.1:%s", listenPort)
    log.Printf("Local proxy listening on http://%s", addr)
    log.Printf("Config: %s", configPath)
    log.Printf("CA cert: %s", caCertPath)
    log.Printf("CA key : %s", caKeyPath)
    log.Printf("CA sha256: %x", sum[:])
    if defaultProxyURL != nil {
        log.Printf("Default upstream proxy: %s", defaultProxyURL.String())
    } else {
        log.Printf("Default upstream proxy: (environment)")
    }

    server := &http.Server{Addr: addr, Handler: proxy}
    if err := server.ListenAndServe(); err != nil {
        log.Fatalf("Proxy server failed: %v", err)
    }
}