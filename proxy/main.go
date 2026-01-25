package main

import (
    "context"
    "flag"
    "fmt"
    "gopkg.in/yaml.v3"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

type Config struct {
    Listen     string `yaml:"listen"`
    ProxyToken string `yaml:"proxy_token"`
    Rules      []Rule `yaml:"rules"`
}

type Rule struct {
    FromHost string `yaml:"from_host"` // api.openai.com
    ToOrigin string `yaml:"to_origin"` // https://reverse-proxy-light.pages.com
}

func main() {
    var cfgPath string
    flag.StringVar(&cfgPath, "config", "proxy.yaml", "config path")
    flag.Parse()

    cfg := mustLoad(cfgPath)
    if cfg.Listen == "" {
        cfg.Listen = "127.0.0.1:18080"
    }

    srv := &http.Server{
        Addr: cfg.Listen,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // We do NOT support CONNECT here because it would hide HTTP headers/path.
            // If your client uses CONNECT for https, this proxy cannot inject x-proxy-token.
            if r.Method == http.MethodConnect {
                http.Error(w, "CONNECT not supported (client must use explicit proxy requests)", http.StatusMethodNotAllowed)
                return
            }
            handleProxy(w, r, cfg)
        }),
    }

    log.Printf("listening on http://%s", cfg.Listen)
    log.Fatal(srv.ListenAndServe())
}

func mustLoad(path string) *Config {
    b, err := os.ReadFile(path)
    if err != nil {
        log.Fatal(err)
    }
    var c Config
    if err := yaml.Unmarshal(b, &c); err != nil {
        log.Fatal(err)
    }
    return &c
}

func matchRule(host string, rules []Rule) *Rule {
    h := host
    if strings.Contains(h, ":") {
        if hh, _, err := net.SplitHostPort(h); err == nil {
            h = hh
        }
    }
    for i := range rules {
        if strings.EqualFold(h, rules[i].FromHost) {
            return &rules[i]
        }
    }
    return nil
}

func handleProxy(w http.ResponseWriter, r *http.Request, cfg *Config) {
    // In proxy mode, clients often send absolute URL in r.URL (Scheme+Host set).
    // Sometimes they send origin-form + Host header; we handle both.

    reqURL := *r.URL
    if reqURL.Scheme == "" {
        // assume https for OpenAI-like targets; otherwise http
        reqURL.Scheme = "https"
    }
    if reqURL.Host == "" {
        reqURL.Host = r.Host
    }

    rule := matchRule(reqURL.Host, cfg.Rules)
    if rule == nil {
        http.Error(w, "no rule for host: "+reqURL.Host, http.StatusBadGateway)
        return
    }

    to, err := url.Parse(rule.ToOrigin)
    if err != nil {
        http.Error(w, "bad to_origin", http.StatusInternalServerError)
        return
    }

    // Rewrite destination: keep path+query
    outURL := *to
    outURL.Path = singleJoin(to.Path, reqURL.Path)
    outURL.RawQuery = reqURL.RawQuery

    outReq := r.Clone(context.Background())
    outReq.RequestURI = ""
    outReq.URL = &outURL

    // IMPORTANT: set Host to reverse-proxy host (TLS SNI/Host header)
    outReq.Host = to.Host

    // Add auth header expected by your Cloudflare Pages function
    outReq.Header.Set("x-proxy-token", cfg.ProxyToken)

    // Remove hop-by-hop
    removeHopByHop(outReq.Header)

    tr := &http.Transport{
        Proxy: nil,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
    }

    resp, err := tr.RoundTrip(outReq)
    if err != nil {
        http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copy back response
    removeHopByHop(resp.Header)
    copyHeader(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}

func singleJoin(a, b string) string {
    if a == "" {
        return b
    }
    if b == "" {
        return a
    }
    aslash := strings.HasSuffix(a, "/")
    bslash := strings.HasPrefix(b, "/")
    switch {
    case aslash && bslash:
        return a + b[1:]
    case !aslash && !bslash:
        return a + "/" + b
    default:
        return a + b
    }
}

var hopByHop = map[string]bool{
    "connection":          true,
    "keep-alive":          true,
    "proxy-authenticate":  true,
    "proxy-authorization": true,
    "te":                  true,
    "trailer":             true,
    "transfer-encoding":   true,
    "upgrade":             true,
}

func removeHopByHop(h http.Header) {
    for k := range h {
        if hopByHop[strings.ToLower(k)] {
            h.Del(k)
        }
    }
    // Also honor "Connection: header1, header2"
    if c := h.Get("Connection"); c != "" {
        for _, f := range strings.Split(c, ",") {
            h.Del(strings.TrimSpace(f))
        }
        h.Del("Connection")
    }
}

func copyHeader(dst, src http.Header) {
    for k, vv := range src {
        for _, v := range vv {
            dst.Add(k, v)
        }
    }
}