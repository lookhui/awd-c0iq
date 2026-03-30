package netutil

import (
	"math/rand"
	"net/http"
	"time"

	"awd-h1m-pro/internal/config"

	"github.com/imroc/req/v3"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
}

type uaTransport struct {
	base http.RoundTripper
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", RandomUserAgent())
	}
	return t.base.RoundTrip(req)
}

func RandomUserAgent() string {
	return userAgents[rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(userAgents))]
}

func InitClient() *req.Client {
	return NewClient(config.Clone().Shell.Proxy, time.Duration(config.Clone().Shell.Timeout)*time.Second)
}

func NewClient(proxy string, timeout time.Duration) *req.Client {
	client := req.C().SetUserAgent(RandomUserAgent())
	if timeout > 0 {
		client.SetTimeout(timeout)
	}
	if proxy != "" {
		client.SetProxyURL(proxy)
	}
	return client
}
