package plugin_securelink

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Config holds the plugin configuration.
type Config struct {
	Secret         string   `json:"secret,omitempty"`
	ProtectedPaths []string `json:"protectedPaths,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type secureLink struct {
	name           string
	next           http.Handler
	secret         string
	protectedPaths []string
}

// New creates and returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Secret) == 0 {
		return nil, fmt.Errorf("secret is required")
	}
	if len(config.ProtectedPaths) == 0 {
		return nil, fmt.Errorf("at least one protected path is required")
	}
	return &secureLink{
		name:           name,
		next:           next,
		secret:         config.Secret,
		protectedPaths: config.ProtectedPaths,
	}, nil
}

func (s *secureLink) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, path := range s.protectedPaths {
		path := strings.TrimRight(path, "/")
		if !strings.HasPrefix(req.URL.Path, path) {
			continue
		}
		strSplit := strings.Split(req.URL.Path[len(path):], "/")
		if len(strSplit) < 3 {
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		hash := strSplit[1]
		url := req.URL.Path[len(path)+len(hash)+1:]
		computedHash := md5.Sum([]byte(url + s.secret))
		strComputedHash := hex.EncodeToString(computedHash[:])
		if strComputedHash != hash {
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}
	s.next.ServeHTTP(rw, req)
}
