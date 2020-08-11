package plugin_securelink

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	Secret         string   `json:"secret,omitempty"`
	ProtectedPaths []string `json:"protectedPaths,omitempty"`
	Query          bool     `json:"query,omitempty"`
	CheckExpire    bool     `json:"checkexpire,omitempty"`
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
	query          bool
	checkExpire    bool
}

// New creates and returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Secret) == 0 {
		return nil, fmt.Errorf("secret is required")
	}
	if len(config.ProtectedPaths) == 0 {
		return nil, fmt.Errorf("at least one protected path is required")
	}
	if config.CheckExpire && !config.Query {
		return nil, fmt.Errorf("check expire is only supported with queries")
	}
	return &secureLink{
		name:           name,
		next:           next,
		secret:         config.Secret,
		protectedPaths: config.ProtectedPaths,
		query:          config.Query,
		checkExpire:    config.CheckExpire,
	}, nil
}

func (s *secureLink) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/favicon.ico" {
		for _, path := range s.protectedPaths {
			path := strings.TrimRight(strings.TrimSpace(path), "/")
			if !strings.HasPrefix(req.URL.Path, path) {
				continue
			}

			var expire string
			var hash string
			var url string
			var computedHash [16]byte
			if !s.query {
				strSplit := strings.Split(req.URL.Path[len(path):], "/")
				if len(strSplit) < 3 {
					rw.WriteHeader(http.StatusForbidden)
					return
				}
				hash = strSplit[1]
				url = string([]rune(req.URL.Path)[len([]rune(path))+len([]rune(hash))+len("/"):])
				computedHash = md5.Sum([]byte(url + s.secret))
				req.URL.Path = path + url
				req.RequestURI = req.URL.RequestURI()
			} else {
				hashQuery, ok := req.URL.Query()["md5"]
				if !ok {
					rw.WriteHeader(http.StatusForbidden)
					return
				}
				hash = hashQuery[0]
				url = string([]rune(req.URL.Path)[len([]rune(path)):])
				if s.checkExpire {
					expireQuery, ok := req.URL.Query()["expire"]
					if !ok {
						rw.WriteHeader(http.StatusForbidden)
						return
					}
					expire = expireQuery[0]
					computedHash = md5.Sum([]byte(expire + url + s.secret))

				} else {
					computedHash = md5.Sum([]byte(url + s.secret))
				}
			}

			strComputedHash := hex.EncodeToString(computedHash[:])
			if strComputedHash != hash {
				rw.WriteHeader(http.StatusForbidden)
				return
			}

			if s.checkExpire {
				now := time.Now().Unix()
				expireInt, err := strconv.ParseInt(expire, 10, 64)
				if err != nil {
					rw.WriteHeader(http.StatusForbidden)
					return
				}
				if expireInt < now {
					rw.WriteHeader(http.StatusGone)
					return
				}
			}
		}
	}
	s.next.ServeHTTP(rw, req)
}
