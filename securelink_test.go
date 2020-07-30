package plugin_securelink

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		desc           string
		secret         string
		protectedPaths []string
		expErr         bool
	}{
		{
			desc:           "should return no error",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			expErr:         false,
		},
		{
			desc:           "should return an error",
			secret:         "",
			protectedPaths: []string{"/video/", "/playlist"},
			expErr:         true,
		},
		{
			desc:           "should return an error",
			secret:         "enigma",
			protectedPaths: []string{},
			expErr:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &Config{
				Secret:         test.secret,
				ProtectedPaths: test.protectedPaths,
			}

			if _, err := New(context.Background(), nil, cfg, "securelink"); test.expErr && err == nil {
				t.Errorf("expected error on bad parameters")
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		desc           string
		secret         string
		protectedPaths []string
		reqPath        string
		expNextCall    bool
		expStatusCode  int
	}{
		{
			desc:           "should return ok status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/foo",
			expNextCall:    true,
			expStatusCode:  http.StatusOK,
		},
		{
			desc:           "should return ok status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/",
			expNextCall:    true,
			expStatusCode:  http.StatusOK,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video/",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video/foo",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video/foo/",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video/foo/bar",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/playlist/foo/bar",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
		{
			desc:           "should return ok status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/video/26d001f85813609efb213b28fae45950/foo/bar",
			expNextCall:    true,
			expStatusCode:  http.StatusOK,
		},
		{
			desc:           "should return ok status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/playlist/26d001f85813609efb213b28fae45950/foo/bar",
			expNextCall:    true,
			expStatusCode:  http.StatusOK,
		},
		{
			desc:           "should return forbidden status",
			secret:         "enigma",
			protectedPaths: []string{"/video/", "/playlist"},
			reqPath:        "/playlist/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/foo/bar",
			expNextCall:    false,
			expStatusCode:  http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &Config{
				Secret:         test.secret,
				ProtectedPaths: test.protectedPaths,
			}

			nextCall := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				nextCall = true
			})

			handler, err := New(context.Background(), next, cfg, "securelink")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			url := fmt.Sprintf("http://localhost%s", test.reqPath)
			req := httptest.NewRequest(http.MethodGet, url, nil)

			handler.ServeHTTP(recorder, req)

			if nextCall != test.expNextCall {
				t.Errorf("next handler should not be called")
			}

			if recorder.Result().StatusCode != test.expStatusCode {
				t.Errorf("got status code %d, want %d", recorder.Code, test.expStatusCode)
			}
		})
	}
}
