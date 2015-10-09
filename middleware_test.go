package keystone

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	ok         = "ok\n"
	notAllowed = "Method not allowed\n"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte(ok))
})

func newRequest(method, url string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

func identityMock(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
}

func checkHeaders(t *testing.T, headers map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, expected := range headers {
			if v := r.Header.Get(key); v != expected {
				t.Errorf("Expected header %s to be %q, got %q", key, expected, v)
			}
		}
		w.Write([]byte(ok))
	})
}

func TestSpoofProtection(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Add("X-Identity-Status", "Confirmed")
	req.Header.Add("X-Project-Id", "p-1234")
	req.Header.Add("X-Domain-Id", "d-1234")

	h := checkHeaders(t, map[string]string{
		"X-Identity-Status": "Invalid",
		"X-Project-Id":      "",
		"X-Domain-Id":       "",
	})

	Handler(h, "", nil).ServeHTTP(rec, req)

	//Validate that checking middleware was called
	if body := rec.Body.String(); body != ok {
		t.Fatalf("wrong body, got %q want %q", body, ok)
	}
}

func TestNoToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status := r.Header.Get("X-Identity-Status"); status != "Invalid" {
			t.Fatalf("X-Identity-Status header got %q, expected %q", status, "Invalid")
		}
		w.Write([]byte(ok))
	})

	Handler(h, "", nil).ServeHTTP(rec, req)

	//Validate that checking middleware was called
	if body := rec.Body.String(); body != ok {
		t.Fatalf("wrong body, got %q want %q", body, ok)
	}

}

func TestUnscopedToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Set("X-Auth-Token", "1234")
	idServer := identityMock(200, `
{
  "token": {
    "expires_at": "2020-10-08T08:40:33.100Z",
    "issued_at": "2015-10-08T07:40:33.099Z",
    "methods": [
      "password"
    ],
    "user": {
      "id": "u-42e54ca0c",
      "name": "arc",
      "description": "Arc Test",
      "email": null,
      "enabled": true,
      "domain_id": "o-testdomain",
      "default_project_id": null,
      "domain": {
        "id": "o-testdomain",
        "name": "testdomain"
      }
    }
  }
}
	`)
	defer idServer.Close()
	h := checkHeaders(t, map[string]string{
		"X-Identity-Status":  "Confirmed",
		"X-User-Id":          "u-42e54ca0c",
		"X-User-Domain-Id":   "o-testdomain",
		"X-User-Domain-Name": "testdomain",
		"X-Roles":            "",
	})
	Handler(h, idServer.URL, nil).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("wrong code, got %d want %d", rec.Code, 200)
	}
	if body := rec.Body.String(); body != ok {
		t.Fatalf("wrong body, got %q want %q", body, ok)
	}
}

func TestProjectScopedToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Set("X-Auth-Token", "1234")
	idServer := identityMock(200, `
{
  "token": {
    "expires_at": "2020-10-09T15:09:12.355Z",
    "issued_at": "2015-10-08T15:09:12.355Z",
    "user": {
      "id": "u-42e54ca0c",
      "name": "arc",
      "description": "Arc Test",
      "email": null,
      "enabled": true,
      "domain_id": "o-testdomain",
      "default_project_id": null,
      "domain": {
        "id": "o-testdomain",
        "name": "testdomain"
      }
    },
    "project": {
      "uri": "/projects/p-d61611de1",
      "id": "p-d61611de1",
      "domain_id": "o-testdomain",
      "name": "Arc",
      "description": "Arc authentication testbed",
      "enabled": true,
      "parent_id": null,
      "domain": {
        "uri": "/domains/o-testdomain",
        "id": "o-testdomain",
        "name": "testdomain",
        "enabled": true
      }
    },
    "roles": [
      {
        "id": "r-member",
        "name": "member"
      }
    ]
  }
}
	`)
	defer idServer.Close()
	h := checkHeaders(t, map[string]string{
		"X-Identity-Status":     "Confirmed",
		"X-Domain-Id":           "",
		"X-Domain-Name":         "",
		"X-Project-Name":        "Arc",
		"X-Project-Id":          "p-d61611de1",
		"X-Project-Domain-Name": "testdomain",
		"X-Project-Domain-Id":   "o-testdomain",
		"X-Roles":               "member",
	})
	Handler(h, idServer.URL, nil).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("wrong code, got %d want %d", rec.Code, 200)
	}
	if body := rec.Body.String(); body != ok {
		t.Fatalf("wrong body, got %q want %q", body, ok)
	}
}

func TestDomainScopedToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Set("X-Auth-Token", "1234")
	idServer := identityMock(200, `
{
  "token": {
    "expires_at": "2015-10-09T15:09:11.727Z",
    "issued_at": "2015-10-08T15:09:11.727Z",
    "methods": [
      "password"
    ],
    "user": {
      "id": "u-42e54ca0c",
      "name": "arc",
      "email": null,
      "enabled": true,
      "domain_id": "o-testdomain",
      "default_project_id": null,
      "domain": {
        "id": "o-testdomain",
        "name": "testdomain"
      }
    },
    "domain": {
      "uri": "/domains/o-testdomain",
      "id": "o-testdomain",
      "name": "testdomain",
      "enabled": true
    },
    "roles": [
      {
        "id": "r-member",
        "name": "member"
      },
			{
				"id": "r-blafasel",
				"name": "blafasel"
			}
    ]
  }
}
	`)
	defer idServer.Close()
	h := checkHeaders(t, map[string]string{
		"X-Identity-Status": "Confirmed",
		"X-Project-Id":      "",
		"X-Domain-Id":       "o-testdomain",
		"X-Domain-Name":     "testdomain",
		"X-Roles":           "member,blafasel",
	})
	Handler(h, idServer.URL, nil).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("wrong code, got %d want %d", rec.Code, 200)
	}
	if body := rec.Body.String(); body != ok {
		t.Fatalf("wrong body, got %q want %q", body, ok)
	}

}

type cacheMock map[string]interface{}

func (c cacheMock) Get(k string) (v interface{}, ok bool) {
	v, ok = c[k]
	return
}

func (c *cacheMock) Set(k string, v interface{}, _ time.Duration) {
	urks := *c
	urks[k] = v
}

func TestTokenCacheRead(t *testing.T) {

	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Set("X-Auth-Token", "1234")
	cache := cacheMock{"1234": token{}}

	h := checkHeaders(t, map[string]string{
		"X-Identity-Status": "Confirmed",
	})

	Handler(h, "http://blafasel", &cache).ServeHTTP(rec, req)

}

func TestTokenCacheWrite(t *testing.T) {
	cache := cacheMock{}
	rec := httptest.NewRecorder()
	req := newRequest("GET", "/foo")
	req.Header.Set("X-Auth-Token", "1234")
	idServer := identityMock(200, `
{
  "token": {
    "expires_at": "2015-10-09T15:09:11.727Z",
    "issued_at": "2015-10-08T15:09:11.727Z"
  }
}
	`)
	defer idServer.Close()
	h := checkHeaders(t, map[string]string{
		"X-Identity-Status": "Confirmed",
	})
	Handler(h, idServer.URL, &cache).ServeHTTP(rec, req)
	v, ok := cache["1234"]
	if !ok {
		t.Fatal("token was not cached")
	}
	if tok, ok := v.(token); !ok || tok.ExpiresAt != "2015-10-09T15:09:11.727Z" {
		t.Fatal("cached element is not of correct type or value")
	}

}
