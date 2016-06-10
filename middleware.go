// Package keystone provides a go http middleware for authentication incoming
// http request against Openstack Keystone. It it modelled after the original
// keystone middleware:
// http://docs.openstack.org/developer/keystonemiddleware/middlewarearchitecture.html
//
// The middleware authenticates incoming requests by validating the `X-Auth-Token` header
// and adding additional headers to the incoming request containing the validation result.
// The final authentication/authorization decision is delegated to subsequent http handlers.
package keystone

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Cache provides the interface for cache implementations.
type Cache interface {
	//Set stores a value with the given ttl
	Set(key string, value interface{}, ttl time.Duration)
	//Get retrieves a value previously stored in the cache.
	//value has to be a pointer to a data structure that matches the type previously given to Set
	//The return value indicates if a value was found
	Get(key string, value interface{}) bool
}

//Auth is the entrypoint for creating the middlware
type Auth struct {
	//Keystone v3 endpoint url for validating tokens ( e.g https://some.where:5000/v3)
	Endpoint string
	//User-Agent used for all http request by the middlware. Defaults to go-keystone-middlware/1.0
	UserAgent string
	//A cache implementation the middleware should use for caching tokens. By default no caching is performed.
	TokenCache Cache
	//How long to cache tokens. Defaults to 5 minutes.
	CacheTime time.Duration
}

//Handler returns a http handler for use in a middleware chain.
func (a *Auth) Handler(h http.Handler) http.Handler {
	auth := handler{
		Auth:    a,
		handler: h,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	if a.CacheTime == 0 {
		a.CacheTime = 5 * time.Minute
	}
	if auth.UserAgent == "" {
		auth.UserAgent = "go-keystone-middleware/1.0"
	}
	return &auth
}

type handler struct {
	*Auth
	handler http.Handler
	client  *http.Client
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	filterIncomingHeaders(req)
	req.Header.Set("X-Identity-Status", "Invalid")
	defer h.handler.ServeHTTP(w, req)
	authToken := req.Header.Get("X-Auth-Token")
	if authToken == "" {
		return
	}

	var context *token
	//lookup token in cache
	if h.TokenCache != nil {
		var cachedToken token
		if ok := h.TokenCache.Get(authToken, &cachedToken); ok {
			fmt.Println("Token from cache", cachedToken)
			context = &cachedToken
		}
	}
	if context == nil {
		var err error
		context, err = h.validate(authToken)
		if err != nil {
			//ToDo: How to handle logging, printing to stdout isn't the best thing
			fmt.Println("Failed to validate token. ", err)
			return
		}
		if h.TokenCache != nil {
			ttl := h.CacheTime
			//The expiry date of the token provides an upper bound on the cache time
			if expiresIn := context.ExpiresAt.Sub(time.Now()); expiresIn < h.CacheTime {
				ttl = expiresIn
			}
			h.TokenCache.Set(authToken, *context, ttl)
		}
	}

	req.Header.Set("X-Identity-Status", "Confirmed")
	for k, v := range context.Headers() {
		req.Header.Set(k, v)
	}
}

type domain struct {
	ID      string
	Name    string
	Enabled bool
}

type project struct {
	ID       string
	DomainID string `json:"domain_id"`
	Name     string
	Enabled  bool
	Domain   *domain
}

type token struct {
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	User      struct {
		ID       string
		Name     string
		Email    string
		Enabled  bool
		DomainID string `json:"domain_id"`
		Domain   struct {
			ID   string
			Name string
		}
	}
	Project *project
	Domain  *domain
	Roles   *[]struct {
		ID   string
		Name string
	}
}

func (t token) Valid() bool {
	now := time.Now().Unix()
	return t.IssuedAt.Unix() <= now && now < t.ExpiresAt.Unix()
}

type authResponse struct {
	Error *struct {
		Code    int
		Message string
		Title   string
	}
	Token *token
}

func (t token) Headers() map[string]string {
	headers := make(map[string]string)
	headers["X-User-Id"] = t.User.ID
	headers["X-User-Name"] = t.User.Name
	headers["X-User-Domain-Id"] = t.User.DomainID
	headers["X-User-Domain-Name"] = t.User.Domain.Name

	if project := t.Project; project != nil {
		headers["X-Project-Name"] = project.Name
		headers["X-Project-Id"] = project.ID
		headers["X-Project-Domain-Name"] = project.Domain.Name
		headers["X-Project-Domain-Id"] = project.DomainID

	}

	if domain := t.Domain; domain != nil {
		headers["X-Domain-Id"] = domain.ID
		headers["X-Domain-Name"] = domain.Name
	}

	if roles := t.Roles; roles != nil {
		roleNames := []string{}
		for _, role := range *t.Roles {
			roleNames = append(roleNames, role.Name)
		}
		headers["X-Roles"] = strings.Join(roleNames, ",")

	}

	return headers
}

func (h *handler) validate(token string) (*token, error) {

	req, err := http.NewRequest("GET", h.Endpoint+"/auth/tokens?nocatalog", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("X-Subject-Token", token)
	req.Header.Set("User-Agent", h.UserAgent)

	r, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode >= 400 {
		return nil, errors.New(r.Status)
	}

	var resp authResponse
	if err = json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return nil, err
	}

	if e := resp.Error; e != nil {
		return nil, fmt.Errorf("%s : %s", r.Status, e.Message)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", r.Status)
	}
	if resp.Token == nil {
		return nil, errors.New("Response didn't contain token context")
	}
	if !resp.Token.Valid() {
		return nil, errors.New("Returned token is not valid")

	}

	return resp.Token, nil
}

func filterIncomingHeaders(req *http.Request) {
	req.Header.Del("X-Identity-Status")
	req.Header.Del("X-Service-Identity-Status")

	req.Header.Del("X-Domain-Id")
	req.Header.Del("X-Service-Domain-Id")

	req.Header.Del("X-Domain-Name")
	req.Header.Del("X-Service-Domain-Name")

	req.Header.Del("X-Project-Id")
	req.Header.Del("X-Service-Project-Id")

	req.Header.Del("X-Project-Name")
	req.Header.Del("X-Service-Project-Name")

	req.Header.Del("X-Project-Domain-Id")
	req.Header.Del("X-Service-Project-Domain-Id")

	req.Header.Del("X-Project-Domain-Name")
	req.Header.Del("X-Service-Project-Domain-Name")

	req.Header.Del("X-User-Id")
	req.Header.Del("X-Service-User-Id")

	req.Header.Del("X-User-Name")
	req.Header.Del("X-Service-User-Name")

	req.Header.Del("X-User-Domain-Id")
	req.Header.Del("X-Service-User-Domain-Id")

	req.Header.Del("X-User-Domain-Name")
	req.Header.Del("X-Service-User-Domain-Name")

	req.Header.Del("X-Roles")
	req.Header.Del("X-Service-Roles")

	req.Header.Del("X-Servie-Catalog")

	//deprecated Headers
	req.Header.Del("X-Tenant-Id")
	req.Header.Del("X-Tenant")
	req.Header.Del("X-User")
	req.Header.Del("X-Role")
}
