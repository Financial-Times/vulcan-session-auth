package sauth

// Note that I import the versions bundled with vulcand. That will make our lives easier, as we'll use exactly the same versions used
// by vulcand. We are escaping dependency management troubles thanks to Godep.
import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"

	"github.com/mailgun/vulcand/plugin"
	"github.com/mailgun/vulcand/vendor/github.com/codegangsta/cli"
)

const Type = "sauth"

var store = newStore()

func newStore() *sessions.CookieStore {
	storeSeed, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		fmt.Errorf("Could not initialise CookieStore: %v\n", err)
	}
	store := sessions.NewCookieStore([]byte(storeSeed.String()))
	store.MaxAge(86400) // 1 day
	return store
}

func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to recreate middleware from another one (this is for deserialization)
		FromCli:   FromCli,    // Tells vulcand how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcand will add this flags to middleware specific command line tool
	}
}

// AuthMiiddleware struct holds configuration parameters and is used to
// serialize/deserialize the configuration from storage engines.
type AuthMiddleware struct {
	// CSV formatted string
	// e.g:
	// "foo,bar
	// username,password
	// us3r,p@ssw0rd1"
	Credentials string
	authKeys    []authKey
}

type authKey struct {
	username string
	password string
}

// Auth middleware handler
type AuthHandler struct {
	cfg  AuthMiddleware
	next http.Handler
}

// This function will be called each time the request hits the location with this middleware activated
func (a *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Check session
	session, _ := store.Get(r, "session")
	if session.Values["active"] != "true" {
		//No session - try to log in
		username, password, ok := r.BasicAuth()
		// Reject the request by writing forbidden response
		if !ok || !isAuthorized(a.cfg, username, password) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Please log in\"")
			return
		}
		session.Values["active"] = "true"
		// Save all sessions.
		sessions.Save(r, w)
	}
	// Pass the request to the next middleware in chain
	a.next.ServeHTTP(w, r)
}

// This function is optional but handy, used to check input parameters when creating new middlewares
func New(credentials string) (*AuthMiddleware, error) {
	var authKeys []authKey
	for _, entry := range strings.Split(credentials, "\n") {
		key := strings.Split(entry, ",")
		if len(key) != 2 || key[0] == "" || key[1] == "" {
			log.Printf("WARN  - Ignoring entry: [%v]", entry)
			continue
		}
		authKeys = append(authKeys, authKey{username: key[0], password: key[1]})
	}
	if len(authKeys) == 0 {
		return nil, fmt.Errorf("No valid credential was provided")
	}

	return &AuthMiddleware{Credentials: credentials, authKeys: authKeys}, nil
}

// This function is important, it's called by vulcand to create a new handler from the middleware config and put it into the
// middleware chain. Note that we need to remember 'next' handler to call
func (c *AuthMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &AuthHandler{next: next, cfg: *c}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (c *AuthMiddleware) String() string {
	var desc string
	for _, key := range c.authKeys {
		desc = desc + fmt.Sprintf("username=%v, pass=%v\n", key.username, "********")
	}
	return desc
}

func isAuthorized(c AuthMiddleware, username, password string) bool {
	for _, c := range c.authKeys {
		if c.username == username && c.password == password {
			return true
		}
	}
	return false
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(c AuthMiddleware) (plugin.Middleware, error) {
	return New(c.Credentials)
}

// FromCli constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	return New(c.String("credentials"))
}

// CliFlags will be used by Vulcand construct help and CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"credentials, c", "", `List of auth key pairs in CSV format, e.g. "foo,bar\nusername,password\nus3r,p@ssw0rd1`, ""},
	}
}
