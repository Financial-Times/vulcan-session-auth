package sauth

import (
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/mailgun/vulcand/plugin"
	"github.com/mailgun/vulcand/vendor/github.com/codegangsta/cli"
	"github.com/vulcand/oxy/testutils"
	. "gopkg.in/check.v1"

	"testing"
)

func TestCL(t *testing.T) { TestingT(t) }

type AuthSuite struct {
}

var _ = Suite(&AuthSuite{})

// One of the most important tests:
// Make sure the RateLimit spec is compatible and will be accepted by middleware registry
func (s *AuthSuite) TestSpecIsOK(c *C) {
	c.Assert(plugin.NewRegistry().AddSpec(GetSpec()), IsNil)
}

func (s *AuthSuite) TestNew(c *C) {
	cl, err := New("user,pass")

	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	c.Assert(cl.String(), Not(Equals), "")

	out, err := cl.NewHandler(nil)
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *AuthSuite) TestNewBadParams(c *C) {
	// Empty pass
	_, err := New("user,")
	c.Assert(err, NotNil)

	// Empty user
	_, err = New(",pass")
	c.Assert(err, NotNil)
}

func (s *AuthSuite) TestFromOther(c *C) {
	a, err := New("user,pass")
	c.Assert(a, NotNil)
	c.Assert(err, IsNil)

	out, err := FromOther(*a)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, a)
}

func (s *AuthSuite) TestAuthFromCli(c *C) {
	app := cli.NewApp()
	app.Name = "test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		out, err := FromCli(ctx)
		c.Assert(out, NotNil)
		c.Assert(err, IsNil)

		a := out.(*AuthMiddleware)
		c.Assert(a.authKeys[0].password, Equals, "pass1")
		c.Assert(a.authKeys[0].username, Equals, "user1")
	}
	app.Flags = CliFlags()
	app.Run([]string{"test", "--credentials=user1,pass1"})
	c.Assert(executed, Equals, true)
}

func (s *AuthSuite) TestRequestSuccess(c *C) {
	a := &AuthMiddleware{authKeys: []authKey{{username: "aladdin", password: "open sesame"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	_, body, err := testutils.Get(srv.URL, testutils.BasicAuth(a.authKeys[0].username, a.authKeys[0].password))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "treasure")
}

func (s *AuthSuite) TestRequestBadPassword(c *C) {
	a := &AuthMiddleware{authKeys: []authKey{{username: "aladdin", password: "open sesame"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	// bad pass
	re, _, err := testutils.Get(srv.URL, testutils.BasicAuth(a.authKeys[0].username, "open please"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusUnauthorized)

	// missing header
	re, _, err = testutils.Get(srv.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusUnauthorized)

	// malformed header
	re, _, err = testutils.Get(srv.URL, testutils.Header("Authorization", "blablabla="))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusUnauthorized)
}
