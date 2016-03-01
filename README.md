#Vulcan session auth

Plugin for vulcan that does basic auth and maintains a cookie session of one day. The seed for secure cookies is kept in memory and therefore restart of vulcan will invalidate all sessions.

Based on https://github.com/mailgun/vulcand-auth/ with sessions added on top.

###Usage

`etcdctl set /vulcand/frontends/f1/middlewares/auth1 '{"Type": "sauth", "Middleware":{"Credentials": "foo:bar,us3r:p@ss"}}'`

This plugin gets used by ft-vulcan build.

