# Jenkins URL Auth SSO Plugin

- License: [MIT License](LICENSE.txt)
- Wiki: [URL Auth SSO Plugin wiki page](https://wiki.jenkins-ci.org/display/JENKINS/URL+Auth+SSO+Plugin)
- Latest Build: [Latest Jenkins Build](https://ci.pgmann.cf/job/url-auth-sso-plugin/lastSuccessfulBuild)
- Demo: [Demo Server](https://ci.pgmann.cf/)

# How it works

This plugin allows users to be logged in to Jenkins automatically when they are logged into another site.

1. This plugin authenticates users via a shared identifying cookie. This is likely to be a session ID (e.g. `PHPSESSID`) which is shared between the `Target URL`'s domain and Jenkins' domain.
2. The identifying cookie **must** be shared between the two sites. This is possible for subdomains by setting a cookie's domain to `.domain.com` (note the leading dot).
3. When a user requests a Jenkins page, their `Cookie` header is sent to the configurable `Target URL` as a `GET` request, which authenticates the user and sends back a JSON response with the `user_name`, `display_name` and `public_email` with status `200 OK`. All JSON keys are configurable.
4. If the server at the `Target URL` cannot authenticate the user with the sent cookies, it will respond with error code `401 Unauthorized`. If you want to see this in action, try [my version](https://pgmann.cf/sso/data).
5. The user will be authenticated in Jenkins if possible. Their username, display name and email will be set using the data from the JSON request.

Because authentication takes place via cookie, this plugin is designed for sites where the user is already logged into a trusted, parent site. It would be a security risk to share sensitive cookies with third party sites.
