// Package static holds the assets served at /static/ and the signup page.
// They are embedded so the binary does not depend on its working directory.
package static

import "embed"

//go:embed *.html *.js *.css
var Files embed.FS
