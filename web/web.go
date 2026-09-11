// Package web holds the app portal serves, built into the binary so that
// deploying portal deploys the app. monoweb's build writes dist/.
package web

import "embed"

//go:embed dist
var FS embed.FS
