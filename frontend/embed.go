// Package frontend exposes the built web console (frontend/dist) as an
// embedded filesystem so the vproxy binary is fully self-contained.
//
// frontend/dist is produced by `task build-frontend` and is not committed;
// only dist/.gitkeep is tracked so this package always compiles.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// DistFS returns the embedded dist directory rooted at its top level.
func DistFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return distFS
	}
	return sub
}
