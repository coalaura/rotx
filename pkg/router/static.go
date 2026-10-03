package router

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coalaura/rotx/pkg/config"
)

func (r *Router) serveStatic(response *Response, request *http.Request, target StaticTarget) error {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")

		return writeStatus(response, request, http.StatusMethodNotAllowed, "Method Not Allowed\n")
	}

	base, exact := target.Route.StaticBase()
	if exact {
		base = filepath.Dir(base)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	defer root.Close()

	name, err := filepath.Rel(base, target.Path)
	if err != nil || !filepath.IsLocal(name) {
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	info, err := root.Stat(name)
	if err != nil {
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	if info.IsDir() {
		indexRoot := root
		indexPrefix := name

		if exact {
			// An exact directory alias is itself the boundary, not its parent.
			directory, openError := root.OpenRoot(name)
			if openError != nil {
				return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
			}

			defer directory.Close()

			indexRoot = directory
			indexPrefix = "."
		}

		if !exact && !strings.HasSuffix(request.URL.Path, "/") {
			redirect := *request.URL

			redirect.Scheme = ""
			redirect.Host = ""
			redirect.Path += "/"
			redirect.RawPath = ""

			http.Redirect(response, request, redirect.RequestURI(), http.StatusMovedPermanently)

			return response.err
		}

		for index := range target.Route.IndexCount() {
			filename := target.Route.Index(index)

			file, metadata, openError := openRegular(indexRoot, filepath.Join(indexPrefix, filename))
			if openError != nil {
				continue
			}

			defer file.Close()

			return r.serveRepresentation(response, request, indexRoot, filepath.Join(indexPrefix, filename), file, metadata)
		}

		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	if strings.HasSuffix(request.URL.Path, "/") {
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	file, metadata, err := openRegular(root, name)
	if err != nil {
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	defer file.Close()

	return r.serveRepresentation(response, request, root, name, file, metadata)
}

func openRegular(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	info, err := root.Stat(name)
	if err != nil {
		return nil, nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, nil, fs.ErrNotExist
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}

	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()

		return nil, nil, fs.ErrNotExist
	}

	return file, info, nil
}

func serveFile(response *Response, request *http.Request, file *os.File, info fs.FileInfo) error {
	err := response.SetMetadata(Metadata{Modified: info.ModTime(), Size: info.Size()})
	if err != nil {
		return err
	}

	var modified time.Time

	if response.route.Cache().Mode == config.CacheEnabled {
		modified = info.ModTime()

		response.setValidators(response.Header())
	}

	// ServeContent handles MIME sniffing, HEAD, byte ranges, and preconditions.
	// A zero modtime keeps cache auto/off from generating Last-Modified.
	request = contentRequest(request)

	http.ServeContent(response, request, info.Name(), modified, file)

	return response.err
}
