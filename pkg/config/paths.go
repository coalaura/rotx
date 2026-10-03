package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func validateStaticRoute(route *Route, parsed *scope) error {
	current := parsed.values["root"]
	if current == nil {
		current = parsed.values["alias"]
	}

	if current == nil {
		return nil
	}

	err := validateStaticPath(route.path, route.aliasExact)
	if err != nil {
		return diagnostic(current.Position, "%s %q: %v", current.Name, route.path, err)
	}

	return nil
}

func validateStaticPath(path string, exact bool) error {
	base := path

	if exact {
		base = filepath.Dir(path)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}

	defer root.Close()

	if !exact {
		return nil
	}

	name := filepath.Base(path)

	info, err := root.Stat(name)
	if err != nil {
		return err
	}

	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("exact alias must name a regular file or directory")
	}

	file, err := root.Open(name)
	if err != nil {
		return err
	}

	return file.Close()
}
