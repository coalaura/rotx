package config

import (
	"net/http"
	"strings"
	"testing"
)

func TestCompiledHeaderOperations(t *testing.T) {
	fixture := newIdentityFixture(t)

	compiled := compileFixture(t, fixture, fixture.config(`
		header_unset example;
		header_set example test1;
		header_set example test2;
		header_add example test3;
		location /unset { header_unset Example; }
		location /extend { header_add Example test4; }
	`))

	headers := make(http.Header)

	headers.Set("Example", "original")

	route := compiled.Match(fixture.name, "/other")

	route.ApplyHeaders(headers)

	if strings.Join(headers.Values("Example"), ",") != "test2,test3" {
		t.Fatalf("ordered operations produced %#v", headers)
	}

	headers["Example"][0] = "mutated"

	route.ApplyHeaders(headers)

	if headers.Get("Example") != "test2" {
		t.Fatal("response header mutation changed compiled policy")
	}

	compiled.Match(fixture.name, "/extend").ApplyHeaders(headers)

	if strings.Join(headers.Values("Example"), ",") != "test2,test3,test4" {
		t.Fatalf("child add failed: %#v", headers)
	}

	compiled.Match(fixture.name, "/unset").ApplyHeaders(headers)

	if len(headers.Values("Example")) != 0 {
		t.Fatal("child unset failed")
	}

	route.ApplyHeaders(headers)

	allocations := testing.AllocsPerRun(100, func() {
		route.ApplyHeaders(headers)
	})

	if allocations != 0 {
		t.Fatalf("header policy did not reuse response storage: %v allocations", allocations)
	}
}
