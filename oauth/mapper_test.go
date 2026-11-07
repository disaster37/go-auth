package oauth

import (
	"reflect"
	"testing"
)

func TestNewGroupMapper(t *testing.T) {
	if _, err := NewGroupMapper([]GroupMappingRule{{Pattern: ""}}); err == nil {
		t.Fatal("empty pattern must error")
	}
	if _, err := NewGroupMapper([]GroupMappingRule{{Pattern: "("}}); err == nil {
		t.Fatal("invalid pattern must error")
	}
	m, err := NewGroupMapper(nil)
	if err != nil {
		t.Fatalf("nil rules: %v", err)
	}
	if m.Active() {
		t.Fatal("nil rules must be inactive")
	}
}

func TestGroupMapperMap(t *testing.T) {
	m, err := NewGroupMapper([]GroupMappingRule{
		{Pattern: `^dev-(.*)$`, Replacement: "engineering-$1"},
		{Pattern: `^ops$`, Replacement: "operations"},
	})
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}
	if !m.Active() {
		t.Fatal("expected active")
	}
	got := m.Map([]string{"dev-web", "ops", "unmatched", "dev-web"})
	want := []string{"engineering-web", "operations"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Map=%v want %v", got, want)
	}
	// Identity when no rules.
	identity, _ := NewGroupMapper(nil)
	if got := identity.Map([]string{"a", "a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("identity Map=%v", got)
	}
}

func TestMapIfActive(t *testing.T) {
	active, _ := NewGroupMapper([]GroupMappingRule{{Pattern: `^x$`, Replacement: "y"}})
	if got := active.MapIfActive([]string{"x"}); !reflect.DeepEqual(got, []string{"y"}) {
		t.Fatalf("active MapIfActive=%v", got)
	}
	inactive, _ := NewGroupMapper(nil)
	if got := inactive.MapIfActive([]string{"x"}); got != nil {
		t.Fatalf("inactive MapIfActive=%v", got)
	}
}

func TestGroupMapperEmptyReplacementDropped(t *testing.T) {
	m, _ := NewGroupMapper([]GroupMappingRule{{Pattern: `^x$`, Replacement: ""}})
	if got := m.Map([]string{"x"}); len(got) != 0 {
		t.Fatalf("empty replacement must be dropped, got %v", got)
	}
}
