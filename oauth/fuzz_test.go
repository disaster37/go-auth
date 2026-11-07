package oauth

import "testing"

func FuzzGroupMapper(f *testing.F) {
	f.Add("dev-web")
	f.Add("")
	f.Fuzz(func(t *testing.T, group string) {
		m, err := NewGroupMapper([]GroupMappingRule{{Pattern: `^dev-(.*)$`, Replacement: "eng-$1"}})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		_ = m.Map([]string{group})
	})
}
