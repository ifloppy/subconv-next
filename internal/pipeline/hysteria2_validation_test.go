package pipeline

import (
	"testing"

	"subconv-next/internal/model"
)

func TestHysteria2ObfsValidation(t *testing.T) {
	cases := []struct {
		name         string
		obfs         string
		obfsPassword string
		authPassword string
		want         bool
	}{
		{name: "no obfuscation", authPassword: "auth", want: true},
		{name: "salamander with password", obfs: "salamander", obfsPassword: "obfs-secret", authPassword: "auth", want: true},
		{name: "gecko with password", obfs: "gecko", obfsPassword: "obfs-secret", authPassword: "auth", want: true},
		{name: "salamander missing password", obfs: "salamander", authPassword: "auth"},
		{name: "gecko missing password", obfs: "gecko", authPassword: "auth"},
		{name: "blank obfs password", obfs: "salamander", obfsPassword: "  ", authPassword: "auth"},
		{name: "unsupported obfuscation", obfs: "unknown", obfsPassword: "obfs-secret", authPassword: "auth"},
		{name: "missing authentication", obfs: "salamander", obfsPassword: "obfs-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := model.NodeIR{
				Name: "hy2", Type: model.ProtocolHysteria2,
				Server: "hy.example.com", Port: 443,
				Auth: model.Auth{Password: tc.authPassword},
				Raw:  map[string]interface{}{"obfs": tc.obfs, "obfsPassword": tc.obfsPassword},
			}
			if got := isRenderableNode(node); got != tc.want {
				t.Fatalf("isRenderableNode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildFinalNodesFiltersInvalidHysteria2(t *testing.T) {
	cfg := model.DefaultConfig()
	invalid := model.NormalizeNode(model.NodeIR{
		Name: "invalid-hy2", Type: model.ProtocolHysteria2,
		Server: "hy.example.com", Port: 443,
		Auth: model.Auth{Password: "auth"},
		Raw:  map[string]interface{}{"obfs": "salamander"},
	})
	valid := model.NormalizeNode(model.NodeIR{
		Name: "valid-hy2", Type: model.ProtocolHysteria2,
		Server: "valid.example.com", Port: 443,
		Auth: model.Auth{Password: "auth"},
		Raw:  map[string]interface{}{"obfs": "salamander", "obfsPassword": "secret"},
	})
	finalSet, audit, err := BuildFinalNodes(cfg, model.DefaultNodeState(), []model.NodeIR{invalid, valid})
	if err != nil {
		t.Fatal(err)
	}
	if len(finalSet.Nodes) != 1 || finalSet.Nodes[0].Name != "valid-hy2" {
		t.Fatalf("unexpected final nodes: %#v", finalSet.Nodes)
	}
	if len(audit.ExcludedNodes) != 1 || audit.ExcludedNodes[0].Reason != "invalid_node" {
		t.Fatalf("unexpected audit exclusions: %#v", audit.ExcludedNodes)
	}
}

func TestBuildFinalNodesRevalidatesOverrides(t *testing.T) {
	cfg := model.DefaultConfig()
	node := model.NormalizeNode(model.NodeIR{
		Name: "changed-hy2", Type: model.ProtocolHysteria2,
		Server: "hy.example.com", Port: 443,
		Auth: model.Auth{Password: "auth"},
	})
	state := model.DefaultNodeState()
	state.NodeOverrides = map[string]model.NodeOverride{
		node.ID: {
			Fields: model.NodeOverrideFields{
				Raw: map[string]interface{}{"obfs": "salamander"},
			},
		},
	}
	finalSet, audit, err := BuildFinalNodes(cfg, state, []model.NodeIR{node})
	if err != nil {
		t.Fatal(err)
	}
	if len(finalSet.Nodes) != 0 {
		t.Fatalf("overridden invalid node leaked: %#v", finalSet.Nodes)
	}
	if len(audit.ExcludedNodes) != 1 || audit.ExcludedNodes[0].Reason != "invalid_node" {
		t.Fatalf("override must be excluded: %#v", audit.ExcludedNodes)
	}
}
