package renderer

import (
	"testing"

	"gopkg.in/yaml.v3"
	"subconv-next/internal/model"
)

func TestClientFingerprintsReplaceDeprecatedGlobalOption(t *testing.T) {
	nodes := []model.NodeIR{
		{Name: "vmess-tls", Type: model.ProtocolVMess, Server: "vm.example.com", Port: 443, Auth: model.Auth{UUID: "00000000-0000-0000-0000-000000000001"}, TLS: model.TLSOptions{Enabled: true}},
		{Name: "vless-explicit", Type: model.ProtocolVLESS, Server: "vl.example.com", Port: 443, Auth: model.Auth{UUID: "00000000-0000-0000-0000-000000000002"}, TLS: model.TLSOptions{Enabled: true, ClientFingerprint: "firefox"}},
		{Name: "trojan", Type: model.ProtocolTrojan, Server: "tr.example.com", Port: 443, Auth: model.Auth{Password: "secret"}},
		{Name: "trojan-explicit", Type: model.ProtocolTrojan, Server: "tr2.example.com", Port: 443, Auth: model.Auth{Password: "secret"}, TLS: model.TLSOptions{ClientFingerprint: "safari"}},
		{Name: "anytls", Type: model.ProtocolAnyTLS, Server: "any.example.com", Port: 443, Auth: model.Auth{Password: "secret"}},
		{Name: "vmess-plain", Type: model.ProtocolVMess, Server: "plain.example.com", Port: 80, Auth: model.Auth{UUID: "00000000-0000-0000-0000-000000000003"}},
		{Name: "ss", Type: model.ProtocolSS, Server: "ss.example.com", Port: 443, Auth: model.Auth{Password: "secret"}, Raw: map[string]interface{}{"method": "aes-256-gcm"}},
	}
	opts := model.DefaultRenderOptions()
	opts.GlobalClientFingerprint = "chrome"
	got, err := RenderMihomo(nodes, opts)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		GlobalClientFingerprint interface{} `yaml:"global-client-fingerprint"`
		Proxies                 []struct {
			Name              string `yaml:"name"`
			ClientFingerprint string `yaml:"client-fingerprint"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.GlobalClientFingerprint != nil {
		t.Fatalf("deprecated global-client-fingerprint leaked into YAML: %s", got)
	}
	want := map[string]string{
		"vmess-tls": "chrome", "vless-explicit": "firefox",
		"trojan": "chrome", "trojan-explicit": "safari",
		"anytls": "chrome", "vmess-plain": "", "ss": "",
	}
	for _, proxy := range parsed.Proxies {
		if got, ok := want[proxy.Name]; !ok || proxy.ClientFingerprint != got {
			t.Errorf("%s client-fingerprint = %q, want %q", proxy.Name, proxy.ClientFingerprint, got)
		}
		delete(want, proxy.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing proxies: %#v", want)
	}
}

func TestClientFingerprintCanBeDisabledForMissingValues(t *testing.T) {
	nodes := []model.NodeIR{{
		Name: "trojan", Type: model.ProtocolTrojan,
		Server: "example.com", Port: 443, Auth: model.Auth{Password: "secret"},
	}}
	opts := model.DefaultRenderOptions()
	opts.GlobalClientFingerprint = ""
	got, err := RenderMihomo(nodes, opts)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Proxies []struct {
			ClientFingerprint string `yaml:"client-fingerprint"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Proxies) != 1 || parsed.Proxies[0].ClientFingerprint != "" {
		t.Fatalf("unexpected default fingerprint: %s", got)
	}
}
