// Package registryauth parses Kubernetes imagePullSecrets (docker config
// JSON) and maps their credentials to the registry authorities used by the
// container image clients (go-containerregistry / stereoscope).
package registryauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
)

// dockerConfig mirrors the structure of a kubernetes.io/dockerconfigjson or
// kubernetes.io/dockercfg secret payload.
type dockerConfig struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type dockerAuthEntry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// ParseDockerConfig parses a .dockerconfigjson (or legacy .dockercfg) payload
// and returns the credentials it contains, keyed by normalized registry
// authority.
func ParseDockerConfig(data []byte) (map[string]image.RegistryCredentials, error) {
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse docker config: %w", err)
	}
	if len(cfg.Auths) == 0 {
		// legacy .dockercfg format: the auths map sits at the top level
		legacy := map[string]dockerAuthEntry{}
		if err := json.Unmarshal(data, &legacy); err == nil && len(legacy) > 0 {
			cfg.Auths = legacy
		}
	}

	out := map[string]image.RegistryCredentials{}
	for rawKey, entry := range cfg.Auths {
		username, password := entry.Username, entry.Password
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return nil, fmt.Errorf("decode auth for registry %q: %w", rawKey, err)
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			username = parts[0]
			if len(parts) == 2 {
				password = parts[1]
			}
		}
		if username == "" && password == "" {
			continue
		}
		cred := image.RegistryCredentials{Username: username, Password: password}
		for _, authority := range AuthoritiesForKey(rawKey) {
			cred.Authority = authority
			out[authority] = cred
		}
	}
	return out, nil
}

// AuthoritiesForKey normalizes a registry key found in a docker config (e.g.
// "https://index.docker.io/v1/", "quay.io", "docker.io") into the authority
// strings container clients may use. Docker Hub aliases all map to every
// known spelling so lookups succeed regardless of which form is used.
func AuthoritiesForKey(key string) []string {
	k := strings.TrimSpace(key)
	k = strings.TrimPrefix(k, "https://")
	k = strings.TrimPrefix(k, "http://")
	if u, err := url.Parse("//" + k); err == nil && u.Host != "" {
		k = u.Host
	} else if i := strings.IndexByte(k, '/'); i >= 0 {
		// bare "host/v1/" style keys
		k = k[:i]
	}
	k = strings.ToLower(k)
	if k == "" {
		return nil
	}
	switch k {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "docker.io", "dockerhub.io":
		return []string{"index.docker.io", "docker.io", "registry-1.docker.io"}
	default:
		return []string{k}
	}
}

// AuthorityForImage returns the registry authority for an image reference.
// References without a registry component (e.g. "nginx", "library/nginx")
// refer to Docker Hub.
func AuthorityForImage(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i] // strip digest
	}
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		if first := ref[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			return strings.ToLower(first)
		}
		return "index.docker.io"
	}
	// no slash: either "name[:tag]" or a bare "registry[:port]"
	if i := strings.LastIndexByte(ref, ':'); i >= 0 {
		if before := ref[:i]; strings.Contains(before, ".") || before == "localhost" {
			return strings.ToLower(before)
		}
		return "index.docker.io" // "nginx:1.25" style tag, not a registry
	}
	if strings.Contains(ref, ".") || ref == "localhost" {
		return strings.ToLower(ref)
	}
	return "index.docker.io"
}

// CredentialsFor returns the credentials applicable to the given image
// reference, looked up in the merged authority map. Alias entries (Docker Hub
// spellings) are deduplicated by username/password, preferring the canonical
// authority of the image.
func CredentialsFor(byAuthority map[string]image.RegistryCredentials, imageRef string) []image.RegistryCredentials {
	authority := AuthorityForImage(imageRef)
	order := []string{authority}
	for _, alias := range AuthoritiesForKey(authority) {
		if alias != authority {
			order = append(order, alias)
		}
	}
	var out []image.RegistryCredentials
	seen := map[string]struct{}{}
	for _, key := range order {
		cred, ok := byAuthority[key]
		if !ok {
			continue
		}
		id := cred.Username + "\x00" + cred.Password
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, cred)
	}
	return out
}
