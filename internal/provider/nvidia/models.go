package nvidia

import (
	"sort"
	"strings"

	"glm52-nvidia/internal/models"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
)

// RegistryModels returns cliproxy ModelInfo entries for every playground model.
func RegistryModels() []*cliproxy.ModelInfo {
	registry := models.All()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*cliproxy.ModelInfo, 0, len(ids))
	for _, id := range ids {
		org, _, _ := strings.Cut(id, "/")
		out = append(out, &cliproxy.ModelInfo{
			ID:      id,
			Object:  "model",
			Created: 0,
			OwnedBy: org,
			Type:    providerKey,
		})
	}
	return out
}
