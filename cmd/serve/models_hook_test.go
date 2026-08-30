package main

import (
	"context"
	"testing"

	"glm52-nvidia/internal/provider/nvidia"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestNvidiaModelHookReregisters(t *testing.T) {
	models := nvidia.RegistryModels()
	if len(models) == 0 {
		t.Fatal("empty registry models")
	}
	const clientID = "nvidia-local.json"
	reg := cliproxy.GlobalModelRegistry()
	reg.RegisterClient(clientID, nvidiaProvider, models)
	t.Cleanup(func() { reg.UnregisterClient(clientID) })

	reg.UnregisterClient(clientID)
	hook := &nvidiaModelHook{catalog: newModelCatalog(models)}
	hook.OnModelsUnregistered(context.Background(), nvidiaProvider, clientID)

	got := reg.GetAvailableModelsByProvider(nvidiaProvider)
	if len(got) == 0 {
		t.Fatal("models not restored after unregister hook")
	}
}

func TestBindNvidiaRuntimeRegistersExecutor(t *testing.T) {
	models := nvidia.RegistryModels()
	core := coreauth.NewManager(nil, nil, nil)
	exec := nvidia.NewExecutor(nvidia.Options{})
	if _, err := core.Register(coreauth.WithSkipPersist(context.Background()), &coreauth.Auth{
		ID:       "nvidia-test",
		Provider: nvidiaProvider,
		Status:   coreauth.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	n := bindNvidiaRuntime(core, exec, models)
	if n != 1 {
		t.Fatalf("auth count=%d", n)
	}
	got, ok := core.Executor(nvidiaProvider)
	if !ok || got != exec {
		t.Fatalf("executor not bound: ok=%v got=%T", ok, got)
	}
	t.Cleanup(func() {
		cliproxy.GlobalModelRegistry().UnregisterClient("nvidia-test")
	})
}

func TestBindNvidiaRuntimePrimesModelsBeforeAuthLoad(t *testing.T) {
	models := nvidia.RegistryModels()
	reg := cliproxy.GlobalModelRegistry()
	reg.UnregisterClient(nvidiaAuthFileName)
	t.Cleanup(func() { reg.UnregisterClient(nvidiaAuthFileName) })

	core := coreauth.NewManager(nil, nil, nil)
	bindNvidiaRuntime(core, nvidia.NewExecutor(nvidia.Options{}), models)

	got := reg.GetAvailableModelsByProvider(nvidiaProvider)
	if len(got) == 0 {
		t.Fatal("models unavailable before auth load")
	}
}
