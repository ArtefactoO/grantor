package adapter

import (
	"fmt"
	"sort"
	"sync"
)

// Factory создаёт новый экземпляр adapter.
type Factory func() Adapter

var registry = struct {
	mu        sync.RWMutex
	factories map[string]Factory
}{factories: map[string]Factory{}}

// Register регистрирует adapter для engine. Вызывается при старте
// worker/connector; повторная регистрация того же engine — ошибка
// программиста и вызывает panic.
func Register(engine string, f Factory) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, dup := registry.factories[engine]; dup {
		panic(fmt.Sprintf("adapter: duplicate registration for engine %q", engine))
	}
	registry.factories[engine] = f
}

// New возвращает новый adapter для engine.
func New(engine string) (Adapter, error) {
	registry.mu.RLock()
	f, ok := registry.factories[engine]
	registry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("adapter: unknown engine %q", engine)
	}
	return f(), nil
}

// Engines возвращает отсортированный список зарегистрированных engines.
func Engines() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	engines := make([]string, 0, len(registry.factories))
	for e := range registry.factories {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	return engines
}
