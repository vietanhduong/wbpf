package wbpf

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
)

type toPin struct {
	m    *ebpf.Map
	path string
}

// mapsToReplace returns a slice of paths and ebpf.Maps corresponding to the
// entries provided in toReplace. Commit the returned pins after attaching the
// Collection's programs to the required hooks using [commitMapPins].
//
// This has two main purposes: replacing pins of incompatible maps that are
// upgraded or downgraded by a different version of the agent, as well as
// replacing pins of maps that should never be reused/repopulated by the loader,
// like tail call maps.
//
// Letting the loader repopulate an existing tail call map will transition the
// program through invalid states. For example, code can be moved from one tail
// call to another, making some instructions execute twice or not at all
// depending on the order the tail calls were inserted.
func mapsToReplace(toReplace []string, spec *ebpf.CollectionSpec, coll *ebpf.Collection, opts ebpf.CollectionOptions) ([]toPin, error) {
	if opts.Maps.PinPath == "" && len(toReplace) > 0 {
		return nil, errors.New("empty Maps.PinPath in CollectionOptions")
	}

	// We need both Map and MapSpec as the pin path is derived from MapSpec.Name,
	// and can be modified before creating the Collection. Maps are often renamed
	// to give them unique bpffs pin paths. MapInfo is/was truncated to 20 chars,
	// so we need the MapSpec.Name.
	var pins []toPin
	for _, key := range toReplace {
		m, ok := coll.Maps[key]
		if !ok {
			return nil, fmt.Errorf("map %s not found in collection", key)
		}
		ms, ok := spec.Maps[key]
		if !ok {
			return nil, fmt.Errorf("map spec %s not found in collection spec", key)
		}

		if m.IsPinned() {
			return nil, fmt.Errorf("map %s was already pinned by ebpf-go: LIBBPF_PIN_BY_NAME is mutually exclusive", ms.Name)
		}

		pins = append(pins, toPin{m: m, path: path.Join(opts.Maps.PinPath, ms.Name)})
	}

	return pins, nil
}

// commitMapPins removes the given map pins and replaces them with the
// corresponding Maps. This is to be called after the Collection's programs have
// been attached to the required hooks. Any existing pins are overwritten.
func commitMapPins(pins []toPin) error {
	for _, pin := range pins {
		if err := os.Remove(pin.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing map pin at %s: %w", pin.path, err)
		}
		if err := pin.m.Pin(pin.path); err != nil {
			return fmt.Errorf("pinning map to %s: %w", pin.path, err)
		}

		log.Debugf("Replaced map pin %s", pin.path)
	}

	return nil
}
