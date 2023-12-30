package syms

import (
	"fmt"
	"os"
	"runtime"

	"github.com/vietanhduong/wbpf/pkg/proc"
	"github.com/vietanhduong/wbpf/pkg/syms/elf"

	"golang.org/x/sys/unix"
)

type vdsoStatus struct {
	image string
	err   error
}

var vstatus *vdsoStatus

func buildVDSOResolver() (SymbolTable, error) {
	if vstatus == nil {
		vstatus = &vdsoStatus{}
		vstatus.image, vstatus.err = findVDSO(unix.Getpid())
		runtime.SetFinalizer(vstatus, func(obj *vdsoStatus) { obj.Cleanup() })
		if vstatus.err != nil {
			return nil, vstatus.err
		}
	}

	if vstatus != nil && vstatus.err != nil {
		return nil, fmt.Errorf("vdso already failed before: %w", vstatus.err)
	}

	mf, err := elf.NewMMapedElfFile(vstatus.image)
	if err != nil {
		return nil, fmt.Errorf("open mmaped filed %s: %w, image, err", vstatus.image, err)
	}
	log.Tracef("Loaded vDSO (image=%s)", vstatus.image)
	return createSymbolTable(mf, &elf.SymbolOptions{
		DemangleOpts: DemangleFull.ToOptions(),
	}), nil
}

func findVDSO(pid int) (string, error) {
	maps, err := proc.ParseProcMaps(pid)
	if err != nil {
		return "", fmt.Errorf("parse proc map pid %d: %w", pid, err)
	}

	for _, m := range maps {
		if image := buildVDSOImage(m, pid); image != "" {
			return image, nil
		}
	}
	return "", fmt.Errorf("unable to create vDSO image")
}

func buildVDSOImage(procmap *proc.Map, pid int) string {
	if !proc.IsVDSO(procmap.Pathname) {
		return ""
	}

	size := procmap.EndAddr - procmap.StartAddr
	procmem := proc.HostProcPath(fmt.Sprintf("%d/mem", pid))
	mem, err := os.OpenFile(procmem, os.O_RDONLY, 0)
	if err != nil {
		log.WithError(err).Tracef("Build vDSO Image: Failed to open file %s", procmem)
		return ""
	}
	defer mem.Close()

	if _, err = mem.Seek(int64(procmap.StartAddr), 0); err != nil {
		log.WithError(err).Tracef("Build vDSO Image: Failed to seek to address")
		return ""
	}

	buf := make([]byte, size)
	if _, err = mem.Read(buf); err != nil {
		log.WithError(err).Tracef("Build vDSO Image: Failed read mem")
		return ""
	}
	tmpfile, err := os.CreateTemp("", fmt.Sprintf("wbpf_%d_vdso_image_*", pid))
	if err != nil {
		log.WithError(err).Tracef("Build vDSO Image: Failed to create vsdo temp file")
		return ""
	}
	defer tmpfile.Close()

	if _, err = tmpfile.Write(buf); err != nil {
		log.WithError(err).Trace("failed to write to vDSO image")
	}
	return tmpfile.Name()
}

func (s *vdsoStatus) Cleanup() {
	if s == nil || s.image == "" {
		return
	}
	log.Tracef("Remove vDSO image: %s", s.image)
	os.Remove(s.image)
	s.err = nil
}
