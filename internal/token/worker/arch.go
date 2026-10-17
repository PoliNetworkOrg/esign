package worker

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

// Archs returns the architectures (GOARCH names) of the code in a Mach-O (thin or universal), ELF or PE file.
func Archs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case string(magic[:]) == "\x7fELF":
		ef, err := elf.NewFile(f)
		if err != nil {
			return nil, err
		}
		return []string{elfArch(ef.Machine)}, nil
	case magic[0] == 'M' && magic[1] == 'Z':
		pf, err := pe.NewFile(f)
		if err != nil {
			return nil, err
		}
		return []string{peArch(pf.Machine)}, nil
	}
	if ff, err := macho.NewFatFile(f); err == nil {
		var out []string
		for _, a := range ff.Arches {
			out = append(out, machoArch(a.Cpu))
		}
		return out, nil
	} else if !errors.Is(err, macho.ErrNotFat) {
		return nil, err
	}
	mf, err := macho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: not a Mach-O, ELF or PE file", path)
	}
	return []string{machoArch(mf.Cpu)}, nil
}

func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "386"
	}
	return strings.ToLower(c.String())
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_ARM:
		return "arm"
	}
	return strings.ToLower(m.String())
}

func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	}
	return fmt.Sprintf("pe-machine-%#x", m)
}

// MacArchName is the name `arch` and `lipo` use for a GOARCH.
func MacArchName(goarch string) string {
	if goarch == "amd64" {
		return "x86_64"
	}
	return goarch
}

// Plan says how to load a module.
type Plan struct {
	// Worker is true when the module runs in a child process.
	Worker bool
	// Arch is the architecture (GOARCH name) the child must run as, when it differs from the agent's; macOS only.
	Arch string
}

func (p Plan) String() string {
	switch {
	case !p.Worker:
		return "in-process"
	case p.Arch != "":
		return MacArchName(p.Arch) + " worker"
	default:
		return "worker"
	}
}

// Choose decides how an agent running on goos/goarch, whose executable contains selfArchs, loads a module containing
// moduleArchs. isolate asks for a child process even when the module could be loaded in-process. A module of another
// architecture needs a child of that architecture, which only macOS can run (through Rosetta, from a universal agent).
func Choose(goos, goarch string, moduleArchs, selfArchs []string, isolate bool) (Plan, error) {
	if slices.Contains(moduleArchs, goarch) {
		return Plan{Worker: isolate}, nil
	}
	have := strings.Join(moduleArchs, "+")
	if goos == "darwin" {
		for _, a := range moduleArchs {
			if (a == "amd64" || a == "arm64") && slices.Contains(selfArchs, a) {
				return Plan{Worker: true, Arch: a}, nil
			}
		}
		if slices.Contains(moduleArchs, "amd64") {
			return Plan{}, fmt.Errorf("the module is %s only and this agent build has no x86_64 code: install the universal build", MacArchName(have))
		}
	}
	return Plan{}, fmt.Errorf("the module is built for %s, the agent runs on %s", have, goarch)
}

// Command builds the child's argv for plan: the agent's executable with args, run through `arch` when the child
// needs another architecture.
func Command(plan Plan, exe string, args ...string) []string {
	argv := append([]string{exe}, args...)
	if plan.Arch != "" {
		argv = append([]string{"/usr/bin/arch", "-" + MacArchName(plan.Arch)}, argv...)
	}
	return argv
}
