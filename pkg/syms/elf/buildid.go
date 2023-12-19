package elf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

type BuildId struct {
	Id  string
	Typ string
}

func GNUBuildId(s string) BuildId {
	return BuildId{Id: s, Typ: "gnu"}
}

func GoBuildId(s string) BuildId {
	return BuildId{Id: s, Typ: "go"}
}

func (b *BuildId) Empty() bool {
	return b.Id == "" || b.Typ == ""
}

func (b *BuildId) GNU() bool {
	return b.Typ == "gnu"
}

var ErrNoBuildIDSection = fmt.Errorf("build ID section not found")

func (f *MMapedElfFile) BuildId() (BuildId, error) {
	id, err := f.GNUBuildId()
	if err != nil && !errors.Is(err, ErrNoBuildIDSection) {
		return BuildId{}, err
	}
	if !id.Empty() {
		return id, nil
	}
	id, err = f.GoBuildId()
	if err != nil && !errors.Is(err, ErrNoBuildIDSection) {
		return BuildId{}, err
	}
	if !id.Empty() {
		return id, nil
	}

	return BuildId{}, ErrNoBuildIDSection
}

var goBuildIDSep = []byte("/")

func (f *MMapedElfFile) GoBuildId() (BuildId, error) {
	buildIDSection := f.Section(".note.go.buildid")
	if buildIDSection == nil {
		return BuildId{}, ErrNoBuildIDSection
	}
	data, err := f.SectionData(buildIDSection)
	if err != nil {
		return BuildId{}, fmt.Errorf("reading .note.go.buildid %w", err)
	}
	if len(data) < 17 {
		return BuildId{}, fmt.Errorf(".note.gnu.build-id is too small")
	}

	data = data[16 : len(data)-1]
	if len(data) < 40 || bytes.Count(data, goBuildIDSep) < 2 {
		return BuildId{}, fmt.Errorf("wrong .note.go.buildid %s", f.fpath)
	}
	id := string(data)
	if id == "redacted" {
		return BuildId{}, fmt.Errorf("blacklisted  .note.go.buildid %s", f.fpath)
	}
	return GoBuildId(id), nil
}

func (f *MMapedElfFile) GNUBuildId() (BuildId, error) {
	buildIDSection := f.Section(".note.gnu.build-id")
	if buildIDSection == nil {
		return BuildId{}, ErrNoBuildIDSection
	}

	data, err := f.SectionData(buildIDSection)
	if err != nil {
		return BuildId{}, fmt.Errorf("reading .note.gnu.build-id %w", err)
	}
	if len(data) < 16 {
		return BuildId{}, fmt.Errorf(".note.gnu.build-id is too small")
	}
	if !bytes.Equal([]byte("GNU"), data[12:15]) {
		return BuildId{}, fmt.Errorf(".note.gnu.build-id is not a GNU build-id")
	}
	rawBuildID := data[16:]
	if len(rawBuildID) != 20 && len(rawBuildID) != 8 { // 8 is xxhash, for example in Container-Optimized OS
		return BuildId{}, fmt.Errorf(".note.gnu.build-id has wrong size %s", f.fpath)
	}
	buildIDHex := hex.EncodeToString(rawBuildID)
	return GNUBuildId(buildIDHex), nil
}
