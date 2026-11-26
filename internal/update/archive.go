// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pipe/internal/version"
)

const (
	tarBlockBytes      = 512
	maxReadmeBytes     = 64 << 10
	maxExpandedArchive = maxAssetSize + maxReadmeBytes + (1 << 20)
)

// ExtractLinuxBinary extracts the pipe executable from a verified Linux
// release tar.gz into an exclusive 0700 file inside stageDir.
// It checks the exact archive inventory, ELF architecture, and unique embedded
// release identity marker before returning the open file positioned at byte 0.
func ExtractLinuxBinary(archivePath, abi, expectedVersion, stageDir string) (*os.File, func(), error) {
	if abi != "amd64" && abi != "arm64" {
		return nil, nil, fmt.Errorf("unsupported Linux architecture %q", abi)
	}
	if err := inspectPrivateDir(stageDir, false); err != nil {
		return nil, nil, err
	}
	dir, err := openLocalSourceDir(filepath.Dir(archivePath))
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	f, _, err := dir.OpenRegular(filepath.Base(archivePath))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return extractLinuxBinaryFromReader(f, abi, expectedVersion, stageDir)
}

func extractLinuxBinaryFromReader(r io.Reader, abi, expectedVersion, stageDir string) (*os.File, func(), error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, errors.New("The release archive is not a valid gzip file.")
	}
	defer gz.Close()

	limited := &io.LimitedReader{R: gz, N: maxExpandedArchive + 1}
	tr := tar.NewReader(limited)

	var (
		seenPipe   bool
		seenReadme bool
		binFile    *os.File
		padding    int64
	)
	cleanup := func() {
		if binFile != nil {
			_ = binFile.Close()
			_ = os.Remove(binFile.Name())
		}
	}
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()

	for {
		before := limited.N
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if before-limited.N != padding+2*tarBlockBytes {
				return nil, nil, errors.New("The release archive has an invalid TAR end marker.")
			}
			break
		}
		if err != nil {
			return nil, nil, errors.New("The release archive is invalid.")
		}
		if (hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA) || hdr.Linkname != "" {
			return nil, nil, fmt.Errorf("The release archive contains an unsupported entry %q.", hdr.Name)
		}
		for key := range hdr.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") || key == "SCHILY.realsize" {
				return nil, nil, errors.New("The release archive contains a sparse entry.")
			}
		}
		padding = -hdr.Size & (tarBlockBytes - 1)
		switch hdr.Name {
		case "pipe":
			if seenPipe || hdr.Size <= 0 || hdr.Size > maxAssetSize {
				return nil, nil, errors.New("The release archive has an invalid pipe executable entry.")
			}
			seenPipe = true
			binFile, err = os.CreateTemp(stageDir, ".pipe-bin-")
			if err != nil {
				return nil, nil, err
			}
			if err := binFile.Chmod(0700); err != nil {
				return nil, nil, err
			}
			n, err := io.Copy(binFile, io.LimitReader(tr, hdr.Size+1))
			if err != nil || n != hdr.Size {
				return nil, nil, errors.New("The release archive executable could not be extracted.")
			}
		case "README.txt":
			if seenReadme || hdr.Size < 0 || hdr.Size > maxReadmeBytes {
				return nil, nil, errors.New("The release archive has an invalid README.txt entry.")
			}
			seenReadme = true
			n, err := io.Copy(io.Discard, io.LimitReader(tr, hdr.Size+1))
			if err != nil || n != hdr.Size {
				return nil, nil, errors.New("The release archive README.txt could not be read.")
			}
		default:
			return nil, nil, fmt.Errorf("The release archive contains an unexpected entry %q.", hdr.Name)
		}
		if limited.N == 0 {
			return nil, nil, errors.New("The release archive exceeds the maximum extracted size.")
		}
	}
	// Reading through gzip EOF checks its checksum. TAR may pad its footer
	// with zeroes within the same expanded-size limit.
	if !validArchivePadding(limited) {
		return nil, nil, errors.New("The release archive contains invalid trailing data.")
	}
	if !seenPipe || !seenReadme || binFile == nil {
		return nil, nil, errors.New("The release archive is missing required files.")
	}
	if err := verifyLinuxELFAndIdentity(binFile, abi, expectedVersion); err != nil {
		return nil, nil, err
	}
	if _, err := binFile.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	if err := binFile.Sync(); err != nil {
		return nil, nil, err
	}
	success = true
	return binFile, cleanup, nil
}

func validArchivePadding(r *io.LimitedReader) bool {
	var buf [32 << 10]byte
	for {
		n, err := r.Read(buf[:])
		if len(bytes.Trim(buf[:n], "\x00")) != 0 {
			return false
		}
		if err != nil {
			return err == io.EOF && r.N > 0
		}
	}
}

func verifyLinuxELFAndIdentity(f *os.File, abi, expectedVersion string) error {
	var hdr [64]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return errors.New("The extracted pipe executable is truncated.")
	}
	// ELF64 little-endian, Linux/SysV ABI, ET_EXEC (2) or ET_DYN (3).
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' || hdr[4] != 2 || hdr[5] != 1 {
		return errors.New("The extracted pipe executable has the wrong platform format.")
	}
	if hdr[7] != 0 && hdr[7] != 3 {
		return errors.New("The extracted pipe executable has the wrong OS ABI.")
	}
	eType := binary.LittleEndian.Uint16(hdr[16:18])
	eMachine := binary.LittleEndian.Uint16(hdr[18:20])
	wantMachine := uint16(62) // x86_64
	if abi == "arm64" {
		wantMachine = 183 // AArch64
	}
	if (eType != 2 && eType != 3) || eMachine != wantMachine {
		return errors.New("The extracted pipe executable has the wrong CPU architecture.")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	goos, goarch, ver, ok := version.ScanIdentity(f)
	if !ok || goos != "linux" || goarch != abi || ver != expectedVersion {
		return errors.New("The extracted pipe executable does not match the signed release version or platform.")
	}
	return nil
}
