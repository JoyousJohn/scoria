//go:build windows

package scan

import (
	"encoding/binary"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileID struct {
	volume uint64
	id     [16]byte
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type hardlinkSet struct {
	mu   sync.Mutex
	seen map[fileID]struct{}
}

func newHardlinkSet() *hardlinkSet {
	return &hardlinkSet{seen: make(map[fileID]struct{})}
}

func (s *hardlinkSet) add(id fileID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return false
	}
	s.seen[id] = struct{}{}
	return true
}

func fileLinkInfo(path *uint16) (uint32, fileID, error) {
	handle, err := windows.CreateFile(
		path,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fileID{}, err
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, fileID{}, err
	}

	id := fileID{volume: uint64(info.VolumeSerialNumber)}
	binary.LittleEndian.PutUint64(id.id[:8], uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow))
	if info.NumberOfLinks <= 1 {
		return info.NumberOfLinks, id, nil
	}

	var full fileIDInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&full)),
		uint32(unsafe.Sizeof(full)),
	); err == nil {
		id.volume = full.VolumeSerialNumber
		id.id = full.FileID
	}
	return info.NumberOfLinks, id, nil
}
