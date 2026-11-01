//go:build windows

package scan

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	findExInfoBasic       = 1
	findExSearchNameMatch = 0
	findFirstExLargeFetch = 0x2
)

type findData struct {
	FileAttributes    uint32
	CreationTime      windows.Filetime
	LastAccessTime    windows.Filetime
	LastWriteTime     windows.Filetime
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [260]uint16
	AlternateFileName [14]uint16
}

var (
	kernel32DLL          = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstFileExW = kernel32DLL.NewProc("FindFirstFileExW")
	procFindNextFileW    = kernel32DLL.NewProc("FindNextFileW")
)

func findFirst(pattern *uint16, data *findData) (windows.Handle, error) {
	r1, _, e1 := procFindFirstFileExW.Call(
		uintptr(unsafe.Pointer(pattern)),
		findExInfoBasic,
		uintptr(unsafe.Pointer(data)),
		findExSearchNameMatch,
		0,
		findFirstExLargeFetch,
	)
	handle := windows.Handle(r1)
	if handle == windows.InvalidHandle {
		if e1 != nil {
			return 0, e1
		}
		return 0, syscall.EINVAL
	}
	return handle, nil
}

func findNext(handle windows.Handle, data *findData) (bool, error) {
	r1, _, e1 := procFindNextFileW.Call(uintptr(handle), uintptr(unsafe.Pointer(data)))
	if r1 != 0 {
		return true, nil
	}
	if e1 == windows.ERROR_NO_MORE_FILES {
		return false, nil
	}
	if e1 != nil {
		return false, e1
	}
	return false, syscall.EINVAL
}

func (d *findData) nameLen() int {
	for i := 0; i < len(d.FileName); i++ {
		if d.FileName[i] == 0 {
			return i
		}
	}
	return len(d.FileName)
}

func (d *findData) size() int64 {
	return int64(uint64(d.FileSizeHigh)<<32 | uint64(d.FileSizeLow))
}

func (d *findData) modTime() time.Time {
	if d.LastWriteTime.HighDateTime == 0 && d.LastWriteTime.LowDateTime == 0 {
		return time.Time{}
	}
	return time.Unix(0, d.LastWriteTime.Nanoseconds())
}
