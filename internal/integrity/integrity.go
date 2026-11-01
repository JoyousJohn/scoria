package integrity

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func LowerToLow() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return err
	}
	defer token.Close()

	sidText, err := windows.UTF16PtrFromString("S-1-16-4096")
	if err != nil {
		return err
	}
	var sid *windows.SID
	if err := windows.ConvertStringSidToSid(sidText, &sid); err != nil {
		return err
	}

	label := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	return windows.SetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)),
		label.Size(),
	)
}
