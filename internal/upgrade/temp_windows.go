//go:build windows

package upgrade

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createUpgradeTemp(dir, prefix string) (*os.File, error) {
	return createPrivateStage(filepath.Join(dir, prefix+rand.Text()))
}

// CREATE_NEW and an explicit protected owner-only DACL apply before any bytes.
// Validate the actual handle; POSIX mode 0600 alone does not protect Windows.
func createPrivateStage(name string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	native, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(native, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, &os.PathError{Op: "create upgrade stage", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), name)
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = validateUpgradeACL(actual, sid)
	}
	if err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(name))
	}
	return file, nil
}

func validateUpgradeACL(sd *windows.SECURITY_DESCRIPTOR, sid *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(sid) {
		return errors.New("upgrade stage has unexpected owner")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("upgrade stage DACL is not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 1 {
		return errors.New("upgrade stage DACL is not owner-only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
		return errors.New("upgrade stage DACL grants another principal")
	}
	return nil
}
