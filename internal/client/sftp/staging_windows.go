//go:build windows

package sftp

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Like agent runtime creation, supply a protected owner-only DACL in the native
// create operation. os.OpenFile's 0600 does not establish Windows ACL privacy.
func createLocalStage(name string) (*os.File, error) {
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
	nativeName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(nativeName, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, &os.PathError{Op: "create private stage", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), name)
	// Fail closed on filesystems that cannot preserve the supplied security
	// descriptor. Check the opened handle, not a path that could be substituted.
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = validateStageACL(actual, sid)
	}
	if err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(name))
	}
	return file, nil
}

func validateStageACL(sd *windows.SECURITY_DESCRIPTOR, sid *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(sid) {
		return errors.New("copy: stage has unexpected owner")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("copy: stage DACL is not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 1 {
		return errors.New("copy: stage DACL is not owner-only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
		return errors.New("copy: stage DACL grants another principal")
	}
	return nil
}
