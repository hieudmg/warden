//go:build windows

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func runtimeEndpointPath(dir string) string {
	digest := sha256.Sum256([]byte(dir))
	return `\\.\pipe\warden-agent-` + hex.EncodeToString(digest[:])
}
func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}
func runtimeSDDL() (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return "O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")", nil
}
func listenRuntime(_ *Runtime, path string) (net.Listener, error) {
	sddl, err := runtimeSDDL()
	if err != nil {
		return nil, err
	}
	// v0.6.2 reserves the first instance with NtCreateNamedPipeFile FILE_CREATE
	// and rejects remote clients. An existing squatter makes this fail, not join.
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
}
func dialRuntime(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

func openPrivateDirectory(path string, create bool) (*privateDirectory, error) {
	if create {
		if err := createPrivateDirectories(path); err != nil {
			return nil, err
		}
	}
	// Reject reparse ancestors rather than trusting a certificate through a
	// redirected directory. The final native handle is checked and retained.
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("agent runtime directory/reparse path refused")
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if err := validatePrivateHandle(handle, true); err != nil {
		file.Close()
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		file.Close()
		return nil, err
	}
	a, errA := file.Stat()
	b, errB := root.Stat(".")
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		file.Close()
		root.Close()
		return nil, errors.New("agent runtime directory changed")
	}
	return &privateDirectory{root: root, file: file}, nil
}
func createPrivateDirectories(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("agent runtime directory/reparse path refused")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return err
	}
	if err := createPrivateDirectories(parent); err != nil {
		return err
	}
	sddl, err := runtimeSDDL()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(name, attributes)
	runtime.KeepAlive(sd)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	return err
}
func openPrivateChild(directory *os.File, name string, flags int) (*os.File, error) {
	sddl, err := runtimeSDDL()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(directory.Fd()), ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	access := uint32(windows.FILE_GENERIC_READ | windows.READ_CONTROL)
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
		access |= windows.FILE_GENERIC_WRITE
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
		if flags&os.O_EXCL != 0 {
			disposition = windows.FILE_CREATE
		}
	}
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access, attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(objectName)
	if err != nil {
		if status, ok := err.(windows.NTStatus); ok {
			err = status.Errno()
		}
		return nil, &os.PathError{Op: "open private agent file", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), name)
	if err := validatePrivateHandle(handle, false); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func validatePrivateHandle(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("agent runtime reparse point refused")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("invalid agent runtime object type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return errors.New("agent runtime file has multiple links")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return validateRuntimeSecurityDescriptor(sd)
}
func validateRuntimeSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		return errors.New("agent runtime object has wrong owner")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("agent runtime DACL is not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return errors.New("agent runtime DACL is absent or empty")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return errors.New("agent runtime DACL contains unsupported ACE")
		}
		allowed := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed.Equals(sid) {
			return errors.New("agent runtime DACL grants another principal access")
		}
	}
	return nil
}
func lockRuntime(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		return fmt.Errorf("lock agent runtime: %w", err)
	}
	return nil
}
