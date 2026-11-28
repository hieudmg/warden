package upgrade

import (
	_ "embed"
	"encoding/base64"
	"strconv"
	"unicode/utf16"
)

const (
	windowsHelperTargetEnv = "WARDEN_UPGRADE_TARGET"
	windowsHelperImageEnv  = "WARDEN_UPGRADE_IMAGE"
	windowsHelperParentEnv = "WARDEN_UPGRADE_PARENT_HANDLE"
	windowsHelperGuardEnv  = "WARDEN_UPGRADE_TARGET_HANDLE"
	windowsHelperStageEnv  = "WARDEN_UPGRADE_STAGE_HANDLE"
	windowsHelperLockEnv   = "WARDEN_UPGRADE_LOCK_HANDLE"
	windowsHelperReadyEnv  = "WARDEN_UPGRADE_READY_HANDLE"
	windowsHelperGoEnv     = "WARDEN_UPGRADE_GO_HANDLE"
)

//go:embed replace_windows.ps1
var windowsHelperProgram string

func windowsHelperEnv(target, image string, parent, guard, stage, lock, ready, authorized uintptr) []string {
	return []string{
		windowsHelperTargetEnv + "=" + target,
		windowsHelperImageEnv + "=" + image,
		windowsHelperParentEnv + "=" + strconv.FormatUint(uint64(parent), 10),
		windowsHelperGuardEnv + "=" + strconv.FormatUint(uint64(guard), 10),
		windowsHelperStageEnv + "=" + strconv.FormatUint(uint64(stage), 10),
		windowsHelperLockEnv + "=" + strconv.FormatUint(uint64(lock), 10),
		windowsHelperReadyEnv + "=" + strconv.FormatUint(uint64(ready), 10),
		windowsHelperGoEnv + "=" + strconv.FormatUint(uint64(authorized), 10),
	}
}

// encodePowerShellCommand uses the UTF-16LE representation required by
// -EncodedCommand. Paths are passed separately in the environment.
func encodePowerShellCommand(program string) string {
	units := utf16.Encode([]rune(program))
	raw := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}
