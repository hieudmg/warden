$ErrorActionPreference = 'Stop'

try {
    [Console]::WriteLine('PowerShell entered replacement script.')
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class WardenUpgrade {
    private const uint Signaled = 0, Timeout = 258;
    private const uint Terminate = 0x0001, QueryLimited = 0x1000, Synchronize = 0x100000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(SafeFileHandle process, uint flags, StringBuilder image, ref uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(SafeFileHandle handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetHandleInformation(SafeFileHandle handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out FileId id, uint size);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId {
        public ulong Volume, Low, High;
    }

    public static void Replace(string destination, string image, long parentHandle, long guardHandle, long stageHandle,
        long lockHandle, long readyHandle, long authorizationHandle) {
        using (var parent = new SafeFileHandle(new IntPtr(parentHandle), true))
        using (var guard = new SafeFileHandle(new IntPtr(guardHandle), true))
        using (var stage = new SafeFileHandle(new IntPtr(stageHandle), true))
        using (var upgradeLock = new SafeFileHandle(new IntPtr(lockHandle), true))
        using (var ready = new SafeFileHandle(new IntPtr(readyHandle), true))
        using (var authorized = new SafeFileHandle(new IntPtr(authorizationHandle), true)) {
            if (WaitForSingleObject(parent, 0) != Timeout)
                throw LastError("inherited upgrade command handle is not a live process");
            if (WaitForSingleObject(authorized, 0) != Timeout)
                throw LastError("inherited authorization event is invalid or already signaled");
            uint flags;
            if (!GetHandleInformation(upgradeLock, out flags)) throw LastError("inherited upgrade lock handle is invalid");
            InspectFile(stage, "inherited staging handle");
            var original = IdentifyFile(guard);
            Console.WriteLine("Helper ready; waiting for upgrade command to exit.");
            if (!SetEvent(ready)) throw LastError("signal replacement helper readiness");

            uint wait = WaitForSingleObject(parent, 30000);
            if (wait == Timeout) throw new TimeoutException("timed out waiting for upgrade command to exit; no processes stopped");
            if (wait != Signaled) throw LastError("waiting for upgrade command failed");
            if (WaitForSingleObject(authorized, 0) != Signaled)
                throw new InvalidOperationException("replacement was not authorized; no processes stopped");

            var path = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(guard, path, (uint)path.Capacity, 2); // VOLUME_NAME_NT
            if (length == 0) throw LastError("cannot confirm target image path; no processes stopped");
            if (length >= path.Capacity || !String.Equals(path.ToString(), image, StringComparison.Ordinal))
                throw new InvalidOperationException("target image path changed; no processes stopped");
            RequireOriginalTarget(destination, original);

            Console.WriteLine("Stopping processes at the verified executable path.");
            StopExactImage(image);
            guard.Dispose(); // Ordinary rename cannot replace the guarded target.
            Console.WriteLine("Publishing the verified executable.");
            RenameOverTarget(stage, destination, original);
        }
    }

    private static Win32Exception LastError(string operation) {
        int error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, operation + ": " + new Win32Exception(error).Message + " (Win32 " + error + ")");
    }

    private static FileInformation InspectFile(SafeFileHandle file, string what) {
        FileInformation info;
        if (!GetFileInformationByHandle(file, out info)) throw LastError("inspect " + what);
        return info;
    }

    private static FileId IdentifyFile(SafeFileHandle file) {
        FileId id;
        if (!GetFileInformationByHandleEx(file, 18, out id, 24)) throw LastError("read executable file ID");
        return id;
    }

    private static void RequireOriginalTarget(string path, FileId original) {
        // FILE_READ_ATTRIBUTES, share all, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
        using (var target = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
            if (target.IsInvalid) throw LastError("reopen original target");
            var current = InspectFile(target, "current target");
            var id = IdentifyFile(target);
            if (id.Volume != original.Volume || id.Low != original.Low || id.High != original.High ||
                current.Links != 1 || (current.Attributes & 0x410) != 0)
                throw new InvalidOperationException("executable identity changed; refusing replacement");
            if ((current.Attributes & 1) != 0)
                throw new InvalidOperationException("executable is read-only; refusing replacement");
        }
    }

    private static void StopExactImage(string target) {
        var deadline = Stopwatch.StartNew();
        var image = new StringBuilder(32768);
        var processes = Process.GetProcesses();
        try {
            foreach (var candidate in processes) {
                int id = candidate.Id;
                using (var query = OpenProcess(QueryLimited | Synchronize, false, id)) {
                    if (!IsExactImage(query, image, target) || WaitForSingleObject(query, 0) == Signaled) continue;
                    using (var handle = OpenProcess(Terminate | QueryLimited | Synchronize, false, id)) {
                        if (handle.IsInvalid) {
                            int error = Marshal.GetLastWin32Error();
                            if (WaitForSingleObject(query, 0) == Signaled) continue;
                            throw StopError(id, error);
                        }
                        // Recheck on the terminable handle, never on the earlier PID lookup.
                        if (!IsExactImage(handle, image, target) || WaitForSingleObject(handle, 0) == Signaled) continue;
                        if (deadline.ElapsedMilliseconds >= 5000) throw new TimeoutException("timed out stopping target processes");
                        if (!TerminateProcess(handle, 1)) {
                            int error = Marshal.GetLastWin32Error();
                            if (WaitForSingleObject(handle, 0) == Signaled) continue;
                            throw StopError(id, error);
                        }
                        uint wait = WaitForSingleObject(handle, (uint)Math.Max(0, 5000 - deadline.ElapsedMilliseconds));
                        if (wait == Timeout) throw new TimeoutException("timed out stopping target process " + id);
                        if (wait != Signaled) throw new Win32Exception(Marshal.GetLastWin32Error(), "waiting for target process failed");
                    }
                }
            }
        } finally {
            foreach (var candidate in processes) candidate.Dispose();
        }
    }

    private static bool IsExactImage(SafeFileHandle handle, StringBuilder image, string target) {
        uint length = (uint)image.Capacity;
        return !handle.IsInvalid && QueryFullProcessImageName(handle, 1, image, ref length) &&
            String.Equals(image.ToString(), target, StringComparison.Ordinal);
    }

    private static Win32Exception StopError(int id, int error) {
        return new Win32Exception(error, "could not stop target process " + id + ": " + new Win32Exception(error).Message);
    }

    private static void RenameOverTarget(SafeFileHandle stage, string destination, FileId original) {
        byte[] name = Encoding.Unicode.GetBytes(destination + "\0");
        // FILE_RENAME_INFO with a NULL RootDirectory and a full literal path.
        int nameOffset = 2 * IntPtr.Size + sizeof(uint);
        int length = nameOffset + name.Length;
        IntPtr info = Marshal.AllocHGlobal(length);
        try {
            Marshal.WriteInt32(info, 0, 1); // ReplaceIfExists
            Marshal.WriteIntPtr(info, IntPtr.Size, IntPtr.Zero);
            Marshal.WriteInt32(info, 2 * IntPtr.Size, name.Length - 2);
            Marshal.Copy(name, 0, IntPtr.Add(info, nameOffset), name.Length);

            var deadline = Stopwatch.StartNew();
            do {
                // FileRenameInfo cannot compare IDs; requires exclusive directory control.
                RequireOriginalTarget(destination, original);
                if (SetFileInformationByHandle(stage, 3, info, (uint)length)) return; // FileRenameInfo
                int error = Marshal.GetLastWin32Error();
                if (error != 5 && error != 32 && error != 33 && error != 1224)
                    throw new Win32Exception(error);
                if (deadline.ElapsedMilliseconds >= 10000)
                    throw new TimeoutException("timed out replacing executable: " + new Win32Exception(error).Message + " (Win32 " + error + ")");
                Thread.Sleep(200);
            } while (true);
        } finally {
            Marshal.FreeHGlobal(info);
        }
    }
}
'@
    [WardenUpgrade]::Replace($env:WARDEN_UPGRADE_TARGET, $env:WARDEN_UPGRADE_IMAGE,
        [long]$env:WARDEN_UPGRADE_PARENT_HANDLE, [long]$env:WARDEN_UPGRADE_TARGET_HANDLE,
        [long]$env:WARDEN_UPGRADE_STAGE_HANDLE, [long]$env:WARDEN_UPGRADE_LOCK_HANDLE,
        [long]$env:WARDEN_UPGRADE_READY_HANDLE, [long]$env:WARDEN_UPGRADE_GO_HANDLE)
    [Console]::WriteLine('Replacement complete.')
} catch {
    [Console]::Error.WriteLine('Replacement failed: ' + $_.Exception.GetBaseException().Message)
    exit 1
}
