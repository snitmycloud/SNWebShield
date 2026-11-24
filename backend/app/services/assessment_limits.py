"""Process limits for fixed, trusted local Python programs; not a sandbox."""
import os


def child_limits():
    if os.name == "posix":
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def attach_windows(process):
    if os.name != "nt":
        return None
    import ctypes as c
    from ctypes import wintypes as w
    class Basic(c.Structure):
        _fields_ = [("process_time", c.c_int64), ("job_time", c.c_int64), ("flags", w.DWORD),
            ("min_ws", c.c_size_t), ("max_ws", c.c_size_t), ("active", w.DWORD),
            ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
    class IO(c.Structure):
        _fields_ = [(name, c.c_uint64) for name in ("ro", "wo", "oo", "rt", "wt", "ot")]
    class Extended(c.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", c.c_size_t),
            ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]
    class CPU(c.Structure):
        _fields_ = [("flags", w.DWORD), ("rate", w.DWORD)]
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]; kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise OSError("windows_job_creation_failed")
    try:
        limit = Extended(); limit.basic.flags = 0x2000 | 0x100 | 0x8
        limit.basic.active = 1; limit.process_memory = 256*1024*1024
        cpu = CPU(0x1 | 0x4, 2500)
        if (not kernel.SetInformationJobObject(handle, 9, c.byref(limit), c.sizeof(limit))
            or not kernel.SetInformationJobObject(handle, 15, c.byref(cpu), c.sizeof(cpu))
            or not kernel.AssignProcessToJobObject(handle, w.HANDLE(int(process._handle)))):
            raise OSError("windows_process_limits_unavailable")
    except Exception:
        kernel.CloseHandle(handle); raise
    return lambda: kernel.CloseHandle(handle)
