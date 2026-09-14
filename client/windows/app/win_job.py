"""Fail-closed Windows job ownership. Children cannot start work before assignment."""
import ctypes
from ctypes import wintypes as w
import os

class Basic(ctypes.Structure):
    _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),
              ('flags',w.DWORD),('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),
              ('active',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
class IO(ctypes.Structure):
    _fields_=[(name,ctypes.c_ulonglong) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
class Extended(ctypes.Structure):
    _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),
              ('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]

class Job:
    def __init__(self):
        if os.name!='nt':raise OSError('Windows only')
        self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR]
        self.api.CreateJobObjectW.restype=w.HANDLE
        self.api.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        self.api.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        self.api.CloseHandle.argtypes=[w.HANDLE]
        self.handle=self.api.CreateJobObjectW(None,None)
        if not self.handle:raise ctypes.WinError(ctypes.get_last_error())
        info=Extended();info.basic.flags=0x2000
        if not self.api.SetInformationJobObject(self.handle,9,ctypes.byref(info),ctypes.sizeof(info)):
            self.close();raise ctypes.WinError(ctypes.get_last_error())
    def assign(self,process):
        if not self.api.AssignProcessToJobObject(self.handle,w.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None
