use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::FALSE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_ALL_ACCESS};
use winapi::um::winnt::{HANDLE, PAGE_READWRITE, PSECURITY_DESCRIPTOR};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::shared::sddl::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use winapi::um::winbase::LocalFree;

pub struct Shmem {
    handle: HANDLE,
    ptr: *mut u8,
    size: usize,
}

unsafe impl Send for Shmem {}
unsafe impl Sync for Shmem {}

impl Shmem {
    pub fn create(name: &str, size: usize) -> anyhow::Result<Self> {
        let name_w = wide_string(name);
        
        // Create Security Descriptor for "Everyone" (World) -> D:(A;;GA;;;WD)
        // This ensures the user session can access the object created by System.
        let sddl = wide_string("D:(A;;GA;;;WD)");
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        
        unsafe {
            let res = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1 as u32,
                &mut sd,
                ptr::null_mut(),
            );
            
            if res == 0 {
                return Err(anyhow::anyhow!("Failed to create Security Descriptor: {}", GetLastError()));
            }
            
            let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
            sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = FALSE;
            
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE, // Use paging file
                &mut sa,
                PAGE_READWRITE,
                (size >> 32) as u32,
                (size & 0xFFFFFFFF) as u32,
                name_w.as_ptr(),
            );
            
            // Free the SD buffer allocated by LocalAlloc (via ConvertString...)
            LocalFree(sd as *mut _);
            
            if handle.is_null() {
                return Err(anyhow::anyhow!("CreateFileMappingW failed: {}", GetLastError()));
            }
            
            let ptr = MapViewOfFile(
                handle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                size,
            );
            
            if ptr.is_null() {
                CloseHandle(handle);
                return Err(anyhow::anyhow!("MapViewOfFile failed: {}", GetLastError()));
            }
            
            Ok(Self {
                handle,
                ptr: ptr as *mut u8,
                size,
            })
        }
    }
    
    pub fn open(name: &str, size: usize) -> anyhow::Result<Self> {
        let name_w = wide_string(name);
        unsafe {
            let handle = OpenFileMappingW(
                FILE_MAP_ALL_ACCESS,
                FALSE,
                name_w.as_ptr(),
            );

            if handle.is_null() {
                return Err(anyhow::anyhow!("OpenFileMappingW failed: {}", GetLastError()));
            }

            let ptr = MapViewOfFile(
                handle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                size,
            );

            if ptr.is_null() {
                CloseHandle(handle);
                return Err(anyhow::anyhow!("MapViewOfFile failed: {}", GetLastError()));
            }

            Ok(Self {
                handle,
                ptr: ptr as *mut u8,
                size,
            })
        }
    }
    
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
    
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for Shmem {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                UnmapViewOfFile(self.ptr as *mut _);
            }
            if !self.handle.is_null() {
                CloseHandle(self.handle);
            }
        }
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
