#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SecurityEvent {
    pub _filename: [u8; 32],
    pub _uid: u32,
    pub _unsafe: i32,
    pub _cgroup_type: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityEvent {}