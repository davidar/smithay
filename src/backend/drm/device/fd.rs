use drm::{Device as BasicDevice, control::Device as ControlDevice};
use std::{
    os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd},
    sync::{Arc, Weak},
};
use tracing::{error, info, warn};

/// Equivalent of libdrm's `drmIsMaster()`: `DRM_IOCTL_AUTH_MAGIC` is a
/// master-only ioctl, so probing it with a bogus magic yields EINVAL when the
/// fd holds drm master (the magic was actually looked up) and EACCES when it
/// does not. Unlike `DRM_IOCTL_SET_MASTER` it is not restricted by
/// `drm_master_check_perm()` on Linux >= 5.8, so it works on fds received
/// from logind.
fn is_drm_master_fd(fd: RawFd) -> bool {
    #[repr(C)]
    struct DrmAuth {
        magic: libc::c_uint,
    }
    const DRM_IOCTL_AUTH_MAGIC: libc::c_ulong = 0x4004_6411; // _IOW('d', 0x11, drm_auth)
    let mut auth = DrmAuth { magic: 0 };
    // SAFETY: ioctl on a valid fd with a properly sized out-parameter.
    let ret = unsafe { libc::ioctl(fd, DRM_IOCTL_AUTH_MAGIC as _, &mut auth) };
    ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
}

use crate::utils::{DevPath, DeviceFd};

#[derive(Debug)]
struct InternalDrmDeviceFd {
    fd: DeviceFd,
    privileged: bool,
}

impl PartialEq for InternalDrmDeviceFd {
    fn eq(&self, other: &Self) -> bool {
        self.fd == other.fd
    }
}

impl Drop for InternalDrmDeviceFd {
    fn drop(&mut self) {
        info!("Dropping device: {:?}", self.fd.dev_path());
        if self.privileged {
            if let Err(err) = self.release_master_lock() {
                error!("Failed to drop drm master state. Error: {}", err);
            }
        }
    }
}

impl AsFd for InternalDrmDeviceFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl BasicDevice for InternalDrmDeviceFd {}
impl ControlDevice for InternalDrmDeviceFd {}

/// Ref-counted file descriptor of an open drm device
#[derive(Debug, Clone, PartialEq)]
pub struct DrmDeviceFd(Arc<InternalDrmDeviceFd>);

impl AsFd for DrmDeviceFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.fd.as_fd()
    }
}

// TODO: drop impl once not needed anymore by smithay or dependencies
impl AsRawFd for DrmDeviceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.fd.as_raw_fd()
    }
}

impl DrmDeviceFd {
    /// Create a new `DrmDeviceFd`.
    ///
    /// This function will try to acquire the master lock for the underlying drm device
    /// and release the lock on drop again.
    /// For that reason you should never create multiple `DrmDeviceFd` out of the same
    /// `DeviceFd`, but instead clone the `DrmDeviceFd`.
    ///
    /// Failing to do so might fail to acquire set lock and release it early,
    /// which can cause some drm ioctls to fail later.
    pub fn new(fd: DeviceFd) -> DrmDeviceFd {
        let mut dev = InternalDrmDeviceFd {
            fd,
            privileged: false,
        };

        // We want to modeset, so we better be the master, if we run via a tty session.
        // Newer kernels grant this permission, if no other process is already the
        // *master*, but since Linux 5.8 DRM_IOCTL_SET_MASTER is also refused with
        // EACCES (drm_master_check_perm) for fds opened by another process — e.g.
        // received from logind via TakeDevice — even when the fd *already holds*
        // master. Probe the actual master status before assuming we are unprivileged.
        if dev.acquire_master_lock().is_ok() || is_drm_master_fd(dev.fd.as_raw_fd()) {
            dev.privileged = true;
        } else {
            warn!("Unable to become drm master, assuming unprivileged mode");
        }

        DrmDeviceFd(Arc::new(dev))
    }

    pub(in crate::backend::drm) fn is_privileged(&self) -> bool {
        self.0.privileged
    }

    pub(in crate::backend::drm) fn is_drm_master(&self) -> bool {
        is_drm_master_fd(self.0.fd.as_raw_fd())
    }

    /// Returns the underlying `DeviceFd`
    pub fn device_fd(&self) -> DeviceFd {
        self.0.fd.clone()
    }

    /// Returns the `dev_t` of the underlying device
    pub fn dev_id(&self) -> rustix::io::Result<libc::dev_t> {
        Ok(rustix::fs::fstat(&self.0.fd)?.st_rdev)
    }

    /// Returns a weak reference to the underlying device
    pub fn downgrade(&self) -> WeakDrmDeviceFd {
        WeakDrmDeviceFd(Arc::downgrade(&self.0))
    }
}

impl BasicDevice for DrmDeviceFd {}
impl ControlDevice for DrmDeviceFd {}

/// Weak variant of [`DrmDeviceFd`]
#[derive(Debug, Clone, Default)]
pub struct WeakDrmDeviceFd(Weak<InternalDrmDeviceFd>);

impl WeakDrmDeviceFd {
    /// Construct an empty Weak reference, that will never upgrade successfully
    pub fn new() -> Self {
        WeakDrmDeviceFd(Weak::new())
    }

    /// Try to upgrade to a strong reference
    pub fn upgrade(&self) -> Option<DrmDeviceFd> {
        self.0.upgrade().map(DrmDeviceFd)
    }
}

impl PartialEq for WeakDrmDeviceFd {
    fn eq(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
}

impl PartialEq<DrmDeviceFd> for WeakDrmDeviceFd {
    fn eq(&self, other: &DrmDeviceFd) -> bool {
        Weak::upgrade(&self.0).is_some_and(|arc| Arc::ptr_eq(&arc, &other.0))
    }
}
