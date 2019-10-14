/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;

use libc;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Error as IoError, Result as IoResult};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use nix::sys::mman::{mmap, munmap, mprotect, ProtFlags as Prot, MapFlags as Map};

use abi::{Attributes, Einittoken, ErrorCode, Miscselect, Secinfo, Secs, Sigstruct, PageType, SecinfoFlags};
use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use sgxs_crate::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::{MappingInfo, Tcs};
use generic::{self, EinittokenError, EnclaveLoad, Mapping};

use self::DriverVersion::*;

#[derive(Fail, Debug)]
pub enum SgxIoctlError {
    #[fail(display = "I/O ctl failed.")]
    Io(#[cause] IoError),
    #[fail(display = "The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
    #[fail(display = "The enclave was destroyed because the CPU was powered down.")]
    PowerLostEnclave,
    #[fail(display = "Launch enclave version rollback detected.")]
    LeRollback,
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to call ECREATE.")]
    Create(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EADD.")]
    Add(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EINIT.")]
    Init(#[cause] SgxIoctlError),
}

impl Error {
    fn map(error: nix::Error) -> Self {
        Error::Map(error.as_errno().unwrap().into())
    }
}

impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        use self::Error::Init;
        use self::SgxIoctlError::Ret;
        match self {
            &Init(Ret(ErrorCode::InvalidEinitToken)) |
            &Init(Ret(ErrorCode::InvalidCpusvn)) |
            &Init(Ret(ErrorCode::InvalidAttribute)) | // InvalidEinitAttribute according to PR, but does not exist.
            &Init(Ret(ErrorCode::InvalidMeasurement)) => true,
            _ => false,
        }
    }
}

macro_rules! ioctl_unsafe {
    ( $f:ident, $v:expr ) => {{
        const SGX_POWER_LOST_ENCLAVE: i32 = 0x40000000;
        const SGX_LE_ROLLBACK: i32 = 0x40000001;

        match unsafe { $v } {
            Err(_) => Err(Error::$f(SgxIoctlError::Io(IoError::last_os_error()))),
            Ok(0) => Ok(()),
            Ok(SGX_POWER_LOST_ENCLAVE) => Err(Error::$f(SgxIoctlError::PowerLostEnclave)),
            Ok(SGX_LE_ROLLBACK) => Err(Error::$f(SgxIoctlError::LeRollback)),
            Ok(v) => Err(Error::$f(SgxIoctlError::Ret(
                ErrorCode::try_from(v as u32).expect("Invalid ioctl return value"),
            ))),
        }
    }};
}

impl EnclaveLoad for InnerDevice {
    type Error = Error;

    fn new(
        mut device: Arc<InnerDevice>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let esize = ecreate.size as usize;
        let ptr = unsafe {
            match device.driver {
                External => {
                    mmap(
                        ptr::null_mut(),
                        esize,
                        Prot::PROT_READ | Prot::PROT_WRITE | Prot::PROT_EXEC,
                        Map::MAP_SHARED,
                        device.fd.as_raw_fd(),
                        0,
                    ).map_err(Error::map)?
                },
                Upstream => {
                    unsafe fn maybe_unmap(addr: *mut std::ffi::c_void, len: usize) {
                        if len == 0 {
                            return;
                        }
                        if let Err(e) = munmap(addr, len) {
                            eprintln!("SGX enclave create: munmap failed: {:?}", e);
                        }
                    }

                    // re-open device by cloning, if necessary
                    Arc::make_mut(&mut device);

                    let ptr = mmap(
                        ptr::null_mut(),
                        esize * 2,
                        Prot::PROT_NONE,
                        Map::MAP_SHARED,
                        device.fd.as_raw_fd(),
                        0,
                    ).map_err(Error::map)?;

                    let align_offset = ptr.align_offset(esize);
                    if align_offset > esize {
                        unreachable!()
                    }
                    let newptr = ptr.add(align_offset);
                    maybe_unmap(ptr, align_offset);
                    maybe_unmap(newptr.add(esize), esize - align_offset);

                    newptr
                },
            }
        };

        let mapping = Mapping {
            device,
            base: ptr as u64,
            size: ecreate.size,
            tcss: vec![],
        };

        let secs = Secs {
            baseaddr: mapping.base,
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };
        let createdata = ioctl::CreateData { secs: &secs };
        ioctl_unsafe!(
            Create,
            ioctl::create(mapping.device.fd.as_raw_fd(), &createdata)
        )?;
        Ok(mapping)
    }

    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {
        let (eadd, chunks, data) = page;
        let secinfo = Secinfo {
            flags: eadd.secinfo.flags,
            ..Default::default()
        };
        let dstpage = mapping.base + eadd.offset;
        match mapping.device.driver {
            External => {
                let adddata = ioctl::external::AddData {
                    dstpage,
                    srcpage: &data,
                    secinfo: &secinfo,
                    chunks: chunks.0,
                };
                ioctl_unsafe!(Add, ioctl::external::add(mapping.device.fd.as_raw_fd(), &adddata))
            },
            Upstream => {
                let data = ioctl::upstream::Align4096(data);
                let adddata = ioctl::upstream::AddData {
                    dstpage,
                    srcpage: &data,
                    secinfo: &secinfo,
                    chunks: chunks.0,
                    reserved: [0; 6],
                };
                ioctl_unsafe!(Add, ioctl::upstream::add(mapping.device.fd.as_raw_fd(), &adddata))?;

                let prot = match PageType::try_from(secinfo.flags.page_type()) {
                    Ok(PageType::Reg) => {
                        let mut prot = Prot::empty();
                        if secinfo.flags.intersects(SecinfoFlags::R) {
                            prot |= Prot::PROT_READ
                        }
                        if secinfo.flags.intersects(SecinfoFlags::W) {
                            prot |= Prot::PROT_WRITE
                        }
                        if secinfo.flags.intersects(SecinfoFlags::X) {
                            prot |= Prot::PROT_EXEC
                        }
                        prot
                    }
                    Ok(PageType::Tcs) => {
                        Prot::PROT_READ | Prot::PROT_WRITE
                    },
                    _ => unreachable!(),
                };
                unsafe {
                    mprotect(dstpage as _, 4096, prot).map_err(Error::map)?;
                }

                Ok(())
            }
        }
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        // ioctl() may return ENOTTY if the specified request does not apply to
        // the kind of object that the descriptor fd references.
        fn is_enotty(result: &Result<(), Error>) -> bool {
            match result {
                Err(Error::Init(SgxIoctlError::Io(ref err))) => {
                    err.raw_os_error() == Some(libc::ENOTTY)
                }
                _ => false,
            }
        }

        fn ioctl_init(mapping: &Mapping<InnerDevice>, sigstruct: &Sigstruct) -> Result<(), Error> {
            match mapping.device.driver {
                External => {
                    let initdata = ioctl::external::InitData {
                        base: mapping.base,
                        sigstruct,
                    };
                    ioctl_unsafe!(Init, ioctl::external::init(mapping.device.fd.as_raw_fd(), &initdata))
                },
                Upstream => {
                    let initdata = ioctl::upstream::InitData {
                        sigstruct,
                    };
                    ioctl_unsafe!(Init, ioctl::upstream::init(mapping.device.fd.as_raw_fd(), &initdata))
                }
            }
        }

        fn ioctl_init_with_token(
            mapping: &Mapping<InnerDevice>,
            sigstruct: &Sigstruct,
            einittoken: &Einittoken,
        ) -> Result<(), Error> {
            match mapping.device.driver {
                External => {
                    let initdata = ioctl::external::InitDataWithToken {
                        base: mapping.base,
                        sigstruct,
                        einittoken,
                    };
                    ioctl_unsafe!(
                        Init,
                        ioctl::external::init_with_token(mapping.device.fd.as_raw_fd(), &initdata)
                    )
                },
                Upstream => {
                    Err(Error::Init(SgxIoctlError::Io(IoError::from_raw_os_error(libc::ENOTTY))))
                }
            }
        }

        // Try either EINIT ioctl(), in the order that makes most sense given
        // the function arguments
        if let Some(einittoken) = einittoken {
            let res = ioctl_init_with_token(mapping, sigstruct, einittoken);

            if is_enotty(&res) {
                ioctl_init(mapping, sigstruct)
            } else {
                res
            }
        } else {
            let res = ioctl_init(mapping, sigstruct);

            if is_enotty(&res) {
                ioctl_init_with_token(mapping, sigstruct, &Default::default())
            } else {
                res
            }
        }
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe { libc::munmap(mapping.base as usize as *mut _, mapping.size as usize) };
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DriverVersion {
    External,
    Upstream,
}

#[derive(Debug)]
struct InnerDevice {
    fd: File,
    path: Arc<PathBuf>,
    driver: DriverVersion,
}

impl Clone for InnerDevice {
    fn clone(&self) -> Self {
        InnerDevice {
            fd: OpenOptions::new().read(true).write(true).open(&**self.path).unwrap(),
            path: self.path.clone(),
            driver: self.driver,
        }
    }
}

#[derive(Debug)]
pub struct Device {
    inner: generic::Device<InnerDevice>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<InnerDevice>,
}

impl Device {
    /// Open `/dev/isgx`, or if that doesn't exist, `/dev/sgx`.
    pub fn new() -> IoResult<DeviceBuilder> {
        const DEFAULT_DEVICE_PATHS: &[(&str, DriverVersion)] = &[
            ("/dev/sgx/enclave", Upstream),
            ("/dev/isgx", External),
            ("/dev/sgx", External),
        ];

        for &(path, version) in DEFAULT_DEVICE_PATHS {
            match Self::open(path, version) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => continue,
                result => return result,
            }
        }

        Err(IoError::new(io::ErrorKind::NotFound, "None of the default SGX device paths were found"))
    }

    pub fn open<T: AsRef<Path>>(path: T, driver: DriverVersion) -> IoResult<DeviceBuilder> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(InnerDevice {
                        fd: file,
                        path: Arc::new(path.to_owned()),
                        driver,
                    }),
                    einittoken_provider: None,
                },
            },
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.inner.path
    }
}

impl loader::Load for Device {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}

impl DeviceBuilder {
    pub fn einittoken_provider<P: Into<Box<dyn EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Device {
        Device {
            inner: self.inner.build(),
        }
    }
}
