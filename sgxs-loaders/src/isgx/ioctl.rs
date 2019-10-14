/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use abi;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CreateData {
    pub secs: *const abi::Secs, // with baseaddr set to actual base
}

const SGX_IOCTL: u8 = 0xa4;
ioctl_write_ptr!(create, SGX_IOCTL, 0x00, CreateData);

/// Kernel API for Intel's out-of-tree driver
pub mod external {
    use super::SGX_IOCTL;

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct AddData {
        pub dstpage: u64,
        pub srcpage: *const [u8; 4096],
        pub secinfo: *const abi::Secinfo,
        pub chunks: u16,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitDataWithToken {
        pub base: u64,
        pub sigstruct: *const abi::Sigstruct,
        pub einittoken: *const abi::Einittoken,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub base: u64,
        pub sigstruct: *const abi::Sigstruct,
    }

    ioctl_write_ptr!(add, SGX_IOCTL, 0x01, AddData);
    ioctl_write_ptr!(init_with_token, SGX_IOCTL, 0x02, InitDataWithToken);
    ioctl_write_ptr!(init, SGX_IOCTL, 0x02, InitData);
}

/// Kernel API for upstream driver
pub mod upstream {
    use super::SGX_IOCTL;

    #[repr(align(4096))]
    pub struct Align4096<T>(pub T);

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct AddData {
        pub dstpage: u64,
        pub srcpage: *const Align4096<[u8; 4096]>,
        pub secinfo: *const abi::Secinfo,
        pub chunks: u16,
        pub reserved: [u8; 6],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub sigstruct: *const abi::Sigstruct,
    }

    ioctl_write_ptr!(add, SGX_IOCTL, 0x01, AddData);
    ioctl_write_ptr!(init, SGX_IOCTL, 0x02, InitData);
}
