use alloc::vec::Vec;
use std::string::String;

use crate::{Bytes, Error, ReadError, ReadRef};
use crate::pe::{FixPathHeader};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// Extracted information from the PE's fixPath section
pub struct FixPathSection<'data> {
        /// Bytes is used to mmap and read all values in memory
        pub section_data: Bytes<'data>,
        /// Stores version, fix_path_size and other FixPath header information
        pub header: FixPathHeader,
}

/// FixPath data structure parser to access '.fixPath' section in PE header
pub fn parse(data: &[u8], offset: u32) -> Result<FixPathSection<'_>, Error> {
        let mut offset = u64::from(offset);
        let fix_path_header = data
            .read::<FixPathHeader>(&mut offset)
            .read_error("Invalid resource table header")?;
        let fix_path_section = FixPathSection {
                section_data: Bytes(data),
                header: *fix_path_header,
        };
        Ok(fix_path_section)
}

/// Convert a [u8] array into a [String] while remembering the last read position inside offset [usize]
fn read_next_fixpath_import_dll_name(data: &[u8], offset: &mut usize) -> Result<String, Error> {
        let info = Bytes(data);
        let s = info
            .read_string_at(*offset)
            .read_error("Invalid PE forwarded export address");
        match s {
                Ok(v) => {
                        match std::str::from_utf8(v) {
                                Ok(t) => {
                                        *offset += t.len() + 1;
                                        Ok(t.parse().unwrap())
                                },
                                Err(e) => {
                                        println!("{e}");
                                        core::prelude::v1::Err(Error("error"))
                                }
                        }
                },
                Err(e) => Err(e)
        }
}

/// Used to extract _n_ [u32] dllNames [Strings] from memory in the .fixPath section
pub fn read_fixpath_import_dll_names(data: &[u8], offset: &mut usize, size: u32) -> Result<Vec<String>, Error> {
        let mut s: u32 = size;
        let mut res: Vec<String> = vec![];
        loop {
                match read_next_fixpath_import_dll_name(data, offset) {
                        Ok(r) => {
                                res.push(r)
                        },
                        Err(_) => break
                }
                s -= 1;
                if s == 0 {
                        break;
                }
        }
        // println!("{:?}", res);
        Ok(res)
}

