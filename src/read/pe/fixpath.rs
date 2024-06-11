use crate::{Error, ReadError, ReadRef};
use crate::pe::{FixDataHeader};

/// FixPath data structure parser to access '.fixPath' section in PE header
pub fn parse(data: &[u8], offset: u32) -> Result<FixDataHeader, Error> {
        let mut offset = u64::from(offset);
        let header = data
            .read::<FixDataHeader>(&mut offset)
            .read_error("Invalid resource table header")?;
        Ok(*header)
}





