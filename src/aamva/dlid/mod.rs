/// AAMVA DL/ID Card Design Standard.
///
/// See: <https://www.aamva.org/assets/best-practices,-guides,-standards,-manuals,-whitepapers/aamva-dl-id-card-design-standard-(2020)>
mod macros;
use std::io;

pub(crate) use macros::*;

pub mod types;

#[derive(Debug, thiserror::Error)]
#[error("missing data element `{0}`")]
pub struct MissingDataElement<T>(pub T);

impl<T> From<MissingDataElement<T>> for io::Error {
    fn from(_value: MissingDataElement<T>) -> Self {
        io::ErrorKind::InvalidData.into()
    }
}

mod dl;
pub use dl::*;
mod id;
pub use id::*;

pub mod pdf_417;
pub use pdf_417::File;
