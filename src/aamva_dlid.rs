/// AAMVA DL/ID Card Design Standard.
///
/// See: <https://www.aamva.org/assets/best-practices,-guides,-standards,-manuals,-whitepapers/aamva-dl-id-card-design-standard-(2020)>
macro_rules! mandatory_data_elements {
	($($(#[$meta:meta])* $id:ident : $tag:literal),*) => {
		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		pub enum MandatoryDataElement {
			$($(#[$meta])* $id),*
		}

		impl MandatoryDataElement {
			pub const LIST: [Self; 22] = [$(Self::$id),*];

			pub fn from_id(id: &[u8; 3]) -> Option<Self> {
				match id {
					$($tag => Some(Self::$id),)*
					_ => None
				}
			}

			pub fn id(&self) -> &'static [u8; 3] {
				match self {
					$(Self::$id => $tag),*
				}
			}
		}
	};
}

impl MandatoryDataElement {
    pub fn string_id(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.id()) }
    }
}

mandatory_data_elements! {
    /// Jurisdiction-specific vehicle class.
    VehicleClass: b"DCA",

    /// Jurisdiction-specific restriction codes.
    RestrictionCodes: b"DCB",

    /// Jurisdiction-specific endorsement codes.
    EndorsementCodes: b"DCD",

    /// Document Expiration Date.
    DocumentExpirationDate: b"DBA",

    /// Customer Family Name.
    CustomerFamilyName: b"DCS",

    /// Customer First Name.
    CustomerFirstName: b"DAC",

    /// Customer Middle Name(s).
    CustomerMiddleName: b"DAD",

    /// Document Issue Date.
    DocumentIssueDate: b"DBD",

    /// Date of Birth.
    DateOfBirth: b"DBB",

    /// Physical Description – Sex.
    PhysicalDescriptionSex: b"DBC",

    /// Physical Description – Eye Color.
    PhysicalDescriptionEyeColor: b"DAY",

    /// Physical Description – Height.
    PhysicalDescriptionHeight: b"DAU",

    /// Address – Street 1.
    AddressStreet1: b"DAG",

    /// Address – City.
    AddressCity: b"DAI",

    /// Address – Jurisdiction Code.
    AddressJurisdictionCode: b"DAJ",

    /// Address – Postal Code.
    AddressPostalCode: b"DAK",

    /// Customer ID Number.
    CustomerIdNumber: b"DAQ",

    /// Document Discriminator.
    DocumentDiscriminator: b"DCF",

    /// Country Identification.
    CountryIdentification: b"DCG",

    /// Family name truncation.
    FamilyNameTruncation: b"DDE",

    /// First name truncation.
    FirstNameTruncation: b"DDF",

    /// Middle name truncation.
    MiddleNameTruncation: b"DDG"
}
