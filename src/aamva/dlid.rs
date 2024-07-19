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
    /// Jurisdiction-specific vehicle class (DCA).
    VehicleClass: b"DCA",

    /// Jurisdiction-specific restriction codes (DCB).
    RestrictionCodes: b"DCB",

    /// Jurisdiction-specific endorsement codes (DCD).
    EndorsementCodes: b"DCD",

    /// Document Expiration Date (DBA).
    DocumentExpirationDate: b"DBA",

    /// Customer Family Name (DCS).
    CustomerFamilyName: b"DCS",

    /// Customer First Name (DAC).
    CustomerFirstName: b"DAC",

    /// Customer Middle Name(s) (DAD).
    CustomerMiddleName: b"DAD",

    /// Document Issue Date (DBD).
    DocumentIssueDate: b"DBD",

    /// Date of Birth (DBB).
    DateOfBirth: b"DBB",

    /// Physical Description – Sex (DBC).
    PhysicalDescriptionSex: b"DBC",

    /// Physical Description – Eye Color (DAY).
    PhysicalDescriptionEyeColor: b"DAY",

    /// Physical Description – Height (DAU).
    PhysicalDescriptionHeight: b"DAU",

    /// Address – Street 1 (DAG).
    AddressStreet1: b"DAG",

    /// Address – City (DAI).
    AddressCity: b"DAI",

    /// Address – Jurisdiction Code (DAJ).
    AddressJurisdictionCode: b"DAJ",

    /// Address – Postal Code (DAK).
    AddressPostalCode: b"DAK",

    /// Customer ID Number (DAQ).
    CustomerIdNumber: b"DAQ",

    /// Document Discriminator (DCF).
    DocumentDiscriminator: b"DCF",

    /// Country Identification (DCG).
    CountryIdentification: b"DCG",

    /// Family name truncation (DDE).
    FamilyNameTruncation: b"DDE",

    /// First name truncation (DDF).
    FirstNameTruncation: b"DDF",

    /// Middle name truncation (DDG).
    MiddleNameTruncation: b"DDG"
}
