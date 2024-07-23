use std::io;

use super::{
    mandatory_data_elements, optional_data_elements,
    pdf_417::{read_array, DecodeSubfile, RecordEntry, Subfile},
    MissingDataElement,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DlElement {
    Mandatory(DlMandatoryElement),
    Optional(DlOptionalElement),
}

impl DlElement {
    pub fn from_id(id: &[u8; 3]) -> Option<Self> {
        DlMandatoryElement::from_id(id)
            .map(Self::Mandatory)
            .or_else(|| DlOptionalElement::from_id(id).map(Self::Optional))
    }

    pub fn id(&self) -> &'static [u8; 3] {
        match self {
            Self::Mandatory(e) => e.id(),
            Self::Optional(e) => e.id(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DlSubfile {
    pub mandatory: DlMandatoryElements,
    pub optional: DlOptionalElements,
}

impl DlSubfile {
    pub fn new(mandatory: DlMandatoryElements) -> Self {
        Self {
            mandatory,
            optional: DlOptionalElements::new(),
        }
    }

    pub fn len(&self) -> usize {
        DlMandatoryElement::COUNT + self.optional.len()
    }

    pub fn get(&self, element: DlElement) -> Option<&[u8]> {
        match element {
            DlElement::Mandatory(e) => Some(self.mandatory.get(e)),
            DlElement::Optional(e) => self.optional.get(e),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (DlElement, &[u8])> {
        self.mandatory
            .iter()
            .map(|(k, v)| (DlElement::Mandatory(k), v))
            .chain(
                self.optional
                    .iter()
                    .map(|(k, v)| (DlElement::Optional(k), v)),
            )
    }
}

pub struct DlSubfileBuilder {
    mandatory: DlMandatoryElementsBuilder,
    optional: DlOptionalElements,
}

impl DlSubfileBuilder {
    pub fn new() -> Self {
        Self {
            mandatory: DlMandatoryElementsBuilder::new(),
            optional: DlOptionalElements::new(),
        }
    }

    pub fn set(&mut self, element: DlElement, value: Vec<u8>) {
        match element {
            DlElement::Mandatory(element) => self.mandatory.set(element, value),
            DlElement::Optional(element) => self.optional.set(element, Some(value)),
        }
    }

    pub fn build(self) -> Result<DlSubfile, MissingDataElement<DlMandatoryElement>> {
        Ok(DlSubfile {
            mandatory: self.mandatory.build()?,
            optional: self.optional,
        })
    }
}

impl DecodeSubfile for DlSubfile {
    fn decode_subfile(reader: &mut impl std::io::prelude::BufRead) -> std::io::Result<Self> {
        if read_array(reader)? != *b"DL" {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut builder = DlSubfileBuilder::new();

        loop {
            let (entry, last) = RecordEntry::decode(reader)?;
            let element =
                DlElement::from_id(&entry.field).ok_or_else(|| io::ErrorKind::InvalidData)?;
            builder.set(element, entry.value);

            if last {
                break Ok(builder.build()?);
            }
        }
    }
}

impl From<DlSubfile> for Subfile {
    fn from(value: DlSubfile) -> Self {
        let last = value.len() - 1;
        let mut data = Vec::new();
        let mut cursor = io::Cursor::new(&mut data);
        for (i, (e, v)) in value.iter().enumerate() {
            RecordEntry::encode_ref(&mut cursor, e.id(), v, i == last).unwrap();
        }

        Self::new(*b"DL", data)
    }
}

mandatory_data_elements! {
    pub enum DlMandatoryElement, struct DlMandatoryElements (DlMandatoryElementsBuilder) {
        /// Customer ID Number (DAQ).
        customer_id_number: V25Ans => CustomerIdNumber: b"DAQ",

        /// Customer Family Name (DCS).
        customer_family_name: V40Ans => CustomerFamilyName: b"DCS",

        /// Family name truncation (DDE).
        family_name_truncation: F1A => FamilyNameTruncation: b"DDE",

        /// Customer First Name (DAC).
        customer_first_name: V40Ans => CustomerFirstName: b"DAC",

        /// First name truncation (DDF).
        first_name_truncation: F1A => FirstNameTruncation: b"DDF",

        /// Customer Middle Name(s) (DAD).
        customer_middle_name: V40Ans => CustomerMiddleName: b"DAD",

        /// Middle name truncation (DDG).
        middle_name_truncation: F1A => MiddleNameTruncation: b"DDG",

        /// Jurisdiction-specific vehicle class (DCA).
        vehicle_class: V6Ans => VehicleClass: b"DCA",

        /// Jurisdiction-specific restriction codes (DCB).
        restriction_codes: V12Ans => RestrictionCodes: b"DCB",

        /// Jurisdiction-specific endorsement codes (DCD).
        endorsement_codes: V5Ans => EndorsementCodes: b"DCD",

        /// Document Issue Date (DBD).
        document_issue_date: F8N => DocumentIssueDate: b"DBD",

        /// Date of Birth (DBB).
        date_of_birth: F8N => DateOfBirth: b"DBB",

        /// Document Expiration Date (DBA).
        document_expiration_date: F8N => DocumentExpirationDate: b"DBA",

        /// Physical Description – Sex (DBC).
        sex: F1N => Sex: b"DBC",

        /// Physical Description – Height (DAU).
        height: F6Ans => Height: b"DAU",

        /// Physical Description – Eye Color (DAY).
        eye_color: F3A => EyeColor: b"DAY",

        /// Address – Street 1 (DAG).
        address_street_1: V35Ans => AddressStreet1: b"DAG",

        /// Address – City (DAI).
        address_city: V20Ans => AddressCity: b"DAI",

        /// Address – Jurisdiction Code (DAJ).
        address_jurisdiction_code: F2A => AddressJurisdictionCode: b"DAJ",

        /// Address – Postal Code (DAK).
        address_postal_code: F11Ans => AddressPostalCode: b"DAK",

        /// Document Discriminator (DCF).
        document_discriminator: V25Ans => DocumentDiscriminator: b"DCF",

        /// Country Identification (DCG).
        country_identification: F3A => CountryIdentification: b"DCG"
    }
}

optional_data_elements! {
    pub enum DlOptionalElement, struct DlOptionalElements {
        /// Second line of street portion of the cardholder address (DAH).
        address_street_2: V35Ans => AddressStreet2: b"DAH",

        /// Cardholder weight in pounds (DAW).
        weight_in_pounds: F3N => WeightInPounds: b"DAW",

        /// Cardholder weight in kilograms (DAX).
        weight_in_kilograms: F3N => WeightInKilograms: b"DAX",

        /// Hair color (DAZ).
        hair_color: V12A => HairColor: b"DAZ",

        /// Place (Country and municipality and/or state/province) of birth
        /// (DCI).
        place_of_birth: V33A => PlaceOfBirth: b"DCI",

        /// String of letters and/or numbers that identifies when, where, and by
        /// whom a driver license/ID card was made (DCJ).
        audit_information: V25Ans => AuditInformation: b"DCJ",

        /// String of letters and/or numbers that is affixed to the raw
        /// materials (card stock, laminate, etc.) used in producing driver
        /// licenses and ID cards (DCK).
        inventory_control_number: V25Ans => InventoryControlNumber: b"DCK",

        /// Other family name by which cardholder is known (DBN).
        aka_family_name: V10Ans => AkaFamilyName: b"DBN",

        /// Other given name by which cardholder is known (DBG).
        aka_given_name: V15Ans => AkaGivenName: b"DBG",

        /// Other suffix by which cardholder is known (DBS).
        aka_suffix_name: V5Ans => AkaSuffixName: b"DBS",

        /// Name Suffix (DCU).
        name_suffix: V5Ans => NameSuffix: b"DCU",

        /// Approximate weight range of the cardholder (DCE).
        weight_range: F1N => WeightRange: b"DCE",

        /// Codes for race or ethnicity of the cardholder, as defined in AAMVA
        /// D20 (DCL).
        race_or_ethnicity: V3A => RaceOrEthnicity: b"DCL",

        /// Standard vehicle classification code(s) for cardholder (DCM).
        standard_vehicle_class: F4An => StandardVehicleClass: b"DCM",

        /// Standard endorsement code(s) for cardholder (DCN).
        standard_endorsement_code: F5An => StandardEndorsementCode: b"DCN",

        /// Standard restriction code(s) for cardholder (DCO).
        standard_restriction_code: F12An => StandardRestrictionCode: b"DCO",

        /// Text that explains the jurisdiction-specific code(s) for
        /// classifications of vehicles cardholder is authorized to drive (DCP).
        vehicle_class_description: V50Ans => VehicleClassDescription: b"DCP",

        /// Text that explains the jurisdiction-specific code(s) that indicates
        /// additional driving privileges granted to the cardholder beyond the
        /// vehicle class (DCQ).
        endorsement_code_description: V50Ans => EndorsementCodeDescription: b"DCQ",

        /// Text describing the jurisdiction-specific restriction code(s) that
        /// curtail driving privileges (DCR).
        restriction_code_description: V50Ans => RestrictionCodeDescription: b"DCR",

        /// DHS required field that indicates compliance (DDA).
        compliance_type: F1A => ComplianceType: b"DDA",

        /// DHS required field that indicates date of the most recent version
        /// change or modification to the visible format of the DL/ID (DDB).
        card_revision_date: F8N => CardRevisionDate: b"DDB",

        /// Date on which the hazardous material endorsement granted by the
        /// document is no longer valid (DDC).
        hazmat_endorsement_expiration_date: F8N => HazmatEndorsementExpirationDate: b"DDC",

        /// DHS required field that indicates that the cardholder has temporary
        /// lawful status = "1" (DDD).
        limited_duration_document_indicator: F1N => LimitedDurationDocumentIndicator: b"DDD",

        /// Date on which the cardholder turns 18 years old (DDH).
        under_18_until: F8N => Under18Until: b"DDH",

        /// Date on which the cardholder turns 19 years old (DDI).
        under_19_until: F8N => Under19Until: b"DDI",

        /// Date on which the cardholder turns 21 years old (DDJ).
        under_21_until: F8N => Under21Until: b"DDJ",

        /// Field that indicates that the cardholder is an organ donor = "1"
        /// (DDK).
        organ_donor_indicator: F1N => OrganDonorIndicator: b"DDK",

        /// Field that indicates that the cardholder is a veteran = "1" (DDL).
        veteran_indicator: F1N => VeteranIndicator: b"DDL"
    }
}
