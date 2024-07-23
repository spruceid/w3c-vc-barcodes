use std::io::{self, BufRead, Seek};

const HEADER_SIZE: u64 = 9 + 6 + 2 + 2 + 2;

const SUBFILE_DESIGNATOR_SIZE: u64 = 2 + 4 + 4;

const DATA_ELEMENT_SEPARATOR: u8 = b'\n';

const RECORD_SEPARATOR: u8 = 0x1e;

const SEGMENT_TERMINATOR: u8 = b'\r';

const PREFIX: [u8; 9] = *b"@\n\x1e\rANSI ";

pub struct FileBuilder {
    header: Header,
    subfiles: Vec<Subfile>,
}

impl FileBuilder {
    pub fn new(issuer_id: u32, version: u8, jurisdiction_version: u8) -> Self {
        Self {
            header: Header {
                issuer_id,
                version,
                jurisdiction_version,
                entry_count: 0,
            },
            subfiles: Vec::new(),
        }
    }

    pub fn push(&mut self, subfile: impl Into<Subfile>) {
        self.subfiles.push(subfile.into());
    }

    pub fn write(mut self, writer: &mut impl io::Write) -> io::Result<()> {
        self.header.entry_count = self.subfiles.len() as u8;
        self.header.encode(writer)?;

        let mut offset = HEADER_SIZE + SUBFILE_DESIGNATOR_SIZE * self.subfiles.len() as u64;
        for subfile in &self.subfiles {
            let length = 2u64 + subfile.data.len() as u64;
            SubfileDesignator {
                subfile_type: subfile.subfile_type,
                offset,
                length,
            }
            .encode(writer)?;
            offset += length;
        }

        for subfile in &self.subfiles {
            subfile.write(writer)?;
        }

        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut cursor = io::Cursor::new(&mut result);
        self.write(&mut cursor).unwrap();
        result
    }
}

pub struct Subfile {
    pub subfile_type: [u8; 2],
    pub data: Vec<u8>,
}

impl Subfile {
    pub fn new(subfile_type: [u8; 2], data: Vec<u8>) -> Self {
        Self { subfile_type, data }
    }

    pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
        write_array(writer, self.subfile_type)?;
        writer.write_all(&self.data)
    }
}

pub struct File<'a, R> {
    header: Header,
    subfile_designators: Vec<SubfileDesignator>,
    reader: &'a mut R,
}

impl<'a, R: BufRead> File<'a, R> {
    pub fn new(reader: &'a mut R) -> io::Result<Self> {
        let header = Header::decode(reader)?;

        let entry_count = header.entry_count as usize;
        let mut subfile_designators = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            subfile_designators.push(SubfileDesignator::decode(reader)?);
        }

        Ok(Self {
            header,
            subfile_designators,
            reader,
        })
    }

    pub fn header(&self) -> Header {
        self.header
    }

    pub fn index_of(&self, subfile_type: &[u8; 2]) -> Option<usize> {
        self.subfile_designators
            .iter()
            .position(|d| d.subfile_type == *subfile_type)
    }
}

impl<'a, R: BufRead + Seek> File<'a, R> {
    pub fn read_subfile<D: DecodeSubfile>(
        &mut self,
        subfile_type: &[u8; 2],
    ) -> io::Result<Option<D>> {
        match self.index_of(subfile_type) {
            Some(i) => self.read_subfile_by_index(i).map(Some),
            None => Ok(None),
        }
    }

    pub fn read_subfile_by_index<D: DecodeSubfile>(&mut self, index: usize) -> io::Result<D> {
        let desc = &self.subfile_designators[index];
        self.reader.seek(io::SeekFrom::Start(desc.offset))?;
        D::decode_subfile(self.reader)
    }
}

pub trait DecodeSubfile: Sized {
    fn decode_subfile(reader: &mut impl BufRead) -> io::Result<Self>;

    fn decode_subfile_from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let mut cursor = io::Cursor::new(bytes);
        Self::decode_subfile(&mut cursor)
    }
}

pub struct Record {
    subfile_type: [u8; 2],
    entries: Vec<RecordEntry>,
}

impl Record {
    fn write_entries(&self, writer: &mut impl io::Write) -> io::Result<()> {
        assert!(!self.entries.is_empty());
        let last = self.entries.len() - 1;
        for (i, entry) in self.entries.iter().enumerate() {
            entry.encode(writer, i == last)?;
        }

        Ok(())
    }
}

impl DecodeSubfile for Record {
    fn decode_subfile(reader: &mut impl BufRead) -> io::Result<Self> {
        let subfile_type = read_array(reader)?;
        let mut entries = Vec::new();

        loop {
            let (entry, last) = RecordEntry::decode(reader)?;
            entries.push(entry);

            if last {
                break Ok(Self {
                    subfile_type,
                    entries,
                });
            }
        }
    }
}

impl From<Record> for Subfile {
    fn from(value: Record) -> Self {
        let mut data = Vec::new();
        let mut cursor = io::Cursor::new(&mut data);
        value.write_entries(&mut cursor).unwrap();

        Subfile {
            subfile_type: value.subfile_type,
            data,
        }
    }
}

impl DecodeSubfile for Vec<u8> {
    fn decode_subfile(reader: &mut impl BufRead) -> io::Result<Self> {
        let mut result = Vec::new();

        loop {
            let b = read_u8(reader)?;
            result.push(b);
            if b == SEGMENT_TERMINATOR {
                break Ok(result);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub issuer_id: u32,
    pub version: u8,
    pub jurisdiction_version: u8,
    pub entry_count: u8,
}

impl Header {
    pub fn decode(reader: &mut impl BufRead) -> io::Result<Self> {
        if read_array(reader)? != PREFIX {
            return Err(io::ErrorKind::InvalidData.into());
        }

        Ok(Self {
            issuer_id: decode_digits6(read_array(reader)?)?,
            version: decode_digits2(read_array(reader)?)?,
            jurisdiction_version: decode_digits2(read_array(reader)?)?,
            entry_count: decode_digits2(read_array(reader)?)?,
        })
    }

    pub fn encode(&self, writer: &mut impl io::Write) -> io::Result<()> {
        writer.write_all(&PREFIX)?;
        write_array(writer, encode_digits6(self.issuer_id))?;
        write_array(writer, encode_digits2(self.version))?;
        write_array(writer, encode_digits2(self.jurisdiction_version))?;
        write_array(writer, encode_digits2(self.entry_count))?;
        Ok(())
    }
}

pub struct SubfileDesignator {
    pub subfile_type: [u8; 2],
    pub offset: u64,
    pub length: u64,
}

impl SubfileDesignator {
    pub fn decode(reader: &mut impl BufRead) -> io::Result<Self> {
        Ok(Self {
            subfile_type: read_array(reader)?,
            offset: decode_digits4(read_array(reader)?)?,
            length: decode_digits4(read_array(reader)?)?,
        })
    }

    pub fn encode(&self, writer: &mut impl io::Write) -> io::Result<()> {
        write_array(writer, self.subfile_type)?;
        write_array(writer, encode_digits4(self.offset))?;
        write_array(writer, encode_digits4(self.length))
    }
}

pub(crate) fn read_array<const N: usize>(reader: &mut impl BufRead) -> io::Result<[u8; N]> {
    let mut buffer = [0; N];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn write_array<const N: usize>(
    writer: &mut impl io::Write,
    array: [u8; N],
) -> io::Result<()> {
    writer.write_all(&array)
}

fn decode_digit(d: u8) -> io::Result<u8> {
    if (b'0'..=b'9').contains(&d) {
        Ok(d - b'0')
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

fn encode_digit(value: u8) -> u8 {
    value + b'0'
}

fn decode_digits2(digits: [u8; 2]) -> io::Result<u8> {
    Ok(decode_digit(digits[0])? * 10 + decode_digit(digits[1])?)
}

fn encode_digits2(value: u8) -> [u8; 2] {
    [encode_digit((value / 10) % 10), encode_digit(value % 10)]
}

fn decode_digits4(digits: [u8; 4]) -> io::Result<u64> {
    Ok(decode_digit(digits[0])? as u64 * 1000
        + decode_digit(digits[1])? as u64 * 100
        + decode_digit(digits[2])? as u64 * 10
        + decode_digit(digits[3])? as u64)
}

fn encode_digits4(value: u64) -> [u8; 4] {
    [
        encode_digit(((value / 1000) % 10) as u8),
        encode_digit(((value / 100) % 10) as u8),
        encode_digit(((value / 10) % 10) as u8),
        encode_digit((value % 10) as u8),
    ]
}

fn decode_digits6(digits: [u8; 6]) -> io::Result<u32> {
    Ok(decode_digit(digits[0])? as u32 * 100000
        + decode_digit(digits[1])? as u32 * 10000
        + decode_digit(digits[2])? as u32 * 1000
        + decode_digit(digits[3])? as u32 * 100
        + decode_digit(digits[4])? as u32 * 10
        + decode_digit(digits[5])? as u32)
}

fn encode_digits6(value: u32) -> [u8; 6] {
    [
        encode_digit(((value / 100000) % 10) as u8),
        encode_digit(((value / 10000) % 10) as u8),
        encode_digit(((value / 1000) % 10) as u8),
        encode_digit(((value / 100) % 10) as u8),
        encode_digit(((value / 10) % 10) as u8),
        encode_digit((value % 10) as u8),
    ]
}

fn read_u8(reader: &mut impl BufRead) -> io::Result<u8> {
    let mut value = 0;
    reader.read_exact(std::slice::from_mut(&mut value))?;
    Ok(value)
}

fn write_u8(writer: &mut impl io::Write, value: u8) -> io::Result<()> {
    writer.write_all(std::slice::from_ref(&value))
}

pub struct RecordEntry {
    pub field: [u8; 3],
    pub value: Vec<u8>,
}

impl RecordEntry {
    pub fn decode(reader: &mut impl io::BufRead) -> io::Result<(Self, bool)> {
        let field: [u8; 3] = read_array(reader)?;
        let mut value = Vec::new();

        let last = loop {
            match read_u8(reader)? {
                DATA_ELEMENT_SEPARATOR => break false,
                RECORD_SEPARATOR => return Err(io::ErrorKind::InvalidData.into()),
                SEGMENT_TERMINATOR => break true,
                b => value.push(b),
            }
        };

        Ok((Self { field, value }, last))
    }

    pub fn encode_ref(
        writer: &mut impl io::Write,
        field: &[u8; 3],
        value: &[u8],
        last: bool,
    ) -> io::Result<()> {
        write_array(writer, *field)?;
        writer.write_all(value)?;
        if last {
            write_u8(writer, SEGMENT_TERMINATOR)
        } else {
            write_u8(writer, DATA_ELEMENT_SEPARATOR)
        }
    }

    pub fn encode(&self, writer: &mut impl io::Write, last: bool) -> io::Result<()> {
        Self::encode_ref(writer, &self.field, &self.value, last)
    }
}
