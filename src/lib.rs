use serde::Serialize;

#[derive(Serialize)]
pub struct Macho {
    header: Header,
}

/*
struct mach_header_64 {
------    uint32_t	magic;		/* mach magic number identifier */
    int32_t		cputype;	/* cpu specifier */
    int32_t		cpusubtype;	/* machine specifier */
    uint32_t	filetype;	/* type of file */
    uint32_t	ncmds;		/* number of load commands */
    uint32_t	sizeofcmds;	/* the size of all the load commands */
    uint32_t	flags;		/* flags */
    uint32_t	reserved;	/* reserved */
};
*/
pub const MAGIC_HEADER: u32 = 0xfeedfacf;

#[derive(Serialize)]
pub struct Header {
    cpu_type: CPUType,
}

/*
#define CPU_TYPE_MC680x0        ((cpu_type_t) 6)
#define CPU_TYPE_X86            ((cpu_type_t) 7)
#define CPU_TYPE_I386           CPU_TYPE_X86            /* compatibility */
#define CPU_TYPE_X86_64         (CPU_TYPE_X86 | CPU_ARCH_ABI64)

/* skip CPU_TYPE_MIPS		((cpu_type_t) 8)	*/
/* skip                         ((cpu_type_t) 9)	*/
#define CPU_TYPE_MC98000        ((cpu_type_t) 10)
#define CPU_TYPE_HPPA           ((cpu_type_t) 11)
#define CPU_TYPE_ARM            ((cpu_type_t) 12)
#define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64_32       (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)
#define CPU_TYPE_MC88000        ((cpu_type_t) 13)
#define CPU_TYPE_SPARC          ((cpu_type_t) 14)
#define CPU_TYPE_I860           ((cpu_type_t) 15)
 */

const CPU_ARCH_ABI64: i32 = 0x01000000;

#[repr(i32)]
#[derive(Serialize)]
pub enum CPUType {
    X86_64 = 7 | CPU_ARCH_ABI64,
    ARM64 = 12 | CPU_ARCH_ABI64,
}

pub fn parse(data: &[u8]) -> Result<Macho, String> {
    let mut reader = DataReader::new(data);
    let header = parse_header(&mut reader)?;
    Ok(Macho { header })
}

fn parse_header(reader: &mut DataReader) -> Result<Header, String> {
    let magic = reader.read_u32();
    if magic != MAGIC_HEADER {
        return Err("not a mach-o 64 file".to_string());
    }
    let cpu_type = parse_cpu_type(reader.read_i32())?;

    Ok(Header { cpu_type })
}

fn parse_cpu_type(v: i32) -> Result<CPUType, String> {
    if v == CPUType::X86_64 as i32 {
        Ok(CPUType::X86_64)
    } else if v == CPUType::ARM64 as i32 {
        Ok(CPUType::ARM64)
    } else {
        Err(format!("unsupported cpu_type: {:x}", v))
    }
}

pub struct DataReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl DataReader<'_> {
    pub fn new(data: &[u8]) -> DataReader<'_> {
        DataReader::new_with_offset(data, 0)
    }

    pub fn new_with_offset(data: &[u8], offset: usize) -> DataReader<'_> {
        DataReader { data, offset }
    }
}

impl DataReader<'_> {
    pub fn read_utf8_string(&mut self, size: usize) -> String {
        let str =
            String::from_utf8_lossy(&self.data[self.offset..(self.offset + size)]).to_string();
        self.offset += size;
        str
    }

    pub fn read_u32(&mut self) -> u32 {
        let u = u32::from_le_bytes(
            self.data[self.offset..(self.offset + 4)]
                .try_into()
                .unwrap(),
        );
        self.offset += 4;
        u
    }

    pub fn read_i32(&mut self) -> i32 {
        let i = i32::from_le_bytes(
            self.data[self.offset..(self.offset + 4)]
                .try_into()
                .unwrap(),
        );
        self.offset += 4;
        i
    }

    pub fn read_u16(&mut self) -> u16 {
        let u = u16::from_le_bytes(
            self.data[self.offset..(self.offset + 2)]
                .try_into()
                .unwrap(),
        );
        self.offset += 2;
        u
    }

    pub fn read_i16(&mut self) -> i16 {
        let i = i16::from_le_bytes(
            self.data[self.offset..(self.offset + 2)]
                .try_into()
                .unwrap(),
        );
        self.offset += 2;
        i
    }

    pub fn read_u8(&mut self) -> u8 {
        let u = self.data[self.offset];
        self.offset += 1;
        u
    }

    pub fn read_bool(&mut self) -> bool {
        let u = self.read_u16();
        u != 0
    }

    // returns a slice over the bytes that were not read so far
    pub fn unread_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    pub fn slice(&self, start: usize, end: usize) -> &[u8] {
        &self.data[start..end]
    }

    pub fn skip(&mut self, bytes: usize) {
        self.offset += bytes;
    }

    pub fn offset(&self) -> usize {
        return self.offset;
    }
}
