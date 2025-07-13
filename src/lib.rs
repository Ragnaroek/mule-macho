use serde::Serialize;

#[derive(Serialize)]
pub struct Macho {
    header: Header,
    load_commands: Vec<LoadCommand>,
}

// Header

pub const MAGIC_HEADER: u32 = 0xfeedfacf;

#[derive(Serialize)]
pub struct Header {
    cpu_type: CPUType,
    cpu_sub_type: CPUSubType,
    file_type: FileType,
    no_cmds: usize,
    size_of_cmds: usize,
    flags: Vec<HeaderFlag>,
}

const CPU_ARCH_ABI64: i32 = 0x01000000;

#[repr(i32)]
#[derive(Serialize, Copy, Clone, PartialEq)]
pub enum CPUType {
    X86_64 = 7 | CPU_ARCH_ABI64,
    ARM64 = 12 | CPU_ARCH_ABI64,
}

#[repr(i32)]
#[derive(Serialize)]
pub enum CPUSubType {
    ARM_ALL = 0,
}

#[repr(u32)]
#[derive(Serialize)]
pub enum FileType {
    MH_OBJECT = 0x1,   /* relocatable object file */
    MH_EXECUTED = 0x2, /* demand paged executable file */
}

#[repr(u32)]
#[derive(Serialize, Copy, Clone)]
pub enum HeaderFlag {
    MH_NOUNDEFS = 0x01, /* the object file has no undefined references */
    MH_INCRLINK = 0x02, /* the object file is the output of an incremental link against a base file
                        and can't be link edited again */
    MH_DYLDLINK = 0x4, /* the object file is input for the dynamic linker and can't be staticly
                       link edited again */
    MH_BINDATLOAD = 0x8, /* the object file's undefined references are bound by the dynamic
                         linker when loaded. */
    MH_PREBOUND = 0x10, /* the file has its dynamic undefined references prebound. */
    MH_SPLIT_SEGS = 0x20, /* the file has its read-only and read-write segments split */
    MH_LAZY_INIT = 0x40, /* the shared library init routine is to be run lazily via catching memory
                        faults to its writeable segments (obsolete) */
    MH_TWOLEVEL = 0x80,    /* the image is using two-level name space bindings */
    MH_FORCE_FLAT = 0x100, /* the executable is forcing all images to use flat name space bindings */
    MH_NOMULTIDEFS = 0x200, /* this umbrella guarantees no multiple defintions of symbols in its
                           sub-images so the two-level namespace hints can always be used. */
    MH_NOFIXPREBINDING = 0x400, /* do not have dyld notify the prebinding agent about this executable */
    MH_PREBINDABLE = 0x800, /* the binary is not prebound but can have its prebinding redone. only used
                            when MH_PREBOUND is not set. */
    MH_ALLMODSBOUND = 0x1000, /* indicates that this binary binds to all two-level namespace modules of
                              its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL
                              are both set. */
    MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000, /* safe to divide up the sections into sub-sections via symbols for dead
                                         code stripping */
    MH_CANONICAL = 0x4000, /* the binary has been canonicalized via the unprebind operation */
    MH_WEAK_DEFINES = 0x8000, /* the final linked image contains external weak symbols */
    MH_BINDS_TO_WEAK = 0x10000, /* the final linked image uses weak symbols */
    MH_ALLOW_STACK_EXECUTION = 0x20000, /* When this bit is set, all stacks in the task will be given stack
                                        execution privilege.  Only used in MH_EXECUTE filetypes. */
    MH_ROOT_SAFE = 0x40000, /* When this bit is set, the binary declares it is safe for use in
                            processes with uid zero */
    MH_SETUID_SAFE = 0x80000, /* When this bit is set, the binary declares it is safe for use in
                              processes when issetugid() is true */
    MH_NO_REEXPORTED_DYLIBS = 0x100000, /* When this bit is set on a dylib, the static linker does not need to
                                        examine dependent dylibs to see if any are re-exported */
    MH_PIE = 0x200000, /* When this bit is set, the OS will load the main executable at a
                       random address.  Only used in MH_EXECUTE filetypes. */
    MH_DEAD_STRIPPABLE_DYLIB = 0x400000, /* Only for use on dylibs.  When linking against a dylib that
                                         has this bit set, the static linker will automatically not create a
                                         LC_LOAD_DYLIB load command to the dylib if no symbols are being
                                         referenced from the dylib. */
    MH_HAS_TLV_DESCRIPTORS = 0x800000, /* Contains a section of type S_THREAD_LOCAL_VARIABLES */
    MH_NO_HEAP_EXECUTION = 0x1000000, /* When this bit is set, the OS will run the main executable with
                                      a non-executable heap even on platforms (e.g. i386) that don't
                                      require it. Only used in MH_EXECUTE filetypes. */
    MH_APP_EXTENSION_SAFE = 0x02000000, /* The code was linked for use in an application extension. */
    MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000, /* The external symbols listed in the nlist symbol table do
                                                   not include all the symbols listed in the dyld info. */
    MH_SIM_SUPPORT = 0x08000000, /* Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with
                                 the platforms macOS, macCatalyst, iOSSimulator, tvOSSimulator and
                                 watchOSSimulator. */
    MH_IMPLICIT_PAGEZERO = 0x10000000, /* main executable has no __PAGEZERO segment.  Instead, loader (xnu)
                                       will load program high and block out all memory below it. */
    MH_DYLIB_IN_CACHE = 0x80000000, /* Only for use on dylibs. When this bit is set, the dylib is part of the dyld
                                    shared cache, rather than loose in
                                    the filesystem. */
}

// Load Commands

const LC_REQ_DYLD: u32 = 0x80000000;
const LC_DYLD_INFO_ONLY: u32 = LC_REQ_DYLD | 0x22;
const LC_MAIN: u32 = LC_REQ_DYLD | 0x28;

#[derive(Serialize)]
pub struct SymtabCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct DsymtabCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct LoadDylibCommand {
    cmd_size: usize,
    name: String,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
}

#[derive(Serialize)]
pub struct LoadDylinkerCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct Segment64Command {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct UuidCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct CodeSignatureCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct BuildVersionCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct FunctionStartsCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct DataInCodeCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct SourceVersionCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct DyldInfoOnlyCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub struct MainCommand {
    cmd_size: usize,
}

#[derive(Serialize)]
pub enum LoadCommand {
    // 0x2
    Symtab(SymtabCommand),
    // 0xb
    Dsymtab(DsymtabCommand),
    // 0xc
    LoadDylib(LoadDylibCommand),
    // 0xe
    LoadDylinker(LoadDylinkerCommand),
    // 0x19
    Segment64(Segment64Command),
    // 0x1b
    Uuid(UuidCommand),
    // 0x1d
    CodeSignature(CodeSignatureCommand),
    // 0x32
    BuildVersion(BuildVersionCommand),
    // 0x26
    FunctionStarts(FunctionStartsCommand),
    // 0x29
    DataInCode(DataInCodeCommand),
    // 0x2A
    SourceVersion(SourceVersionCommand),
    // (0x22|LC_REQ_DYLD)
    DyldInfoOnly(DyldInfoOnlyCommand),
    // (0x28|LC_REQ_DYLD)
    Main(MainCommand),
    Unknow(u32),
}

pub fn parse(data: &[u8]) -> Result<Macho, String> {
    let mut reader = DataReader::new(data);
    let header = parse_header(&mut reader)?;
    let load_commands = parse_load_commands(&mut reader, header.no_cmds)?;
    Ok(Macho {
        header,
        load_commands,
    })
}

fn parse_header(reader: &mut DataReader) -> Result<Header, String> {
    let magic = reader.read_u32();
    if magic != MAGIC_HEADER {
        return Err("not a mach-o 64 file".to_string());
    }
    let cpu_type = parse_cpu_type(reader.read_i32())?;
    let cpu_sub_type = parse_cpu_sub_type(cpu_type, reader.read_i32())?;
    let file_type = parse_file_type(reader.read_u32())?;
    let no_cmds = reader.read_u32() as usize;
    let size_of_cmds = reader.read_u32() as usize;
    let flags = parse_header_flags(reader.read_u32())?;
    reader.skip(4); // reserved

    Ok(Header {
        cpu_type,
        cpu_sub_type,
        file_type,
        no_cmds,
        size_of_cmds,
        flags,
    })
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

fn parse_cpu_sub_type(cpu_type: CPUType, v: i32) -> Result<CPUSubType, String> {
    if cpu_type == CPUType::ARM64 {
        match v {
            0 => Ok(CPUSubType::ARM_ALL),
            _ => Err(format!("unsupported ARM64 cpu_sub_type: {:x}", v)),
        }
    } else {
        Err(format!("unsupported cpu_sub_type: {:x}", v))
    }
}

fn parse_file_type(v: u32) -> Result<FileType, String> {
    match v {
        0x1 => Ok(FileType::MH_OBJECT),
        0x2 => Ok(FileType::MH_EXECUTED),
        _ => Err(format!("unsupported file_type: {:x}", v)),
    }
}

fn parse_header_flags(v: u32) -> Result<Vec<HeaderFlag>, String> {
    let mut result = Vec::new();
    let r = &mut result;
    h_flag(v, HeaderFlag::MH_NOUNDEFS, r);
    h_flag(v, HeaderFlag::MH_INCRLINK, r);
    h_flag(v, HeaderFlag::MH_DYLDLINK, r);
    h_flag(v, HeaderFlag::MH_BINDATLOAD, r);
    h_flag(v, HeaderFlag::MH_PREBOUND, r);
    h_flag(v, HeaderFlag::MH_SPLIT_SEGS, r);
    h_flag(v, HeaderFlag::MH_LAZY_INIT, r);
    h_flag(v, HeaderFlag::MH_TWOLEVEL, r);
    h_flag(v, HeaderFlag::MH_FORCE_FLAT, r);
    h_flag(v, HeaderFlag::MH_NOMULTIDEFS, r);
    h_flag(v, HeaderFlag::MH_NOFIXPREBINDING, r);
    h_flag(v, HeaderFlag::MH_PREBINDABLE, r);
    h_flag(v, HeaderFlag::MH_ALLMODSBOUND, r);
    h_flag(v, HeaderFlag::MH_SUBSECTIONS_VIA_SYMBOLS, r);
    h_flag(v, HeaderFlag::MH_CANONICAL, r);
    h_flag(v, HeaderFlag::MH_WEAK_DEFINES, r);
    h_flag(v, HeaderFlag::MH_BINDS_TO_WEAK, r);
    h_flag(v, HeaderFlag::MH_ALLOW_STACK_EXECUTION, r);
    h_flag(v, HeaderFlag::MH_ROOT_SAFE, r);
    h_flag(v, HeaderFlag::MH_SETUID_SAFE, r);
    h_flag(v, HeaderFlag::MH_NO_REEXPORTED_DYLIBS, r);
    h_flag(v, HeaderFlag::MH_PIE, r);
    h_flag(v, HeaderFlag::MH_DEAD_STRIPPABLE_DYLIB, r);
    h_flag(v, HeaderFlag::MH_HAS_TLV_DESCRIPTORS, r);
    h_flag(v, HeaderFlag::MH_NO_HEAP_EXECUTION, r);
    h_flag(v, HeaderFlag::MH_APP_EXTENSION_SAFE, r);
    h_flag(v, HeaderFlag::MH_NLIST_OUTOFSYNC_WITH_DYLDINFO, r);
    h_flag(v, HeaderFlag::MH_SIM_SUPPORT, r);
    h_flag(v, HeaderFlag::MH_IMPLICIT_PAGEZERO, r);
    h_flag(v, HeaderFlag::MH_DYLIB_IN_CACHE, r);
    Ok(result)
}

fn h_flag(v: u32, flag: HeaderFlag, result: &mut Vec<HeaderFlag>) {
    if (v & (flag as u32)) != 0 {
        result.push(flag)
    }
}

fn parse_load_commands(
    reader: &mut DataReader,
    no_cmds: usize,
) -> Result<Vec<LoadCommand>, String> {
    let mut commands = Vec::with_capacity(no_cmds);
    for _ in 0..no_cmds {
        let cmd = reader.read_u32();
        let cmd_size = reader.read_u32() as usize;
        let command = match cmd {
            0x2 => parse_cmd_symtab(reader, cmd_size),
            0xb => parse_cmd_dsymtab(reader, cmd_size),
            0xc => parse_cmd_load_dylib(reader, cmd_size),
            0xe => parse_cmd_load_dylinker(reader, cmd_size),
            0x19 => parse_cmd_segment_64(reader, cmd_size),
            0x1b => parse_cmd_uuid(reader, cmd_size),
            0x1d => parse_cmd_code_signature(reader, cmd_size),
            0x32 => parse_cmd_build_version(reader, cmd_size),
            0x26 => parse_cmd_function_starts(reader, cmd_size),
            0x2a => parse_cmd_source_version(reader, cmd_size),
            0x29 => parse_cmd_data_in_code(reader, cmd_size),
            LC_DYLD_INFO_ONLY => parse_cmd_dyld_info_only(reader, cmd_size),
            LC_MAIN => parse_cmd_main(reader, cmd_size),
            _ => {
                reader.skip(cmd_size - 8);
                Ok(LoadCommand::Unknow(cmd))
            }
        }?;
        commands.push(command);
    }
    Ok(commands)
}

fn parse_cmd_symtab(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::Symtab(SymtabCommand { cmd_size }))
}

fn parse_cmd_dsymtab(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::Dsymtab(DsymtabCommand { cmd_size }))
}

fn parse_cmd_load_dylib(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(4); //name offset, derived from cmd_size
    let timestamp = reader.read_u32();
    let current_version = reader.read_u32();
    let compatibility_version = reader.read_u32();
    let name = clean_string(&reader.read_utf8_string(cmd_size - (6 * 4)));
    Ok(LoadCommand::LoadDylib(LoadDylibCommand {
        cmd_size,
        name,
        timestamp,
        current_version,
        compatibility_version,
    }))
}

fn parse_cmd_load_dylinker(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::LoadDylinker(LoadDylinkerCommand { cmd_size }))
}

fn parse_cmd_segment_64(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::Segment64(Segment64Command { cmd_size }))
}

fn parse_cmd_uuid(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::Uuid(UuidCommand { cmd_size }))
}

fn parse_cmd_code_signature(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::CodeSignature(CodeSignatureCommand {
        cmd_size,
    }))
}

fn parse_cmd_build_version(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::BuildVersion(BuildVersionCommand { cmd_size }))
}

fn parse_cmd_function_starts(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::FunctionStarts(FunctionStartsCommand {
        cmd_size,
    }))
}

fn parse_cmd_source_version(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::SourceVersion(SourceVersionCommand {
        cmd_size,
    }))
}

fn parse_cmd_data_in_code(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::DataInCode(DataInCodeCommand { cmd_size }))
}

fn parse_cmd_dyld_info_only(
    reader: &mut DataReader,
    cmd_size: usize,
) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::DyldInfoOnly(DyldInfoOnlyCommand { cmd_size }))
}

fn parse_cmd_main(reader: &mut DataReader, cmd_size: usize) -> Result<LoadCommand, String> {
    reader.skip(cmd_size - 8);
    Ok(LoadCommand::Main(MainCommand { cmd_size }))
}

// helper

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

fn clean_string(str: &str) -> String {
    str.replace('\0', "")
}
