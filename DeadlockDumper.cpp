#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include <psapi.h>

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <exception>

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------
using i32 = int;
using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

// ---------------------------------------------------------------------------
// IOCTL codes (from Communication.h / Definitions.h)
// ---------------------------------------------------------------------------
#define PRW_CODE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2ec33, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VRW_ATTACH_CODE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2ec34, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VRW_CODE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2ec35, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define BA_CODE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2ec36, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

static constexpr u64 SECURITY_CODE = 0x94c9e4bc3ULL;

// ---------------------------------------------------------------------------
// Request structures (must match driver's Communication.h)
// ---------------------------------------------------------------------------
struct _PRW
{
    u64   security_code;
    i32   process_id;
    void* address;
    void* buffer;
    u64   size;
    u64   return_size;
    bool  Type;
};

struct _VRW
{
    u64    security_code;
    HANDLE process_handle;
    void*  address;
    void*  buffer;
    u64    size;
    u64    return_size;
    bool   Type;
};

struct _BA
{
    u64   security_code;
    i32   process_id;
    u64*  address;
};

static constexpr u64 CHUNK_SIZE = 4096;

// ---------------------------------------------------------------------------
// Error printing
// ---------------------------------------------------------------------------
static void print_error(const char* context, DWORD code = GetLastError())
{
    char buf[512] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, buf, sizeof(buf), nullptr);
    for (int i = (int)strlen(buf) - 1; i >= 0 && (buf[i] == '\n' || buf[i] == '\r'); --i)
        buf[i] = '\0';
    fprintf(stderr, "[ERROR] %s: %s (0x%08X)\n", context, buf, (unsigned)code);
}

// ===========================================================================
// Driver communication
// ===========================================================================
class DriverComm
{
public:
    DriverComm()
    {
        m_handle = CreateFileA(
            "\\\\.\\RickOwens00",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr
        );
    }

    ~DriverComm()
    {
        if (m_handle != INVALID_HANDLE_VALUE)
            CloseHandle(m_handle);
    }

    bool is_connected() const { return m_handle != INVALID_HANDLE_VALUE; }

    i32 find_process(const char* process_name)
    {
        PROCESSENTRY32 entry = {};
        entry.dwSize = sizeof(entry);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { print_error("Process snapshot"); return 0; }

        m_pid = 0;
        if (Process32First(snap, &entry))
        {
            do
            {
                if (_stricmp(entry.szExeFile, process_name) == 0)
                {
                    m_pid = static_cast<i32>(entry.th32ProcessID);
                    break;
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
        return m_pid;
    }

    bool v_attach(i32 pid)
    {
        _VRW args = {};
        args.security_code = SECURITY_CODE;
        args.process_handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
        DWORD bytes = 0;
        return DeviceIoControl(m_handle, VRW_ATTACH_CODE,
                               &args, sizeof(args), &args, sizeof(args),
                               &bytes, nullptr) != FALSE;
    }

    u64 find_image()
    {
        u64 image_base = 0;
        _BA args = {};
        args.security_code = SECURITY_CODE;
        args.process_id    = m_pid;
        args.address       = &image_base;
        DWORD bytes = 0;
        if (!DeviceIoControl(m_handle, BA_CODE, &args, sizeof(args), nullptr, 0, &bytes, nullptr))
        {
            print_error("Get image base IOCTL");
            return 0;
        }
        m_image_base = image_base;
        return image_base;
    }

    u64 v_read_raw(u64 address, void* out_buf, u64 size)
    {
        _VRW args = {};
        args.security_code = SECURITY_CODE;
        args.address       = reinterpret_cast<void*>(address);
        args.buffer        = out_buf;
        args.size          = size;
        args.Type          = false;
        DWORD bytes = 0;
        if (!DeviceIoControl(m_handle, VRW_CODE,
                        &args, sizeof(args), &args, sizeof(args), &bytes, nullptr))
        {
            if (!m_read_error_reported) print_error("Read memory IOCTL");
            m_read_error_reported = true;
            return 0;
        }
        if (bytes < offsetof(_VRW, return_size) + sizeof(args.return_size) || args.return_size > size)
        {
            if (!m_read_error_reported) fprintf(stderr, "[ERROR] Driver returned an invalid read response.\n");
            m_read_error_reported = true;
            return 0;
        }
        return args.return_size;
    }

    template<typename T>
    T v_read(u64 address)
    {
        T val = {};
        v_read_raw(address, &val, sizeof(T));
        return val;
    }

    i32 pid()        const { return m_pid; }
    u64 image_base() const { return m_image_base; }

private:
    HANDLE m_handle     = INVALID_HANDLE_VALUE;
    i32    m_pid        = 0;
    u64    m_image_base = 0;
    bool   m_read_error_reported = false;
};

// ===========================================================================
// PE helpers
// ===========================================================================
static u32 get_remote_image_size(DriverComm& comm, u64 base)
{
    IMAGE_DOS_HEADER dos = {};
    if (comm.v_read_raw(base, &dos, sizeof(dos)) != sizeof(dos))
    {
        fprintf(stderr, "[WARN] Could not read DOS header at 0x%llX\n", base);
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(stderr, "[WARN] Bad DOS magic: 0x%04X\n", dos.e_magic);
        return 0;
    }

    if (dos.e_lfanew < static_cast<LONG>(sizeof(dos)) || dos.e_lfanew > 1024 * 1024)
        return 0;
    u64 nt_offset = base + static_cast<u32>(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt = {};
    if (comm.v_read_raw(nt_offset, &nt, sizeof(nt)) != sizeof(nt))
    {
        fprintf(stderr, "[WARN] Could not read NT headers\n");
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[WARN] Bad NT signature: 0x%08X\n", nt.Signature);
        return 0;
    }

    u32 size_of_image = 0;
    if (nt.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        IMAGE_NT_HEADERS32 nt32 = {};
        if (comm.v_read_raw(nt_offset, &nt32, sizeof(nt32)) != sizeof(nt32) ||
            nt32.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 0;
        size_of_image = nt32.OptionalHeader.SizeOfImage;
    }
    else if (nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
             nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        size_of_image = nt.OptionalHeader.SizeOfImage;
    }
    if (size_of_image < sizeof(IMAGE_DOS_HEADER)) return 0;
    return size_of_image;
}

static u32 align_up(u32 value, u32 alignment)
{
    if (alignment == 0) return value;
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static bool rebuild_memory_image_as_pe(std::vector<u8>& image)
{
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return false;

    const size_t nt_off = static_cast<size_t>(dos->e_lfanew);
    if (nt_off > image.size() || image.size() - nt_off < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD)) return false;
    if (*reinterpret_cast<DWORD*>(image.data() + nt_off) != IMAGE_NT_SIGNATURE) return false;

    auto* file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(image.data() + nt_off + sizeof(DWORD));
    const WORD num_sections = file_hdr->NumberOfSections;
    const WORD opt_magic = *reinterpret_cast<WORD*>(image.data() + nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    u32 section_align = 0;
    size_t first_section_off = 0;

    if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (image.size() - nt_off < sizeof(IMAGE_NT_HEADERS32) || file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) return false;
        auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data() + nt_off);
        section_align = nt32->OptionalHeader.SectionAlignment ? nt32->OptionalHeader.SectionAlignment : 0x1000;
        nt32->OptionalHeader.FileAlignment = section_align;
        nt32->OptionalHeader.CheckSum = 0;
        first_section_off = nt_off + sizeof(IMAGE_NT_HEADERS32);
    }
    else if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (image.size() - nt_off < sizeof(IMAGE_NT_HEADERS64) || file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return false;
        auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + nt_off);
        section_align = nt64->OptionalHeader.SectionAlignment ? nt64->OptionalHeader.SectionAlignment : 0x1000;
        nt64->OptionalHeader.FileAlignment = section_align;
        nt64->OptionalHeader.CheckSum = 0;
        first_section_off = nt_off + sizeof(IMAGE_NT_HEADERS64);
    }
    else return false;

    first_section_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    if (num_sections == 0 || num_sections > 96 || first_section_off > image.size() ||
        num_sections > (image.size() - first_section_off) / sizeof(IMAGE_SECTION_HEADER)) return false;
    if (section_align > 65536 || (section_align & (section_align - 1)) != 0) return false;

    u64 required = image.size();
    for (WORD i = 0; i < num_sections; ++i)
    {
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            image.data() + first_section_off + i * sizeof(IMAGE_SECTION_HEADER));
        u32 raw_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (raw_size > 0x80000000u || raw_size > UINT32_MAX - (section_align - 1)) return false;
        raw_size = align_up(raw_size, section_align);
        u64 end = static_cast<u64>(sec->VirtualAddress) + raw_size;
        if (end > 0x80000000ULL) return false;
        if (end > required) required = end;
    }
    if (required > image.size()) image.resize(static_cast<size_t>(required), 0x00);

    for (WORD i = 0; i < num_sections; ++i)
    {
        auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            image.data() + first_section_off + i * sizeof(IMAGE_SECTION_HEADER));
        u32 raw_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        raw_size = align_up(raw_size, section_align);
        sec->PointerToRawData = sec->VirtualAddress;
        sec->SizeOfRawData = raw_size;
    }

    if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data() + nt_off);
        nt32->OptionalHeader.SizeOfImage = align_up(static_cast<u32>(image.size()), section_align);
    }
    else
    {
        auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + nt_off);
        nt64->OptionalHeader.SizeOfImage = align_up(static_cast<u32>(image.size()), section_align);
    }
    return true;
}

// ===========================================================================
// Dump routine
// ===========================================================================
static bool dump_process_memory(DriverComm& comm, u64 base, u32 image_size, const char* out_path)
{
    printf("[*] Dumping 0x%08X bytes (%.2f MiB) from base 0x%llX...\n",
           image_size, (double)image_size / (1024.0 * 1024.0), base);

    std::vector<u8> dump_buffer(image_size, 0x00);
    u64 bytes_dumped = 0, bytes_failed = 0;
    u64 chunks_total = (image_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    u64 chunks_done = 0, last_pct = 0;

    for (u64 offset = 0; offset < image_size; offset += CHUNK_SIZE)
    {
        u64 this_chunk = std::min<u64>(CHUNK_SIZE, image_size - offset);
        u64 transferred = comm.v_read_raw(base + offset, dump_buffer.data() + offset, this_chunk);
        bytes_dumped += transferred;
        bytes_failed += this_chunk - transferred;
        if (transferred < this_chunk)
            memset(dump_buffer.data() + offset + transferred, 0, static_cast<size_t>(this_chunk - transferred));
        ++chunks_done;
        u64 pct = (chunks_done * 100) / chunks_total;
        if (pct >= last_pct + 5)
        {
            printf("\r[*] Progress: %llu%% (%llu bytes skipped) ", pct, bytes_failed);
            fflush(stdout);
            last_pct = pct;
        }
    }
    printf("\r[*] Progress: 100%%                              \n");
    printf("[*] Read %llu bytes, %llu unavailable\n", bytes_dumped, bytes_failed);
    if (bytes_failed != 0) fprintf(stderr, "[WARN] Dump is incomplete; unread bytes are zero-filled.\n");

    if (dump_buffer.size() < 2 || dump_buffer[0] != 'M' || dump_buffer[1] != 'Z')
    {
        fprintf(stderr, "[ERROR] Dump has no MZ header.\n");
        return false;
    }

    if (!rebuild_memory_image_as_pe(dump_buffer))
    {
        fprintf(stderr, "[ERROR] Failed to rebuild PE.\n");
        return false;
    }

    HANDLE hFile = CreateFileA(out_path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { print_error("CreateFile"); return false; }

    u64 total = 0, remaining = dump_buffer.size();
    const u8* ptr = dump_buffer.data();
    DWORD written = 0;
    while (remaining > 0)
    {
        DWORD to_write = static_cast<DWORD>(std::min<u64>(remaining, 0x7FFF0000ULL));
        if (!WriteFile(hFile, ptr, to_write, &written, nullptr) || written == 0)
        { print_error("WriteFile"); CloseHandle(hFile); return false; }
        ptr += written; total += written; remaining -= written;
    }
    CloseHandle(hFile);
    printf("[+] Wrote %llu bytes to '%s'\n", total, out_path);
    return true;
}

// ===========================================================================
// Entry point
// ===========================================================================
static int run_dumper(int argc, char* argv[])
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    BOOL elevated = FALSE;
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators))
    { print_error("Administrator SID"); return 1; }
    BOOL checked = CheckTokenMembership(nullptr, administrators, &elevated);
    DWORD check_error = checked ? ERROR_SUCCESS : GetLastError();
    FreeSid(administrators);
    if (!checked) { print_error("Administrator check", check_error); return 1; }
    if (!elevated) { fprintf(stderr, "[FATAL] Administrator privileges are required.\n"); return 1; }
    // ═══════════════════════════════════════════════════════════════
    // CHANGE THIS IF THE PROCESS NAME IS DIFFERENT
    // Target process name
    // ═══════════════════════════════════════════════════════════════
    const char* target_process = "deadlock.exe";

    const char* out_file = (argc >= 2) ? argv[1] : "Deadlock_dump.exe";

    printf("=== Deadlock Dumper — RickOwens00 driver ===\n");
    printf("[*] Target : %s\n", target_process);
    printf("[*] Output : %s\n\n", out_file);

    DriverComm comm;
    if (!comm.is_connected())
    {
        DWORD err = GetLastError();
        fprintf(stderr, "[FATAL] Could not open driver (0x%08X)\n", err);
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            fprintf(stderr, "        Driver not loaded.\n");
        else if (err == ERROR_ACCESS_DENIED)
            fprintf(stderr, "        Run as Administrator.\n");
        return 1;
    }
    printf("[+] Driver opened.\n");

    i32 pid = comm.find_process(target_process);
    if (pid == 0)
    {
        fprintf(stderr, "[FATAL] Process '%s' not found.\n", target_process);
        return 1;
    }
    printf("[+] Found PID %d\n", pid);

    if (!comm.v_attach(pid))
    {
        print_error("Attach IOCTL");
        return 1;
    }
    else
        printf("[+] Attached.\n");

    u64 image_base = comm.find_image();
    if (image_base == 0)
    {
        fprintf(stderr, "[FATAL] Could not get image base.\n");
        return 1;
    }
    printf("[+] Image base: 0x%llX\n", image_base);

    u32 image_size = get_remote_image_size(comm, image_base);
    if (image_size == 0)
    {
        fprintf(stderr, "[FATAL] Cannot validate the image headers or size.\n");
        return 1;
    }
    else
    {
        printf("[+] SizeOfImage: 0x%08X (%.2f MiB)\n",
               image_size, (double)image_size / (1024.0 * 1024.0));
    }

    // Deadlock is large — allow up to 2 GB
    constexpr u32 MAX_DUMP_SIZE = 2048u * 1024u * 1024u;
    if (image_size > MAX_DUMP_SIZE)
    {
        fprintf(stderr, "[FATAL] Image exceeds the 2 GiB limit.\n");
        return 1;
    }

    if (!dump_process_memory(comm, image_base, image_size, out_file))
    {
        fprintf(stderr, "[FATAL] Dump failed.\n");
        return 1;
    }

    printf("\n[SUCCESS] Dump complete -> '%s'\n", out_file);
    return 0;
}

int main(int argc, char* argv[])
{
    try { return run_dumper(argc, argv); }
    catch (const std::exception& error)
    {
        fprintf(stderr, "[FATAL] %s\n", error.what());
        return 1;
    }
}
