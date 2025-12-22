# GIẢI THÍCH CHI TIẾT DỰ ÁN EXOWIN
## Công cụ Phân tích Tĩnh và Trích xuất Đặc trưng từ File PE

---

## MỤC LỤC

1. [Tổng quan dự án](#1-tổng-quan-dự-án)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Cấu trúc file PE (Portable Executable)](#3-cấu-trúc-file-pe-portable-executable)
4. [Các module trích xuất (Extractors)](#4-các-module-trích-xuất-extractors)
5. [Thuật toán và phương pháp phân tích](#5-thuật-toán-và-phương-pháp-phân-tích)
6. [Trích xuất đặc trưng cho Machine Learning](#6-trích-xuất-đặc-trưng-cho-machine-learning)
7. [Phát hiện mối đe dọa](#7-phát-hiện-mối-đe-dọa)
8. [Module báo cáo (Reporters)](#8-module-báo-cáo-reporters)
9. [Giao diện người dùng](#9-giao-diện-người-dùng)
10. [Thư viện và công nghệ sử dụng](#10-thư-viện-và-công-nghệ-sử-dụng)
11. [Quy trình phân tích hoàn chỉnh](#11-quy-trình-phân-tích-hoàn-chỉnh)

---

## 1. TỔNG QUAN DỰ ÁN

### 1.1. Mục đích

ExoWin là công cụ phân tích tĩnh (static analysis) được thiết kế để:
- Phân tích cấu trúc và nội dung của file thực thi Windows (PE files)
- Trích xuất thông tin hữu ích cho việc nghiên cứu bảo mật
- Phát hiện các chỉ báo đáng ngờ (suspicious indicators)
- Cung cấp đặc trưng số (numerical features) cho các mô hình Machine Learning phân loại malware

### 1.2. Đối tượng sử dụng

- Nhà nghiên cứu bảo mật (Security Researchers)
- Chuyên gia phân tích malware (Malware Analysts)
- Kỹ sư Machine Learning trong lĩnh vực an ninh mạng
- Sinh viên nghiên cứu về bảo mật thông tin

### 1.3. Phạm vi phân tích

ExoWin thực hiện **phân tích tĩnh** (static analysis), nghĩa là:
- Không thực thi file (không chạy mã độc)
- Chỉ đọc và phân tích cấu trúc binary
- An toàn cho hệ thống (không có rủi ro lây nhiễm)

---

## 2. KIẾN TRÚC HỆ THỐNG

### 2.1. Sơ đồ kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                         ExoWin                                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │    CLI      │    │    GUI      │    │   Python    │          │
│  │  (Typer)    │    │(CustomTk)   │    │    API      │          │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘          │
│         │                  │                  │                  │
│         └──────────────────┼──────────────────┘                  │
│                            │                                     │
│                    ┌───────▼───────┐                            │
│                    │   Analyzer    │                            │
│                    │    Engine     │                            │
│                    └───────┬───────┘                            │
│                            │                                     │
│         ┌──────────────────┼──────────────────┐                  │
│         │                  │                  │                  │
│  ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐          │
│  │  Extractors │    │  Reporters  │    │   Utils     │          │
│  │   Module    │    │   Module    │    │   Module    │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2. Mô tả các thành phần

| Thành phần | Mô tả | File |
|------------|-------|------|
| **CLI** | Giao diện dòng lệnh, sử dụng Typer framework | `cli.py` |
| **GUI** | Giao diện đồ họa, sử dụng CustomTkinter | `gui.py` |
| **Analyzer Engine** | Bộ điều phối chính, quản lý các extractor | `analyzer.py` |
| **Extractors** | Các module trích xuất đặc trưng | `extractors/` |
| **Reporters** | Các module xuất báo cáo | `reporters/` |
| **Utils** | Các tiện ích hỗ trợ | `utils/` |

### 2.3. Luồng xử lý dữ liệu

```
File PE → pefile.PE object → Extractors → Results Dict → Reporters → Output
```

1. **Input**: File PE (.exe, .dll)
2. **Parsing**: Sử dụng thư viện `pefile` để parse cấu trúc PE
3. **Extraction**: Các extractor trích xuất thông tin theo từng khía cạnh
4. **Analysis**: Phân tích kết quả, phát hiện các chỉ báo đáng ngờ
5. **Output**: Xuất báo cáo theo định dạng yêu cầu

---

## 3. CẤU TRÚC FILE PE (PORTABLE EXECUTABLE)

### 3.1. Tổng quan về định dạng PE

PE (Portable Executable) là định dạng file thực thi tiêu chuẩn của Windows, bao gồm:
- File thực thi (.exe)
- Thư viện liên kết động (.dll)
- Driver (.sys)
- Các file thực thi khác (.ocx, .cpl, .scr)

### 3.2. Cấu trúc PE

```
┌──────────────────────────────────┐
│         DOS Header               │  ← MZ signature (0x5A4D)
├──────────────────────────────────┤
│         DOS Stub                 │  ← "This program cannot..."
├──────────────────────────────────┤
│         PE Signature             │  ← "PE\0\0" (0x50450000)
├──────────────────────────────────┤
│         File Header (COFF)       │  ← Machine type, sections count
├──────────────────────────────────┤
│         Optional Header          │  ← Entry point, image base
├──────────────────────────────────┤
│         Data Directories         │  ← Import, Export, Resource...
├──────────────────────────────────┤
│         Section Headers          │  ← .text, .data, .rdata...
├──────────────────────────────────┤
│         Section 1 (.text)        │  ← Mã thực thi
├──────────────────────────────────┤
│         Section 2 (.data)        │  ← Dữ liệu khởi tạo
├──────────────────────────────────┤
│         Section N (...)          │  ← Các section khác
├──────────────────────────────────┤
│         Overlay (optional)       │  ← Dữ liệu sau section cuối
└──────────────────────────────────┘
```

### 3.3. Các thành phần quan trọng

#### DOS Header
- **e_magic**: Chữ ký "MZ" (0x5A4D) - xác định file DOS/PE hợp lệ
- **e_lfanew**: Offset đến PE signature

#### File Header (COFF Header)
- **Machine**: Kiến trúc CPU (x86, x64, ARM...)
- **NumberOfSections**: Số lượng section
- **TimeDateStamp**: Thời gian biên dịch
- **Characteristics**: Các đặc tính file (EXE, DLL...)

#### Optional Header
- **AddressOfEntryPoint**: Điểm bắt đầu thực thi
- **ImageBase**: Địa chỉ nạp ưu tiên trong bộ nhớ
- **SizeOfCode**: Kích thước vùng mã
- **Subsystem**: Loại subsystem (Console, GUI...)

#### Sections
- **.text**: Chứa mã thực thi
- **.data**: Chứa dữ liệu đã khởi tạo
- **.rdata**: Chứa dữ liệu chỉ đọc
- **.rsrc**: Chứa resources (icon, string...)
- **.reloc**: Chứa thông tin relocation

---

## 4. CÁC MODULE TRÍCH XUẤT (EXTRACTORS)

### 4.1. Kiến trúc Extractor

Tất cả các extractor đều kế thừa từ lớp cơ sở `BaseExtractor`:

```python
class BaseExtractor(ABC):
    """Base class for all feature extractors"""

    @abstractmethod
    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract features from PE file"""
        pass

    def extract_safe(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Safely extract features, catching and logging any errors"""
        try:
            return self.extract(pe, filepath)
        except Exception as e:
            return {"error": str(e), "extractor": self.name}
```

**Thiết kế pattern**: Template Method Pattern
- Phương thức `extract()` là abstract, mỗi extractor phải implement
- Phương thức `extract_safe()` bọc lỗi, đảm bảo không crash toàn bộ phân tích

### 4.2. FileInfoExtractor

**Mục đích**: Trích xuất thông tin cơ bản về file

**Thông tin trích xuất**:
| Trường | Mô tả |
|--------|-------|
| `filename` | Tên file |
| `size` | Kích thước file (bytes) |
| `md5` | Hash MD5 |
| `sha1` | Hash SHA1 |
| `sha256` | Hash SHA256 |
| `entropy` | Entropy của file |
| `imphash` | Import hash (đặc trưng của import table) |
| `ssdeep` | Fuzzy hash (nếu có thư viện ppdeep) |

**Giải thích Entropy**:
- Entropy đo lường mức độ ngẫu nhiên của dữ liệu
- Công thức Shannon Entropy: $H = -\sum_{i} p_i \log_2(p_i)$
- Giá trị từ 0 (không ngẫu nhiên) đến 8 (hoàn toàn ngẫu nhiên)
- **> 7.0**: Có thể đã packed/encrypted
- **5.0 - 7.0**: Bình thường cho file thực thi
- **< 5.0**: Bất thường, có thể chứa nhiều dữ liệu trống

### 4.3. HeadersExtractor

**Mục đích**: Trích xuất thông tin từ PE headers

**Thông tin DOS Header**:
- `e_magic`: Magic number (phải là 0x5A4D = "MZ")
- `e_lfanew`: Offset đến PE header

**Thông tin File Header**:
| Trường | Mô tả |
|--------|-------|
| `Machine` | Kiến trúc CPU (I386, AMD64, ARM...) |
| `NumberOfSections` | Số section |
| `TimeDateStamp` | Thời gian biên dịch |
| `Characteristics` | Đặc tính file |

**Thông tin Optional Header**:
| Trường | Mô tả |
|--------|-------|
| `Magic` | PE32 (0x10b) hoặc PE32+ (0x20b) |
| `AddressOfEntryPoint` | Điểm vào thực thi |
| `ImageBase` | Địa chỉ nạp ưu tiên |
| `SizeOfCode` | Kích thước mã |
| `Subsystem` | Console, GUI, Native... |

### 4.4. SectionsExtractor

**Mục đích**: Phân tích các section của PE file

**Thông tin mỗi section**:
| Trường | Mô tả |
|--------|-------|
| `Name` | Tên section (.text, .data...) |
| `VirtualAddress` | Địa chỉ ảo khi nạp vào bộ nhớ |
| `VirtualSize` | Kích thước trong bộ nhớ |
| `RawSize` | Kích thước trên đĩa |
| `Entropy` | Entropy của section |
| `Characteristics` | Quyền READ/WRITE/EXECUTE |

**Phát hiện section đáng ngờ**:
1. **Entropy cao (> 7.0)**: Section có thể đã được packed/encrypted
2. **Writable + Executable**: Có thể là dấu hiệu code injection
3. **Size mismatch**: Chênh lệch lớn giữa VirtualSize và RawSize

### 4.5. ImportsExtractor

**Mục đích**: Phân tích bảng Import và phát hiện API đáng ngờ

**Thông tin Import**:
- Danh sách DLL được import
- Danh sách hàm từ mỗi DLL
- Số lượng hàm import

**Phân loại API đáng ngờ**:

| Danh mục | Ví dụ API | Mô tả |
|----------|-----------|-------|
| `process_injection` | CreateRemoteThread, WriteProcessMemory | Kỹ thuật inject mã vào process khác |
| `keylogging` | SetWindowsHookEx, GetAsyncKeyState | Theo dõi bàn phím |
| `anti_debugging` | IsDebuggerPresent, CheckRemoteDebuggerPresent | Chống phân tích debug |
| `network` | InternetOpen, URLDownloadToFile | Hoạt động mạng |
| `registry` | RegSetValue, RegCreateKey | Thao tác registry |
| `file_operations` | CreateFile, DeleteFile | Thao tác file |
| `persistence` | CreateService, SetWindowsHookEx | Duy trì persistence |
| `crypto` | CryptEncrypt, CryptDecrypt | Mã hóa/giải mã |
| `anti_vm` | CreateToolhelp32Snapshot | Phát hiện máy ảo |

### 4.6. StringsExtractor

**Mục đích**: Trích xuất và phân loại chuỗi từ file

**Phương pháp trích xuất**:
1. **ASCII strings**: Chuỗi ký tự ASCII có độ dài >= 4
2. **Unicode strings**: Chuỗi UTF-16LE

**Phân loại chuỗi bằng Regular Expression**:

| Loại | Pattern | Ví dụ |
|------|---------|-------|
| URLs | `https?://[^\s<>"{}|\\^`\[\]]+` | http://malware.com |
| IP Addresses | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | 192.168.1.1 |
| Emails | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b` | hacker@evil.com |
| Registry Keys | `HKEY_[A-Z_]+\\[^\s]+` | HKEY_LOCAL_MACHINE\SOFTWARE |
| File Paths | `[A-Z]:\\(?:[^\s<>:"|?*\\]+\\)*` | C:\Windows\System32 |
| Suspicious Keywords | `cmd|powershell|inject|payload...` | powershell, backdoor |

### 4.7. DisasmExtractor

**Mục đích**: Disassemble mã máy từ Entry Point

**Công nghệ**: Sử dụng thư viện Capstone (multi-architecture disassembler)

**Quy trình**:
1. Xác định kiến trúc CPU (x86 hoặc x64)
2. Lấy địa chỉ Entry Point từ Optional Header
3. Đọc mã máy từ Entry Point
4. Sử dụng Capstone để disassemble thành assembly

**Output mỗi instruction**:
| Trường | Mô tả |
|--------|-------|
| `address` | Địa chỉ instruction |
| `mnemonic` | Tên instruction (mov, push, call...) |
| `operands` | Các operand |
| `bytes` | Mã máy hex |
| `size` | Kích thước instruction |

### 4.8. MLFeaturesExtractor

**Mục đích**: Trích xuất đặc trưng số cho Machine Learning

**Chi tiết xem Section 6**.

---

## 5. THUẬT TOÁN VÀ PHƯƠNG PHÁP PHÂN TÍCH

### 5.1. Thuật toán tính Entropy (Shannon Entropy)

**Mục đích**: Đo lường mức độ ngẫu nhiên của dữ liệu

**Công thức**:
$$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$

Trong đó:
- $p_i$ = tần suất xuất hiện của byte giá trị $i$
- $H$ nằm trong khoảng [0, 8]

**Implementation**:
```python
def calculate_entropy(self, data: bytes) -> float:
    if not data:
        return 0.0

    # Đếm tần suất mỗi byte
    p, lns = Counter(data), float(len(data))

    # Tính entropy
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
```

**Ý nghĩa trong phân tích malware**:
- **Entropy cao (> 7.0)**: File có thể đã được nén hoặc mã hóa (packed)
- **Entropy thấp (< 5.0)**: File chứa nhiều dữ liệu lặp lại hoặc trống
- Malware thường được packed để tránh phát hiện → entropy cao

### 5.2. Thuật toán tính Hash

**MD5** (Message Digest 5):
- Output: 128-bit (32 ký tự hex)
- Nhanh nhưng không an toàn cho mật mã
- Dùng để nhận dạng file

**SHA-1** (Secure Hash Algorithm 1):
- Output: 160-bit (40 ký tự hex)
- An toàn hơn MD5

**SHA-256** (SHA-2 family):
- Output: 256-bit (64 ký tự hex)
- Tiêu chuẩn hiện tại cho bảo mật

**Import Hash (ImpHash)**:
- Hash của danh sách import được sắp xếp
- Malware cùng họ thường có ImpHash giống nhau
- Dùng để clustering malware

**SSDeep (Fuzzy Hash)**:
- Context-triggered piecewise hashing
- So sánh độ tương đồng giữa các file
- Hữu ích cho biến thể malware

### 5.3. Phương pháp trích xuất String

**ASCII String Extraction**:
```python
pattern = b'[\x20-\x7E]{4,}'  # Printable ASCII, min 4 chars
matches = re.findall(pattern, data)
```

**Unicode String Extraction (UTF-16LE)**:
```python
pattern = b'(?:[\x20-\x7E][\x00]){4,}'  # ASCII + null byte
matches = re.findall(pattern, data)
decoded = [s.decode('utf-16le') for s in matches]
```

### 5.4. Phương pháp phân tích Section

**Đánh giá rủi ro section**:

```python
def _is_suspicious_section(self, name, entropy, characteristics, vsize, rsize):
    suspicious = []

    # 1. Kiểm tra entropy cao
    if entropy > 7.0:
        suspicious.append("High entropy - possibly packed/encrypted")

    # 2. Kiểm tra WX (Writable + Executable)
    if "WRITE" in characteristics and "EXECUTE" in characteristics:
        suspicious.append("Writable and executable - code injection risk")

    # 3. Kiểm tra size mismatch
    size_diff = abs(vsize - rsize)
    if size_diff > 0 and vsize > 0:
        ratio = size_diff / vsize
        if ratio > 0.5:
            suspicious.append(f"Large size mismatch")

    return suspicious
```

---

## 6. TRÍCH XUẤT ĐẶC TRƯNG CHO MACHINE LEARNING

### 6.1. Tổng quan

Module `MLFeaturesExtractor` trích xuất **hơn 50 đặc trưng số** từ file PE, phù hợp cho:
- Mô hình phân loại malware/benign
- Mô hình phân loại họ malware (malware family)
- Mô hình phát hiện anomaly

### 6.2. Danh sách đặc trưng theo danh mục

#### File-level Features
| Đặc trưng | Mô tả | Kiểu |
|-----------|-------|------|
| `file_size` | Kích thước file (bytes) | int |
| `file_entropy` | Entropy toàn file | float |
| `file_entropy_high` | Entropy > 7.0 | binary |
| `file_entropy_packed` | Entropy > 6.5 | binary |
| `overlay_size` | Kích thước overlay | int |
| `has_cert` | Có chữ ký số | binary |
| `timestamp` | Unix timestamp biên dịch | int |
| `timestamp_zero` | Timestamp = 0 | binary |
| `timestamp_age_days` | Tuổi file (ngày) | float |

#### DOS Header Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `dos_e_magic` | Magic number (0x5A4D) |
| `dos_e_lfanew` | Offset đến PE header |

#### File Header Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `fh_machine` | Kiến trúc CPU |
| `fh_num_sections` | Số section |
| `fh_timestamp` | Thời gian biên dịch |
| `fh_size_optional_header` | Kích thước optional header |
| `fh_characteristics` | Đặc tính file |

#### Optional Header Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `oh_magic` | PE32 hoặc PE32+ |
| `oh_size_of_code` | Kích thước vùng mã |
| `oh_size_of_initialized_data` | Kích thước dữ liệu khởi tạo |
| `oh_size_of_uninitialized_data` | Kích thước dữ liệu chưa khởi tạo |
| `oh_entry_point` | Địa chỉ entry point |
| `oh_base_of_code` | Địa chỉ base of code |
| `oh_image_base` | Image base address |
| `oh_section_alignment` | Section alignment |
| `oh_file_alignment` | File alignment |
| `oh_size_of_image` | Kích thước image |
| `oh_size_of_headers` | Kích thước headers |
| `oh_checksum` | Checksum |
| `oh_subsystem` | Subsystem type |
| `oh_dll_characteristics` | DLL characteristics |
| `oh_num_rva_sizes` | Số data directory entries |

#### Section Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `sec_num_sections` | Tổng số section |
| `sec_avg_entropy` | Entropy trung bình |
| `sec_max_entropy` | Entropy cao nhất |
| `sec_min_entropy` | Entropy thấp nhất |
| `sec_avg_raw_size` | Kích thước raw trung bình |
| `sec_avg_virtual_size` | Kích thước virtual trung bình |
| `sec_num_wx` | Số section WX (writable+executable) |
| `sec_num_suspicious_entropy` | Số section entropy > 7.0 |
| `sec_num_code` | Số section CODE |
| `sec_num_data` | Số section DATA |
| `sec_code_data_ratio` | Tỷ lệ code/data sections |

#### Import Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `imp_count` | Tổng số hàm import |
| `imp_dll_count` | Số DLL import |
| `imp_sus_process_injection` | Số API process injection |
| `imp_sus_keylogging` | Số API keylogging |
| `imp_sus_anti_debugging` | Số API anti-debugging |
| `imp_sus_network` | Số API network |
| `imp_sus_registry` | Số API registry |
| `imp_sus_file_operations` | Số API file operations |
| `imp_sus_persistence` | Số API persistence |
| `imp_sus_crypto` | Số API crypto |
| `imp_sus_anti_vm` | Số API anti-VM |
| `imp_sus_total` | Tổng số API đáng ngờ |

#### Export Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `exp_count` | Số hàm export |

#### Resource Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `res_count` | Số resource |
| `res_total_size` | Tổng kích thước resource |
| `res_avg_entropy` | Entropy trung bình của resource |

#### Data Directory Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `dd_has_import` | Có Import Directory |
| `dd_has_export` | Có Export Directory |
| `dd_has_resource` | Có Resource Directory |
| `dd_has_exception` | Có Exception Directory |
| `dd_has_security` | Có Security Directory |
| `dd_has_relocation` | Có Relocation Directory |
| `dd_has_debug` | Có Debug Directory |
| `dd_has_tls` | Có TLS Directory |
| `dd_has_load_config` | Có Load Config Directory |
| `dd_has_bound_import` | Có Bound Import Directory |
| `dd_has_iat` | Có IAT Directory |
| `dd_has_delay_import` | Có Delay Import Directory |
| `dd_has_clr` | Có CLR Directory (.NET) |

#### PE Type Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `is_exe` | Là file EXE |
| `is_dll` | Là file DLL |
| `is_64bit` | Là PE32+ (64-bit) |

#### Behavioral Indicators
| Đặc trưng | Mô tả |
|-----------|-------|
| `has_anti_debugging` | Có API anti-debugging |
| `has_injection_apis` | Có API injection |
| `has_network_apis` | Có API network |
| `has_filesystem_apis` | Có API filesystem |
| `has_persistence_apis` | Có API persistence |

#### String Features
| Đặc trưng | Mô tả |
|-----------|-------|
| `extracted_strings_count` | Số chuỗi trích xuất |
| `extracted_strings_avg_len` | Độ dài trung bình |
| `extracted_strings_max_len` | Độ dài tối đa |
| `res_string_url_count` | Số URL |
| `res_string_ip_count` | Số IP address |
| `res_string_email_count` | Số email |
| `res_string_path_count` | Số file path |
| `printable_ratio` | Tỷ lệ byte printable |
| `byte_stddev` | Độ lệch chuẩn byte |

#### Heuristic Scores
| Đặc trưng | Mô tả |
|-----------|-------|
| `packed_score` | Điểm khả năng packed (0-1) |
| `anomaly_score` | Điểm bất thường (0-1) |

### 6.3. Công thức tính Packed Score

```python
packed_raw = 0.0
packed_raw += 1.0 if overlay_size > 0 else 0.0
packed_raw += 0.5 * sec_num_suspicious_entropy
packed_raw += 1.0 * sec_num_wx
packed_raw += 0.5 * sec_name_suspicious_count

sec_count = max(1, sec_num_sections)
packed_score = min(1.0, packed_raw / (1.0 + sec_count/2.0))
```

### 6.4. Công thức tính Anomaly Score

```python
raw_anom = 0.0
raw_anom += imp_sus_total
raw_anom += 2 * sec_num_suspicious_entropy
raw_anom += 2 * sec_num_wx
raw_anom += 3 if overlay_size > 0 else 0
raw_anom += suspicious_string_patterns_count

anomaly_score = min(1.0, raw_anom / (5.0 + sec_count))
```

### 6.5. Ứng dụng trong Machine Learning

**Các mô hình phù hợp**:
- Random Forest
- Gradient Boosting (XGBoost, LightGBM)
- Neural Networks
- SVM (Support Vector Machine)

**Workflow điển hình**:
```
1. Thu thập dataset (malware + benign samples)
2. Sử dụng batch-extract để trích xuất đặc trưng
3. Chia train/test set
4. Huấn luyện mô hình
5. Đánh giá độ chính xác
```

---

## 7. PHÁT HIỆN MỐI ĐE DỌA

### 7.1. Các chỉ báo đáng ngờ (Suspicious Indicators)

ExoWin phát hiện và tổng hợp các chỉ báo đáng ngờ từ nhiều nguồn:

#### Từ File Info
- Entropy cao (> 7.0) → có thể packed/encrypted

#### Từ Sections
- Section có entropy cao
- Section có quyền Writable + Executable
- Chênh lệch lớn giữa VirtualSize và RawSize

#### Từ Imports
- Có API process injection
- Có API anti-debugging
- Có API keylogging
- Có API network đáng ngờ
- Có API crypto
- Có API persistence

#### Từ Strings
- Có URL đáng ngờ
- Có IP address
- Có từ khóa malware (backdoor, payload, inject...)

### 7.2. Quy trình phát hiện

```python
def _analyze_suspicious_indicators(self, results):
    indicators = []

    # 1. Kiểm tra entropy
    if file_info.get("entropy", 0) > 7.0:
        indicators.append("High entropy - likely packed/encrypted")

    # 2. Kiểm tra sections
    for section in sections:
        if section.get("suspicious"):
            for sus in section["suspicious"]:
                indicators.append(f"Section {section['Name']}: {sus}")

    # 3. Kiểm tra API đáng ngờ
    for category, apis in suspicious_apis.items():
        indicators.append(f"Suspicious {category} APIs: {apis}")

    # 4. Kiểm tra strings
    if categorized.get("urls"):
        indicators.append(f"Contains {len(urls)} URLs")

    if categorized.get("suspicious_keywords"):
        indicators.append(f"Suspicious keywords: {keywords}")

    return indicators
```

---

## 8. MODULE BÁO CÁO (REPORTERS)

### 8.1. Kiến trúc Reporter

Tất cả reporter kế thừa từ `BaseReporter`:

```python
class BaseReporter(ABC):
    @abstractmethod
    def generate(self, data: Dict[str, Any], output_path: str = None) -> str:
        pass
```

### 8.2. ConsoleReporter

- Hiển thị kết quả trên terminal
- Sử dụng thư viện Rich để format đẹp
- Hỗ trợ bảng, màu sắc, syntax highlighting

### 8.3. JSONReporter

- Xuất kết quả ra file JSON
- Định dạng có cấu trúc, dễ xử lý tự động
- Phù hợp cho tích hợp API

### 8.4. HTMLReporter

- Tạo báo cáo HTML tương tác
- Sử dụng Jinja2 template engine
- Có thể xem trực tiếp trên trình duyệt

### 8.5. MarkdownReporter

- Xuất báo cáo định dạng Markdown
- Phù hợp cho tài liệu, GitHub

### 8.6. CSVReporter

- Xuất dữ liệu dạng bảng CSV
- Phù hợp cho Excel, phân tích dữ liệu
- Hỗ trợ append để gộp nhiều file

---

## 9. GIAO DIỆN NGƯỜI DÙNG

### 9.1. Command Line Interface (CLI)

**Framework**: Typer

**Các lệnh chính**:
```
exowin gui          # Mở giao diện đồ họa
exowin analyze      # Phân tích toàn diện
exowin info         # Thông tin cơ bản
exowin sections     # Phân tích sections
exowin imports      # Phân tích imports
exowin strings      # Trích xuất strings
exowin disasm       # Disassembly
exowin compare      # So sánh 2 file
exowin batch        # Phân tích hàng loạt
exowin extract-features  # Trích xuất ML features
exowin batch-extract     # Trích xuất ML hàng loạt
```

### 9.2. Graphical User Interface (GUI)

**Framework**: CustomTkinter

**Các tính năng**:
- Dashboard với thống kê tổng quan
- Drag and drop file PE
- Tabs riêng cho từng loại thông tin
- Xuất báo cáo đa định dạng
- Theme Dark/Light
- Responsive design

**Thành phần chính**:
- Sidebar navigation
- File selector
- Analysis tabs (Info, Headers, Sections, Imports, Strings...)
- Export buttons
- Status bar

---

## 10. THƯ VIỆN VÀ CÔNG NGHỆ SỬ DỤNG

### 10.1. Core Libraries

| Thư viện | Phiên bản | Mục đích |
|----------|-----------|----------|
| **pefile** | Latest | Parse cấu trúc PE file |
| **capstone** | Latest | Disassembly engine đa kiến trúc |
| **ppdeep** | Latest | Fuzzy hashing (ssdeep) |

### 10.2. CLI Framework

| Thư viện | Mục đích |
|----------|----------|
| **typer** | Framework tạo CLI application |
| **rich** | Console formatting (bảng, màu sắc) |

### 10.3. GUI Framework

| Thư viện | Mục đích |
|----------|----------|
| **customtkinter** | Modern UI framework cho Tkinter |
| **pillow** | Xử lý hình ảnh (icon) |

### 10.4. Template Engine

| Thư viện | Mục đích |
|----------|----------|
| **jinja2** | HTML template rendering |

### 10.5. Python Standard Library

| Module | Mục đích |
|--------|----------|
| `hashlib` | Tính hash MD5, SHA1, SHA256 |
| `re` | Regular expression |
| `math` | Tính toán entropy |
| `collections.Counter` | Đếm tần suất byte |
| `pathlib` | Xử lý đường dẫn file |
| `json` | Xuất/đọc JSON |
| `datetime` | Xử lý thời gian |

---

## 11. QUY TRÌNH PHÂN TÍCH HOÀN CHỈNH

### 11.1. Sơ đồ quy trình

```
┌─────────────────┐
│   Input File    │
│   (.exe/.dll)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  pefile.PE()    │ ← Parse PE structure
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│              Extractors                      │
├─────────────────────────────────────────────┤
│  FileInfoExtractor    → Hash, Entropy       │
│  HeadersExtractor     → DOS, COFF, Optional │
│  SectionsExtractor    → Section analysis    │
│  ImportsExtractor     → DLL, APIs           │
│  StringsExtractor     → URLs, IPs, Keywords │
│  DisasmExtractor      → Assembly code       │
│  MLFeaturesExtractor  → Numerical features  │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│  Analyzer       │ ← Aggregate results
│  Engine         │ ← Detect suspicious
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│              Reporters                       │
├─────────────────────────────────────────────┤
│  ConsoleReporter  → Terminal output         │
│  JSONReporter     → JSON file               │
│  HTMLReporter     → Interactive HTML        │
│  MarkdownReporter → Markdown document       │
│  CSVReporter      → CSV for ML              │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│     Output      │
└─────────────────┘
```

### 11.2. Ví dụ code sử dụng

```python
from exowin import PEStaticAnalyzer
from exowin.reporters import JSONReporter, HTMLReporter

# 1. Khởi tạo analyzer
analyzer = PEStaticAnalyzer()

# 2. Phân tích file
result = analyzer.analyze_file(
    filepath="malware.exe",
    include_disasm=True,
    num_instructions=50
)

# 3. Truy cập kết quả
print(f"File size: {result['file_info']['size']}")
print(f"Entropy: {result['file_info']['entropy']}")
print(f"MD5: {result['file_info']['md5']}")
print(f"Sections: {result['sections']['count']}")
print(f"Imports: {len(result['imports']['imports'])}")
print(f"Suspicious indicators: {result['suspicious_indicators']}")

# 4. Xuất báo cáo
JSONReporter().generate(result, "report.json")
HTMLReporter().generate(result, "report.html")
```

### 11.3. Batch Processing

```python
from pathlib import Path
from exowin import PEStaticAnalyzer
from exowin.extractors import MLFeaturesExtractor
from exowin.reporters import CSVReporter

analyzer = PEStaticAnalyzer()
ml_extractor = MLFeaturesExtractor()

# Thu thập tất cả file .exe
files = list(Path("./samples").glob("*.exe"))

all_features = []
for file in files:
    try:
        import pefile
        pe = pefile.PE(str(file))   
        features = ml_extractor.extract(pe, str(file))
        features["filename"] = file.name
        features["label"] = "malware"  # hoặc "benign"
        all_features.append(features)
        pe.close()
    except Exception as e:
        print(f"Error: {file.name}: {e}")

# Xuất CSV cho ML
CSVReporter.generate_batch(all_features, "dataset.csv")
```

---

*Tài liệu này được viết cho dự án ExoWin v1.0.0*
*Cập nhật: Tháng 12/2025*
