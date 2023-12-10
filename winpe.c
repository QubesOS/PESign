#include <stdalign.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <err.h>
#include <unistd.h>

#include "winpe.h"
#include "WinCertificate.h"
static_assert(sizeof(EFI_IMAGE_SECTION_HEADER) == 8 + 4 * 6 + 2 * 2 + 4,
              "EFI_IMAGE_SECTION_HEADER has padding?");


#define OPTIONAL_HEADER_OFFSET32 (offsetof(EFI_IMAGE_NT_HEADERS32, OptionalHeader))
#define OPTIONAL_HEADER_OFFSET64 (offsetof(EFI_IMAGE_NT_HEADERS64, OptionalHeader))

static_assert(OPTIONAL_HEADER_OFFSET32 == sizeof(uint32_t) + sizeof(EFI_IMAGE_FILE_HEADER), "unexpected padding");
static_assert(OPTIONAL_HEADER_OFFSET64 == sizeof(uint32_t) + sizeof(EFI_IMAGE_FILE_HEADER), "IMAGE_NT_HEADERS32 and IMAGE_NT_HEADERS64 must not have padding");
static_assert(alignof(EFI_IMAGE_FILE_HEADER) == 4,
              "wrong defintion of EFI_IMAGE_FILE_HEADER");
static_assert(alignof(EFI_IMAGE_NT_HEADERS32) == 4,
              "wrong defintion of IMAGE_NT_HEADERS32");
static_assert(alignof(EFI_IMAGE_NT_HEADERS64) == 8,
              "wrong defintion of IMAGE_NT_HEADERS64");
static_assert(offsetof(EFI_IMAGE_NT_HEADERS32, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS32");
static_assert(offsetof(EFI_IMAGE_NT_HEADERS64, FileHeader) == 4,
              "wrong definition of IMAGE_NT_HEADERS64");
static_assert(OPTIONAL_HEADER_OFFSET64 == 24, "wrong offset of optional header");

#define MIN_FILE_ALIGNMENT (UINT32_C(32))
#define MIN_OPTIONAL_HEADER_SIZE (offsetof(EFI_IMAGE_OPTIONAL_HEADER32, DataDirectory))
#define MAX_OPTIONAL_HEADER_SIZE (sizeof(EFI_IMAGE_OPTIONAL_HEADER64))

/**
 * Extract the NT header, skipping over any DOS header.
 *
 * If this function returns a valid pointer, the entire NT header is
 * guaranteed to be in bounds.  However, not all of it might actually be
 * valid.  Accessing invalid members (such as a nonexistent data directory)
 * will produce garbage from other parts of the PE file.  It will not
 * result in undefined behavior or a * memory access violation.
 *
 * \return The pointer on success, or NULL on failure.
 */
static const union PeHeader*
extract_pe_header(const uint8_t *const ptr, size_t const len)
{
#define NT_HEADER_OFFSET_LOC UINT32_C(60)
#define DOS_HEADER_SIZE (NT_HEADER_OFFSET_LOC + sizeof(uint32_t))
   union PeHeader const* pe_header;
   static_assert(DOS_HEADER_SIZE < sizeof(*pe_header),
                 "NT header shorter than DOS header?");

   if (len < sizeof(*pe_header)) {
      LOG("Too short (min length %zu, got %zu)", sizeof(*pe_header), len);
      return NULL;
   }

   if (ptr[0] == 'M' && ptr[1] == 'Z') {
      uint32_t nt_header_offset;
      /* Skip past DOS header */
      memcpy(&nt_header_offset, ptr + NT_HEADER_OFFSET_LOC, sizeof(uint32_t));

      if (nt_header_offset < DOS_HEADER_SIZE) {
         LOG("DOS header overlaps NT header (%" PRIu32 " less than %zu)",
             nt_header_offset, DOS_HEADER_SIZE);
         return NULL;
      }

      if (nt_header_offset > len - sizeof(*pe_header)) {
         LOG("NT header does not leave room for section (offset %" PRIi32 ", file size %zu)",
             nt_header_offset, len);
         return NULL;
      }

      if (nt_header_offset & 7) {
         LOG("NT header not 8-byte aligned (offset %" PRIi32 ")", nt_header_offset);
         return NULL;
      }

      LOG("Skipping DOS header of %" PRIu32 " bytes", nt_header_offset);
      pe_header = (const union PeHeader *)(ptr + nt_header_offset);
   } else {
      pe_header = (const union PeHeader *)ptr;
   }

   return pe_header;
}

static bool
validate_section_name(const EFI_IMAGE_SECTION_HEADER *section)
{
   /* Validate section name */
   const uint8_t *name = section->Name;
   if (name[0] != '.')
      LOG("Section name does not start with a \".\" - is it overlong?");
   for (uint8_t j = 0; j < sizeof(section->Name); ++j) {
      if (name[j] == '\0') {
         if (j < 1) {
            LOG("Empty section name not allowed");
            return false;
         }
         for (uint8_t k = j + 1; k < sizeof(section->Name); ++k) {
            if (name[k] != '\0') {
               LOG("Section name has non-NUL byte after NUL byte");
               return false;
            }
         }
         return true;
      }
      if (name[j] == '$') {
         LOG("$ not allowed in image section names");
         return false;
      }
      if (name[j] <= ' ' || name[j] > '~') {
         LOG("Invalid byte %" PRIu8 " in section name", name[j]);
         return false;
      }
   }
   return true;
}

static bool parse_file_header(const EFI_IMAGE_FILE_HEADER *untrusted_file_header,
                              uint32_t nt_len,
                              uint32_t *nt_header_size,
                              uint32_t *number_of_sections,
                              uint32_t *optional_header_size)
{
   if (!(untrusted_file_header->Characteristics & 0x2)) {
      LOG("File is not executable");
      return false;
   }
   if (untrusted_file_header->Characteristics & 0x1) {
      LOG("Relocations stripped from image");
   }
   if (untrusted_file_header->Characteristics & 0x2000) {
      LOG("DLL cannot be executable");
   }
   if (untrusted_file_header->PointerToSymbolTable ||
       untrusted_file_header->NumberOfSymbols) {
      LOG("COFF symbol tables detected: symbol table offset 0x%" PRIx32
          ", number of symbols 0x%" PRIx32,
          untrusted_file_header->PointerToSymbolTable,
          untrusted_file_header->NumberOfSymbols);
   }
   /*
    * FIXME: sanitize symbol table.  Note that if the file is signed,
    * these pointers must be offset by the contents of the certificate
    * table, as signing the file will change them.
    */

   /* sanitize SizeOfOptionalHeader start */
   uint32_t const SizeOfOptionalHeader = untrusted_file_header->SizeOfOptionalHeader;
   if (SizeOfOptionalHeader < MIN_OPTIONAL_HEADER_SIZE) {
      LOG("Optional header too short: got %" PRIu32 " but minimum is %zu",
          SizeOfOptionalHeader, MIN_OPTIONAL_HEADER_SIZE);
      return false;
   }
   if (SizeOfOptionalHeader > MAX_OPTIONAL_HEADER_SIZE) {
      LOG("Optional header too long: got %" PRIu32 " but maximum is %zu",
          SizeOfOptionalHeader, MAX_OPTIONAL_HEADER_SIZE);
      return false;
   }
   if (SizeOfOptionalHeader & 7) {
      LOG("Optional header size 0x%" PRIx16 " not multiple of 8",
          SizeOfOptionalHeader);
      return false;
   }

   /* sanitize NumberOfSections start */
   uint32_t const NumberOfSections = untrusted_file_header->NumberOfSections;
   if (NumberOfSections < 1) {
      LOG("No sections!");
      return false;
   }

   if (NumberOfSections > 96) {
      LOG("Too many sections: got %" PRIu16 ", limit 96", NumberOfSections);
      return false;
   }

   /*
    * Overflow is impossible because NumberOfSections is limited to 96 and
    * optional_header_size is limited to sizeof(IMAGE_OPTIONAL_HEADER64).
    * Therefore, the maximum is 40 * 96 + 112 + 16 * 8 = 4080 bytes.
    */
   uint32_t const untrusted_nt_headers_size =
      (NumberOfSections * (uint32_t)sizeof(EFI_IMAGE_SECTION_HEADER)) +
      ((uint32_t)OPTIONAL_HEADER_OFFSET32 + SizeOfOptionalHeader);
   /* sanitize NT headers size start */
   if (nt_len <= untrusted_nt_headers_size) {
      LOG("Section headers do not fit in image");
      return false;
   }
   *nt_header_size = untrusted_nt_headers_size;
   *number_of_sections = NumberOfSections;
   *optional_header_size = SizeOfOptionalHeader;
   /* sanitize NT headers size end */
   /* sanitize SizeOfOptionalHeader end */
   /* sanitize NumberOfSections end */

   return true;
}

static bool
validate_image_base_and_alignment(uint64_t const image_base,
                                  uint32_t const file_alignment,
                                  uint32_t const section_alignment)
{
   if (image_base % (1UL << 16)) {
      LOG("Image base 0x%" PRIx64 " not multiple of 0x%x", image_base, 1U << 16);
      return false;
   }
   if (section_alignment < (1U << 12)) {
      LOG("Section alignment too small (0x%" PRIx32 " < 0x%x)", section_alignment, 1U << 12);
      return false;
   }
   /*
    * The specification requires 512, but the Xen PE loader has 32 here,
    * and 32 is enough for all the casts to be well-defined.
    */
   if (file_alignment < MIN_FILE_ALIGNMENT) {
      LOG("File alignment too small (0x%" PRIx32 " < 0x%x)", file_alignment, MIN_FILE_ALIGNMENT);
      return false;
   }
   if (file_alignment > (1U << 16)) {
      LOG("Too large file alignment (0x%" PRIx32 " > 0x%x)", file_alignment, 1U << 16);
      return false;
   }
   if (file_alignment & (file_alignment - 1)) {
      LOG("Non-power of 2 file alignment 0x%" PRIx32, file_alignment);
      return false;
   }
   if (section_alignment < file_alignment) {
      LOG("File alignment greater than section alignment (0x%" PRIx32 " > 0x%" PRIx32 ")",
          file_alignment, section_alignment);
      return false;
   }
   if (section_alignment & (section_alignment - 1)) {
      LOG("Non-power of 2 section alignment 0x%" PRIx32, section_alignment);
      return false;
   }
   if (image_base & (section_alignment - 1)) {
      LOG("Image base 0x%" PRIx64 " not multiple of section alignment 0x%" PRIx32,
          image_base, section_alignment);
      return false;
   }

   return true;
}

static bool parse_optional_header(union PeHeader const *const untrusted_pe_header,
                                  struct ParsedImage *const image,
                                  uint32_t len,
                                  uint32_t nt_header_end,
                                  uint32_t optional_header_size,
                                  uint64_t *max_address) {
   uint64_t untrusted_image_base;
   uint32_t untrusted_file_alignment;
   uint32_t untrusted_section_alignment;
   uint32_t untrusted_size_of_headers;
   uint32_t untrusted_number_of_directory_entries;
   uint32_t min_size_of_optional_header;

   switch (untrusted_pe_header->shared.Magic) {
   case 0x10b:
      LOG("This is a PE32 file: magic 0x10b");
      static_assert(offsetof(EFI_IMAGE_NT_HEADERS32, OptionalHeader) == 24, "wrong offset");
      static_assert(offsetof(EFI_IMAGE_OPTIONAL_HEADER32, DataDirectory) == 96, "wrong size");
      min_size_of_optional_header = offsetof(EFI_IMAGE_OPTIONAL_HEADER32, DataDirectory);
      untrusted_image_base = untrusted_pe_header->pe32.OptionalHeader.ImageBase;
      untrusted_file_alignment = untrusted_pe_header->pe32.OptionalHeader.FileAlignment;
      untrusted_section_alignment = untrusted_pe_header->pe32.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->pe32.OptionalHeader.SizeOfHeaders;
      untrusted_number_of_directory_entries = untrusted_pe_header->pe32.OptionalHeader.NumberOfRvaAndSizes;
      image->directory = untrusted_pe_header->pe32.OptionalHeader.DataDirectory;
      *max_address = UINT32_MAX;
      break;
   case 0x20b:
      LOG("This is a PE32+ file: magic 0x20b");
      static_assert(offsetof(EFI_IMAGE_NT_HEADERS64, OptionalHeader) == 24, "wrong offset");
      static_assert(offsetof(EFI_IMAGE_OPTIONAL_HEADER64, DataDirectory) == 112, "wrong size");
      min_size_of_optional_header = offsetof(EFI_IMAGE_OPTIONAL_HEADER64, DataDirectory);
      untrusted_image_base = untrusted_pe_header->pe32p.OptionalHeader.ImageBase;
      untrusted_file_alignment = untrusted_pe_header->pe32p.OptionalHeader.FileAlignment;
      untrusted_section_alignment = untrusted_pe_header->pe32p.OptionalHeader.SectionAlignment;
      untrusted_size_of_headers = untrusted_pe_header->pe32p.OptionalHeader.SizeOfHeaders;
      untrusted_number_of_directory_entries = untrusted_pe_header->pe32p.OptionalHeader.NumberOfRvaAndSizes;
      image->directory = untrusted_pe_header->pe32p.OptionalHeader.DataDirectory;
      *max_address = UINT64_MAX;
      break;
   case 0xb20:
   case 0xb10:
      LOG("Optional header indicates endian-swapped file (not implemented) %" PRIu16,
          untrusted_pe_header->shared.Magic);
      return false;
   default:
      LOG("Bad optional header magic %" PRIu16, untrusted_pe_header->shared.Magic);
      return false;
   }

   /* sanitize directory entry number start */
   if (untrusted_number_of_directory_entries > 16) {
      LOG("Too many NumberOfRvaAndSizes (got %" PRIu32 ", limit 16",
          untrusted_number_of_directory_entries);
      return false;
   }
   image->directory_entries = untrusted_number_of_directory_entries;
   /* sanitize directory entry number end */

   if (!validate_image_base_and_alignment(untrusted_image_base,
                                          untrusted_file_alignment,
                                          untrusted_section_alignment))
      return false;
   image->file_alignment = untrusted_file_alignment;
   image->section_alignment = untrusted_section_alignment;
   image->image_base = untrusted_image_base;

   /* sanitize SizeOfHeaders start */
   if (untrusted_size_of_headers >= len) {
      LOG("SizeOfHeaders extends past end of image (0x%" PRIx32 " > 0x%zu)",
          untrusted_size_of_headers, len);
      return false;
   }
   if (untrusted_size_of_headers & (image->file_alignment - 1)) {
      LOG("Misaligned size of headers: got 0x%" PRIx32 " but alignment is 0x%" PRIx32,
          untrusted_size_of_headers, image->file_alignment);
      return false;
   }
   if (untrusted_size_of_headers < nt_header_end) {
      LOG("Bad size of headers: got 0x%" PRIx32 " but first byte after section headers is 0x%" PRIx32,
          untrusted_size_of_headers, nt_header_end);
      return false;
   }
   image->size_of_headers = untrusted_size_of_headers;
   /* sanitize SizeOfHeaders end */

   uint32_t const expected_optional_header_size =
      image->directory_entries * sizeof(EFI_IMAGE_DATA_DIRECTORY) +
      min_size_of_optional_header;
   if (optional_header_size != expected_optional_header_size) {
      LOG("Wrong optional header size: got %" PRIu32 " but computed %" PRIu32,
          optional_header_size, expected_optional_header_size);
      return false;
   }

   return true;
}


bool pe_parse(const uint8_t *const ptr, size_t const len, struct ParsedImage *image)
{
   if (len > 0x7FFFFFFFUL) {
      LOG("Too long (max length 0x7FFFFFFF, got 0x%zx)", len);
      return NULL;
   }

   if ((uintptr_t)(const void *)ptr & 7) {
      LOG("Pointer %p isn't 8-byte aligned", (const void*)ptr);
      return NULL;
   }

   union PeHeader const *const untrusted_pe_header = extract_pe_header(ptr, len);
   if (untrusted_pe_header == NULL) {
      return false;
   }
   uint32_t const nt_header_offset = (uint32_t)((uint8_t const *)untrusted_pe_header - ptr);
   const uint8_t *const optional_header = (const uint8_t*)untrusted_pe_header + OPTIONAL_HEADER_OFFSET32;

   if (memcmp(untrusted_pe_header, "PE\0", 4) != 0) {
      LOG("Bad magic for NT header at offset 0x%" PRIx32, nt_header_offset);
      return false;
   }

   uint32_t nt_header_size, optional_header_size;
   if (!parse_file_header(&untrusted_pe_header->shared.FileHeader,
                          (uint32_t)len - nt_header_offset,
                          &nt_header_size,
                          &image->n_sections,
                          &optional_header_size)) {
      return false;
   }
   image->sections = (const EFI_IMAGE_SECTION_HEADER *)(optional_header + optional_header_size);

   /* Overflow is impossible because nt_header_size is less than len - nt_header_offset. */
   uint32_t const nt_header_end = nt_header_size + nt_header_offset;
   uint64_t max_address;
   if (!parse_optional_header(untrusted_pe_header,
                              image,
                              (uint32_t)len,
                              nt_header_end,
                              optional_header_size,
                              &max_address))
      return false;
   for (uint32_t i = nt_header_end; i < image->size_of_headers; ++i) {
      if (ptr[i]) {
         LOG("Non-zero byte at offset 0x%" PRIx32 " that should be zero", i);
         return false;
      }
   }
   /* Overflow is impossible: max_address is always at least as large as image->image_base */
   uint64_t const image_address_space = max_address - image->image_base;
   uint32_t last_section_start = image->size_of_headers;
   uint64_t last_virtual_address = 0;
   uint64_t last_virtual_address_end = 0;
   const uint8_t *section_name = NULL, *new_section_name = NULL;
   for (uint32_t i = 0; i < image->n_sections; ++i) {
      if (image->sections[i].PointerToRelocations != 0 ||
          image->sections[i].NumberOfRelocations != 0) {
         LOG("Section %" PRIu32 " contains COFF relocations", i);
         return false;
      }

      if (image->sections[i].PointerToLinenumbers != 0 ||
          image->sections[i].NumberOfLinenumbers != 0) {
         LOG("Section %" PRIu32 " contains COFF line numbers", i);
         return false;
      }

      if (!validate_section_name(image->sections + i))
         return false;
      new_section_name = image->sections[i].Name;

      /* Validate PointerToRawData and SizeOfRawData */
      if (image->sections[i].PointerToRawData != 0) {
         if (len - last_section_start < image->sections[i].SizeOfRawData) {
            LOG("Section %" PRIu32 " too long: length is %" PRIu32 " but only %" PRIu32
                  " bytes remaining in file", i,
                  image->sections[i].SizeOfRawData,
                  (uint32_t)(len - last_section_start));
            return false;
         }
         if (image->sections[i].PointerToRawData & (image->file_alignment - 1)) {
            LOG("Misaligned raw data pointer");
            return false;
         }
         if (image->sections[i].SizeOfRawData & (image->file_alignment - 1)) {
            LOG("Misaligned raw data size");
            return false;
         }
         if (image->sections[i].PointerToRawData != last_section_start) {
            LOG("Section %" PRIu32 " starts at 0x%" PRIx32 ", but %s at 0x%" PRIx32,
                i, image->sections[i].PointerToRawData,
                i > 0 ? "previous section ends" : "NT headers end",
                last_section_start);
            return false;
         }
         if (image->sections[i].SizeOfRawData < image->sections[i].Misc.VirtualSize) {
            LOG("Section %" PRIu32 " has size 0x%" PRIx32 " in the file, but "
                "0x%" PRIx32 " in memory", i, image->sections[i].SizeOfRawData,
                image->sections[i].Misc.VirtualSize);
            return false;
         }
         last_section_start += image->sections[i].SizeOfRawData;
      } else {
         if (image->sections[i].SizeOfRawData != 0) {
            LOG("Section %" PRIu32 " starts at zero but has nonzero size", i);
            return false;
         }
      }

      /* Validate VirtualAddress and VirtualSize */
      if (image->sections[i].VirtualAddress > image_address_space) {
         LOG("VMA too large: 0x%" PRIx32 " extends beyond address space [0x%" PRIx64 ", 0x%" PRIx64 "]",
             image->sections[i].VirtualAddress, image->image_base, max_address);
         return false;
      }
      uint64_t const untrusted_virtual_address = image->sections[i].VirtualAddress + image->image_base;
      if (untrusted_virtual_address & (image->section_alignment - 1)) {
         LOG("Section %" PRIu32 " (%.8s) has misaligned VMA: 0x%" PRIx64 " not aligned to 0x%" PRIx32,
             i, image->sections[i].Name, untrusted_virtual_address, image->section_alignment);
      }
      if (max_address - untrusted_virtual_address < image->sections[i].Misc.VirtualSize) {
         LOG("Virtual address overflow: 0x%" PRIx64 " + 0x%" PRIx32 " > 0x%" PRIx64,
             untrusted_virtual_address, image->sections[i].Misc.VirtualSize, max_address);
         return false;
      }
      LOG("Section %" PRIu32 "(name %.8s) has flags 0x%" PRIx32, i, new_section_name, image->sections[i].Characteristics);
      uint32_t untrusted_characteristics = image->sections[i].Characteristics;
      if ((untrusted_characteristics & pe_section_reserved_bits) != 0) {
         LOG("Section %" PRIu32 ": characteristics 0x%08" PRIx32 " has reserved bits",
             i, untrusted_characteristics);
         return false;
      }
      if ((untrusted_characteristics & (pe_section_code|pe_section_initialized_data|pe_section_uninitialized_data))) {
         if (untrusted_virtual_address < last_virtual_address) {
            assert(new_section_name != NULL);
            assert(section_name != NULL);
            LOG("Sections not sorted by VA: current section (%.8s) VA 0x%" PRIx64 " < previous section (%.8s) 0x%" PRIx64,
                new_section_name, untrusted_virtual_address, section_name, last_virtual_address);
            return false;
         }
         if (untrusted_virtual_address < last_virtual_address_end) {
            assert(new_section_name != NULL);
            assert(section_name != NULL);
            LOG("Sections %.8s (%" PRIu32 ") and %.8s (%" PRIu32 ") overlap in memory: 0x%" PRIx64 " in [0x%" PRIx64 ", 0x%" PRIx64 ")",
                section_name, i - 1, new_section_name, i, untrusted_virtual_address, last_virtual_address, last_virtual_address_end);
            return false;
         }
         last_virtual_address = untrusted_virtual_address;
         last_virtual_address_end = last_virtual_address + image->sections[i].Misc.VirtualSize;
         section_name = new_section_name;
      }

   }

   uint32_t untrusted_signature_size = 0;
   uint32_t untrusted_signature_offset = 0;
   if (image->directory_entries >= 5) {
      untrusted_signature_offset = image->directory[4].VirtualAddress;
      untrusted_signature_size = image->directory[4].Size;
   }
   if (untrusted_signature_offset == 0) {
      if (untrusted_signature_size != 0) {
         LOG("Signature offset zero but size nonzero");
         return false;
      } else {
         LOG("File is not signed");
      }
   } else {
      /* sanitize signature offset and size start */
      if (untrusted_signature_offset != last_section_start) {
         LOG("Signature does not start immediately after last section (%" PRIu32 " != %" PRIu32 ")",
               untrusted_signature_offset, last_section_start);
         return false;
      }

      if (untrusted_signature_size > len - last_section_start) {
         LOG("Signature too large (got 0x%" PRIx32 "but only 0x%zu bytes left in file)",
               untrusted_signature_size, len - last_section_start);
         return false;
      }

      if ((untrusted_signature_size & 7) != 0) {
         LOG("Signature size not a multiple of 8 (got 0x%" PRIx32 ")",
             untrusted_signature_size);
         return false;
      }

      uint32_t signature_offset = untrusted_signature_offset;
      uint32_t signature_size = untrusted_signature_size;
      /* sanitize signature offset and size end */

      /* Alignment is guaranteed initially because signature_offset was checked to equal
       * last_section_start, and last_section_start must be a multiple of file_alignment.
       * file_alignment, in turn, must be at least 32 and a power of 2.  Alignment will
       * be maintained because sig->length must be a multiple of 8.
       */
      do {
         if (signature_size < sizeof(WIN_CERTIFICATE)) {
            LOG("Signature too small (got %" PRIu32 ", minimum 8", signature_size);
            return false;
         }
         const WIN_CERTIFICATE *sig = (const WIN_CERTIFICATE *)(ptr + signature_offset);
         if (sig->wRevision != 0x0200) {
            LOG("Wrong signature version 0x%" PRIx16, sig->wRevision);
            return false;
         }
         if (sig->wCertificateType != 0x0002) {
            LOG("Wrong signature type 0x%" PRIx16, sig->wCertificateType);
            return false;
         }
         if (sig->dwLength > signature_size) {
            LOG("Signature too long: signature is 0x%" PRIx32 " bytes but directory entry has 0x%" PRIx32 " bytes",
                sig->dwLength, signature_size);
            return false;
         }
         if (sig->dwLength < sizeof(WIN_CERTIFICATE)) {
            LOG("Signature too small (got %" PRIu32 ", minimum 8", sig->dwLength);
            return false;
         }
         if (sig->dwLength & 7) {
            LOG("Signature length 0x%" PRIx32 " is not 8-byte aligned", sig->dwLength);
            return false;
         }
         LOG("Signature at offset 0x%" PRIx32 " with length 0x%" PRIx32,
             signature_offset, sig->dwLength);
         signature_offset += sig->dwLength;
         signature_size -= sig->dwLength;
      } while (signature_size > 0);
   }
   return true;
}
