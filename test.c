#include <string.h>
#include <stdalign.h>
#include "winpe.h"
#include "winpe-private.h"

// Test DOS header parsing
static void test_dos_header(void) {
   uint8_t alignas(8) header[sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION) + 128] = {
      'P', 'E', '\0', '\0',
   };
   // valid
   assert((void *)extract_pe_header(header, sizeof header - 128) == (void *)header);
   // misaligned
   assert(extract_pe_header(header + 1, sizeof header - 128) == NULL);
   // too short
   assert(extract_pe_header(header, sizeof header - 129) == NULL);
   // too long
   assert(extract_pe_header(header, 0x7FFFFFFFUL + 1) == NULL);
   // Corrupt the NT header magic
   uint32_t nt_offset = 128;
   // marmarek: what is 60? use #define or a comment (or sizeof() relevant structure) to describe it
   memcpy(header + 60, &nt_offset, 4);
   memcpy(header + nt_offset, "PE\0", 4);
   header[0] = 'M';
   assert((void *)extract_pe_header(header, sizeof header - 128) == NULL);
   assert((void *)extract_pe_header(header, sizeof header) == NULL);
   // Add a DOS header
   header[1] = 'Z';
   // Check that the DOS header is skipped
   for (nt_offset = 2; nt_offset < 136; nt_offset += 1) {
      memcpy(header + nt_offset, "PE\0", 4);
      memcpy(header + 60, &nt_offset, 4);
      // Check that the DOS header is skipped
      if (nt_offset % 8 == 0 && nt_offset >= 64 && nt_offset < 136) {
         assert((void *)extract_pe_header(header, sizeof header) == header + nt_offset);
         header[nt_offset] = 0;
         assert((void *)extract_pe_header(header, sizeof header) == NULL);
      } else {
         assert((void *)extract_pe_header(header, sizeof header) == NULL);
      }
   }
   // Check for integer overflow problems
   for (nt_offset = UINT32_MAX - sizeof header;; nt_offset += 1) {
      memcpy(header + 60, &nt_offset, 4);
      assert((void *)extract_pe_header(header, sizeof header) == NULL);
      if (nt_offset == UINT32_MAX)
         break;
   }
}

int main(void)
{
   test_dos_header();
}
