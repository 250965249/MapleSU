; Return zero for an invalid range; the caller reports ERR_MODULE_PARAM.
define internal fastcc i64 @maplesu_memory_protection_pages(i64 %address, i64 %size, i64 %page) {
entry:
  %p4 = icmp eq i64 %page, 4096
  %p16 = icmp eq i64 %page, 16384
  %p64 = icmp eq i64 %page, 65536
  %p4or16 = or i1 %p4, %p16
  %supported = or i1 %p4or16, %p64
  %nonempty = icmp ne i64 %size, 0
  %last = add i64 %size, -1
  %remaining = sub i64 -1, %address
  %nowrap = icmp ule i64 %last, %remaining
  %validsize = and i1 %nonempty, %nowrap
  %valid = and i1 %supported, %validsize
  br i1 %valid, label %calculate, label %invalid
calculate:
  %mask = add i64 %page, -1
  %offset = and i64 %address, %mask
  %whole = udiv i64 %size, %page
  %tail = urem i64 %size, %page
  %span = add i64 %offset, %tail
  %extra = udiv i64 %span, %page
  %residue = urem i64 %span, %page
  %hasresidue = icmp ne i64 %residue, 0
  %roundup = zext i1 %hasresidue to i64
  %with_extra = add i64 %whole, %extra
  %pages = add i64 %with_extra, %roundup
  ; The kernel set_memory_* ABI takes a signed int page count.
  %fits_count = icmp ule i64 %pages, 2147483647
  %page_mask = sub i64 0, %page
  %base = and i64 %address, %page_mask
  %bytes = mul i64 %pages, %page
  %room = sub i64 -1, %base
  %fits_end = icmp ule i64 %bytes, %room
  %fits = and i1 %fits_count, %fits_end
  %result = select i1 %fits, i64 %pages, i64 0
  ret i64 %result
invalid:
  ret i64 0
}
