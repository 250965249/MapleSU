use super::*;
use android_bootimg::cpio::{Cpio, CpioEntry};
use android_bootimg::layouts::{VENDOR_BOOT_HEADER_V3, VENDOR_BOOT_HEADER_V4};

fn put_u32(data: &mut [u8], offset: usize, value: usize) {
    data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

fn align_page(data: &mut Vec<u8>) {
    data.resize((data.len() + 4095) & !4095, 0);
}

fn cpio(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Cpio::new();
    for (path, contents) in files {
        archive.add(path, CpioEntry::regular(0o640, Box::new(contents.to_vec()))).unwrap();
    }
    let mut data = Vec::new();
    archive.dump(&mut data).unwrap();
    data
}

fn image(version: usize, fragments: &[Vec<u8>]) -> Vec<u8> {
    let layout = if version == 3 { &VENDOR_BOOT_HEADER_V3 } else { &VENDOR_BOOT_HEADER_V4 };
    let mut bytes = vec![0; 4096];
    bytes[..8].copy_from_slice(b"VNDRBOOT");
    put_u32(&mut bytes, layout.offset_header_version as usize, version);
    put_u32(&mut bytes, layout.offset_page_size as usize, 4096);
    put_u32(&mut bytes, 2096, layout.total_size as usize);
    put_u32(&mut bytes, layout.offset_ramdisk_size as usize, fragments.iter().map(Vec::len).sum());
    put_u32(&mut bytes, layout.offset_dtb_size as usize, 8);
    for fragment in fragments { bytes.extend_from_slice(fragment); }
    align_page(&mut bytes);
    bytes.extend_from_slice(b"DTB_TEST");
    align_page(&mut bytes);
    if version == 4 {
        put_u32(&mut bytes, layout.offset_vendor_ramdisk_table_size as usize, fragments.len() * 108);
        put_u32(&mut bytes, layout.offset_vendor_ramdisk_table_entry_num as usize, fragments.len());
        put_u32(&mut bytes, layout.offset_vendor_ramdisk_table_entry_size as usize, 108);
        put_u32(&mut bytes, layout.offset_bootconfig_size as usize, 4);
        let mut offset = 0;
        for (index, fragment) in fragments.iter().enumerate() {
            let mut entry = vec![0; 108];
            put_u32(&mut entry, 0, fragment.len());
            put_u32(&mut entry, 4, offset);
            put_u32(&mut entry, 8, index + 1);
            let name = format!("fragment{index}");
            entry[12..12 + name.len()].copy_from_slice(name.as_bytes());
            entry[44..].fill((index + 1) as u8);
            bytes.extend_from_slice(&entry);
            offset += fragment.len();
        }
        align_page(&mut bytes);
        bytes.extend_from_slice(b"x=1\n");
        align_page(&mut bytes);
    }
    bytes.resize(bytes.len() + 8192, 0);
    bytes
}

fn fragment_entries(image_bytes: &[u8]) -> Vec<Cpio> {
    let parsed = BootImage::parse(image_bytes).unwrap();
    let ramdisk = parsed.get_blocks().get_ramdisk().unwrap();
    if ramdisk.is_vendor_ramdisk() {
        ramdisk.iter_vendor_ramdisk().map(|entry| {
            let mut bytes = Vec::new();
            entry.dump(&mut bytes, false).unwrap();
            Cpio::load_from_data(&bytes).unwrap()
        }).collect()
    } else {
        let mut bytes = Vec::new();
        ramdisk.dump(&mut bytes, false).unwrap();
        vec![Cpio::load_from_data(&bytes).unwrap()]
    }
}

#[test]
fn vendor_v3_removal_roundtrips_and_is_idempotent() {
    let original = image(3, &[cpio(&[("lib/modules/vr.ko", b"vr"), ("fstab.fixture", b"keep")])]);
    let (cleaned, report) = clean_vendor_boot(&original).unwrap();
    assert!(report.changed());
    assert_eq!(cleaned.len(), original.len());
    let entries = fragment_entries(&cleaned);
    assert!(!entries[0].exists("lib/modules/vr.ko"));
    assert!(entries[0].exists("fstab.fixture"));
    assert!(cleaned.windows(8).any(|s| s == b"DTB_TEST"));
    assert!(!clean_vendor_boot(&cleaned).unwrap().1.changed());
}

#[test]
fn vendor_v4_visits_all_fragments_preserves_unchanged_fragment_and_metadata() {
    let untouched = cpio(&[("lib/modules/other.ko", b"other")]);
    let original = image(4, &[
        cpio(&[("lib/modules/vr.ko", b"vr")]),
        cpio(&[("lib/modules/vklp.ko.xz", b"vklp")]),
        untouched.clone(),
    ]);
    let parsed = BootImage::parse(&original).unwrap();
    let (cleaned, report) = clean_vendor_boot(&original).unwrap();
    assert!(report.changed());
    let entries = fragment_entries(&cleaned);
    assert_eq!(entries.len(), 3);
    assert!(!entries[0].exists("lib/modules/vr.ko"));
    assert!(!entries[1].exists("lib/modules/vklp.ko.xz"));
    assert!(entries[2].exists("lib/modules/other.ko"));
    let after = BootImage::parse(&cleaned).unwrap();
    let original_rd = parsed.get_blocks().get_ramdisk().unwrap();
    let new_rd = after.get_blocks().get_ramdisk().unwrap();
    let mut raw = Vec::new();
    new_rd.get_vendor_ramdisk(2).unwrap().dump(&mut raw, true).unwrap();
    assert_eq!(raw, untouched);
    for i in 0..3 {
        let old = original_rd.get_vendor_ramdisk(i).unwrap();
        let new = new_rd.get_vendor_ramdisk(i).unwrap();
        assert_eq!(old.get_name().unwrap(), new.get_name().unwrap());
        assert_eq!(format!("{:?}", old.get_entry_type()), format!("{:?}", new.get_entry_type()));
    }
    assert!(cleaned.windows(4).any(|s| s == b"x=1\n"));
}

#[test]
fn malformed_second_fragment_returns_error_before_an_output() {
    let original = image(4, &[cpio(&[("lib/modules/vr.ko", b"vr")]), b"NOT_A_CPIO_FRAGMENT".to_vec()]);
    assert!(clean_vendor_boot(&original).is_err());
}

#[test]
fn no_target_vendor_image_is_a_true_noop_for_canonical_indexes() {
    let original = image(4, &[cpio(&[("lib/modules/other.ko", b"other"), ("lib/modules/modules.dep", b"other.ko: helper.ko\n")])]);
    let (after, report) = clean_vendor_boot(&original).unwrap();
    assert!(!report.changed());
    assert_eq!(after, original);
}

#[test]
fn unrelated_dep_whitespace_is_byte_stable() {
    let original = image(3, &[cpio(&[("lib/modules/modules.dep", b"other.ko:  helper.ko\n")])]);
    let (cleaned, report) = clean_vendor_boot(&original).unwrap();
    assert!(!report.changed());
    assert_eq!(cleaned, original);
}

#[test]
fn binary_indexes_and_vendor_module_paths_are_outside_rmvr_scope() {
    let mut archive = Cpio::load_from_data(&cpio(&[
        ("vendor/lib/modules/vr.ko", b"vr"),
        ("lib/modules/modules.dep.bin", b"vr.ko\0"),
        ("lib/modules/vr.ko.zst", b"compressed_fixture"),
    ])).unwrap();
    let mut raw = Vec::new();
    archive.dump(&mut raw).unwrap();
    let (cleaned, report) = clean_cpio(&raw).unwrap();
    archive = Cpio::load_from_data(&cleaned).unwrap();
    assert_eq!(report.removed_modules, 1);
    assert!(archive.exists("vendor/lib/modules/vr.ko"));
    assert!(archive.exists("lib/modules/modules.dep.bin"));
}

#[test]
fn compressed_fragments_roundtrip_keep_formats_and_other_payloads() {
    use std::io::Write;

    for version in [3, 4] {
        for format in ["GZIP", "LZ4", "LZ4_LEGACY"] {
            let target = cpio(&[
                ("lib/modules/vr.ko", b"vr"),
                ("lib/modules/modules.load", b"vr.ko\nother.ko\n"),
                ("fstab.fixture", b"keep"),
            ]);
            let compressed = match format {
                "GZIP" => {
                    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(&target).unwrap();
                    encoder.finish().unwrap()
                }
                "LZ4" => {
                    let mut encoder = lz4::EncoderBuilder::new().build(Vec::new()).unwrap();
                    encoder.write_all(&target).unwrap();
                    let (bytes, result) = encoder.finish();
                    result.unwrap();
                    bytes
                }
                "LZ4_LEGACY" => {
                    let block = lz4::block::compress(&target, None, false).unwrap();
                    let mut bytes = vec![0x02, 0x21, 0x4c, 0x18];
                    bytes.extend_from_slice(&(block.len() as u32).to_le_bytes());
                    bytes.extend_from_slice(&block);
                    bytes
                }
                _ => unreachable!(),
            };

            let untouched = cpio(&[("lib/modules/other.ko", b"other")]);
            let fragments = if version == 4 {
                vec![compressed, untouched.clone()]
            } else {
                vec![compressed]
            };
            let original = image(version, &fragments);
                    let (cleaned, report) = clean_vendor_boot(&original).unwrap();
    assert!(report.changed());
            assert_eq!(cleaned.len(), original.len());
            let entries = fragment_entries(&cleaned);
            assert!(!entries[0].exists("lib/modules/vr.ko"));
            assert!(entries[0].exists("fstab.fixture"));
            let after = BootImage::parse(&cleaned).unwrap();
            let ramdisk = after.get_blocks().get_ramdisk().unwrap();
            let actual_format = if version == 4 {
                let mut second_raw = Vec::new();
                ramdisk.get_vendor_ramdisk(1).unwrap().dump(&mut second_raw, true).unwrap();
                assert_eq!(second_raw, untouched);
                format!("{:?}", ramdisk.get_vendor_ramdisk(0).unwrap().get_compress_format())
            } else {
                format!("{:?}", ramdisk.get_compress_format())
            };
            assert_eq!(actual_format, format);
            assert!(!clean_vendor_boot(&cleaned).unwrap().1.changed());
        }
    }
}

#[test]
fn module_names_and_all_text_indexes_follow_upstream_boundaries() {
    let (output, report) = clean_cpio(&cpio(&[
        ("lib/modules/6.6/VR.ko.lz4", b"remove"),
        ("lib/modules/vklp.ko.gz", b"remove"),
        ("lib/modules/vr_extra.ko", b"keep"),
        ("lib/modules/modules.load.recovery", b"# keep\r\nvr.ko\r\nother.ko\r\n"),
        ("lib/modules/modules.dep", b"vr.ko: helper.ko\nother.ko: vr.ko helper.ko vklp.ko.xz # comment\n"),
        ("lib/modules/modules.softdep", b"softdep vr pre: helper\nsoftdep other pre: vr helper post: vklp\n"),
        ("lib/modules/modules.alias", b"alias fixture vr\nalias other other\n"),
        ("lib/modules/modules.options", b"options vr x=1\noptions other y=2\n"),
        ("lib/modules/modules.blocklist", b"blocklist vklp\nblocklist other\n"),
        ("lib/modules/modules.order", b"vr.ko\nother.ko\n"),
    ])).unwrap();
    assert_eq!(report.removed_modules,2); assert_eq!(report.updated_indexes,7);
    let cp = Cpio::load_from_data(&output).unwrap();
    for (name,expected) in [
        ("modules.load.recovery","# keep\r\nother.ko\r\n"),
        ("modules.dep","other.ko: helper.ko # comment\n"),
        ("modules.softdep","softdep other pre: helper post:\n"),
        ("modules.alias","alias other other\n"),
        ("modules.options","options other y=2\n"),
        ("modules.blocklist","blocklist other\n"),
        ("modules.order","other.ko\n"),
    ] { assert_eq!(cp.entry_by_name(&format!("lib/modules/{name}")).unwrap().data(),Some(expected.as_bytes()),"{name}"); }
    assert!(cp.exists("lib/modules/vr_extra.ko"));
}

fn records(data: &[u8]) -> Vec<&[u8]> {
    let mut at=0; let mut result=Vec::new();
    while at<data.len() {
        let h=&data[at..at+110];
        let n=usize::from_str_radix(std::str::from_utf8(&h[94..102]).unwrap(),16).unwrap();
        let len=usize::from_str_radix(std::str::from_utf8(&h[54..62]).unwrap(),16).unwrap();
        let end=(((at+110+n+3)&!3)+len+3)&!3;
        result.push(&data[at..end]); at=end;
    } result
}
#[test]
fn unchanged_cpio_metadata_and_record_order_are_byte_identical() {
    let mut source=cpio(&[("lib/modules/other.ko",b"KEEP"),("lib/modules/vr.ko",b"REMOVE")]);
    for (offset,value) in [(6,999),(22,2000),(30,3000),(46,123456)] {
        source[offset..offset+8].copy_from_slice(format!("{value:08x}").as_bytes());
    }
    let (after,_)=clean_cpio(&source).unwrap();
    let old=records(&source); let new=records(&after);
    assert_eq!(new[0],old[0]); assert_eq!(new[1],old[2]);
}
#[test]
fn hardlinked_target_or_modified_index_rejects_whole_archive() {
    for name in ["lib/modules/vr.ko","lib/modules/modules.load"] {
        let mut source=cpio(&[(name,b"vr.ko\n")]); source[38..46].copy_from_slice(b"00000002");
        assert!(clean_cpio(&source).is_err());
    }
}
#[test]
fn crc_index_updates_checksum_and_concatenated_archives_are_cleaned() {
    let mut source=cpio(&[("lib/modules/modules.load",b"vr.ko\nother.ko\n")]);
    source[..6].copy_from_slice(b"070702");
    let (after,_)=clean_cpio(&source).unwrap(); let row=records(&after)[0];
    assert_eq!(&row[..6],b"070702");
    let sum=b"other.ko\n".iter().fold(0u32,|sum,b|sum+u32::from(*b));
    assert_eq!(&row[102..110],format!("{sum:08x}").as_bytes());
    let mut concat=cpio(&[("lib/modules/vr.ko",b"remove")]); concat.extend_from_slice(&[0;16]);
    concat.extend_from_slice(&cpio(&[("lib/modules/vklp.ko",b"remove")]));
    assert_eq!(clean_cpio(&concat).unwrap().1.removed_modules,2);
}
