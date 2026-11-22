// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/stat.h>
#include <linux/string.h>
#include "protected_install_kernel.h"
#include "su_durable_authority.h"
#include "su_durable_modern.h"

#define MSU_DURABLE_LIMIT (1024U * 1024U)
#define MSU_DURABLE_ROWS 4095U
struct msu_durable_authority {
    refcount_t references;
    char directory[24];
    char path[48];
};
struct msu_durable_span { const char *data; size_t size; };
struct msu_durable_row {
    bool explicit;
    u32 uid, decision;
    u64 device, inode;
    struct msu_durable_span package, members;
};
struct msu_durable_document {
    struct file *file;
    void *bytes;
    size_t length;
    struct kstat stat;
};
static bool msu_durable_package(struct msu_durable_span name)
{
    size_t i;
    if (!name.size || name.size >= 256) return false;
    if ((name.size == 1 && name.data[0] == '.') ||
        (name.size == 2 && !memcmp(name.data, "..", 2))) return false;
    for (i = 0; i < name.size; ++i) {
        unsigned char c = name.data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_')) return false;
    }
    return true;
}
static bool msu_durable_equal(struct msu_durable_span a, struct msu_durable_span b)
{ return a.size == b.size && !memcmp(a.data, b.data, a.size); }
static bool msu_durable_uid(u64 uid)
{ return uid <= 0x7fffffffU && (uid >= 2000U || uid == 1000U); }
static int msu_durable_number(struct msu_durable_span value, u64 *output)
{
    size_t i;
    u64 number = 0;
    if (!value.size) return -EBADMSG;
    for (i = 0; i < value.size; ++i) {
        unsigned char c = value.data[i];
        if (c < '0' || c > '9' || number > (~0ULL - (c - '0')) / 10)
            return -EBADMSG;
        number = number * 10 + c - '0';
    }
    *output = number;
    return 0;
}
static int msu_durable_split(struct msu_durable_span *input, char delimiter,
    struct msu_durable_span *part)
{
    const char *found = memchr(input->data, delimiter, input->size);
    if (!found) return -EBADMSG;
    part->data = input->data;
    part->size = found - input->data;
    input->size -= part->size + 1;
    input->data = found + 1;
    return 0;
}
static int msu_durable_member(struct msu_durable_span *input,
    struct msu_durable_span *package, u64 *device, u64 *inode)
{
    struct msu_durable_span part, one;
    const char *end = memchr(input->data, ';', input->size);
    one.data = input->data;
    one.size = end ? (size_t)(end - input->data) : input->size;
    input->size -= one.size + (end != NULL);
    input->data += one.size + (end != NULL);
    if (end && !input->size) return -EBADMSG;
    if (msu_durable_split(&one, '=', package) || !msu_durable_package(*package) ||
        msu_durable_split(&one, ',', &part) || msu_durable_number(part, device) ||
        msu_durable_number(one, inode) || !*inode) return -EBADMSG;
    return 0;
}
static int msu_durable_parse(struct msu_durable_span text, struct msu_durable_row *row)
{
    static const char prefix[] = "@maplesu_uid_v1:";
    struct msu_durable_span part, rest, previous = {0};
    u64 uid, device, inode;
    memset(row, 0, sizeof(*row));
    if (text.size < sizeof(prefix) - 1 ||
        memcmp(text.data, prefix, sizeof(prefix) - 1)) {
        if (!msu_durable_package(text)) return -EBADMSG;
        row->package = text;
        row->decision = 1;
        return 0;
    }
    text.data += sizeof(prefix) - 1;
    text.size -= sizeof(prefix) - 1;
    row->explicit = true;
    if (msu_durable_split(&text, ':', &part) || msu_durable_number(part, &uid) ||
        !msu_durable_uid(uid)) return -EBADMSG;
    row->uid = uid;
    if (msu_durable_split(&text, ':', &part) || part.size != 1 ||
        (part.data[0] != '0' && part.data[0] != '1')) return -EBADMSG;
    row->decision = part.data[0] - '0';
    if (msu_durable_split(&text, ':', &part) || msu_durable_number(part, &row->device) ||
        msu_durable_split(&text, ':', &part) || msu_durable_number(part, &row->inode) ||
        msu_durable_split(&text, ':', &row->package) || !msu_durable_package(row->package))
        return -EBADMSG;
    row->members = text;
    if (!row->decision) return row->device || row->inode || text.size ? -EBADMSG : 0;
    if (!row->inode || !text.size) return -EBADMSG;
    rest = text;
    while (rest.size) {
        size_t common;
        int order;
        if (msu_durable_member(&rest, &part, &device, &inode)) return -EBADMSG;
        common = min(previous.size, part.size);
        order = common ? memcmp(previous.data, part.data, common) : -1;
        if (previous.size && (order > 0 || (!order && previous.size >= part.size)))
            return -EBADMSG;
        previous = part;
    }
    return 0;
}
static bool msu_durable_space(unsigned char c)
{ return c == ' ' || (c >= '\t' && c <= '\r'); }
static bool msu_durable_line(struct msu_durable_span *input, struct msu_durable_span *line)
{
    const char *end;
    size_t length;
    if (!input->size) return false;
    end = memchr(input->data, '\n', input->size);
    length = end ? (size_t)(end - input->data) : input->size;
    line->data = input->data;
    line->size = length;
    input->data += length + (end != NULL);
    input->size -= length + (end != NULL);
    while (line->size && msu_durable_space(line->data[0])) { ++line->data; --line->size; }
    while (line->size && msu_durable_space(line->data[line->size - 1])) --line->size;
    return true;
}
static void msu_durable_drop(struct msu_durable_document *document)
{
    if (document->file) fput(document->file);
    kvfree(document->bytes);
    memset(document, 0, sizeof(*document));
}
static int msu_durable_read(const char *path, struct msu_durable_document *document)
{
    int error;
    memset(document, 0, sizeof(*document));
    error = msu_kernel_read_protected_document(path, MSU_DURABLE_LIMIT,
        &document->file, &document->bytes, &document->length, &document->stat);
    if (error) return error;
    if (__kuid_val(document->stat.uid) || document->stat.nlink != 1 ||
        document->stat.mode & 0077) { msu_durable_drop(document); return -EPERM; }
    if (memchr(document->bytes, 0, document->length)) {
        msu_durable_drop(document); return -EBADMSG;
    }
    return 0;
}
static int msu_durable_revalidate(const char *path, const struct msu_durable_document *document)
{
    struct file *held;
    struct kstat current_stat;
    const struct kstat *prior = &document->stat;
    int error = msu_kernel_stat_protected_path(path, false, &held, &current_stat);
    if (error) return error;
    if (file_inode(held) != file_inode(document->file) ||
        prior->ino != current_stat.ino || prior->dev != current_stat.dev ||
        prior->size != current_stat.size || prior->nlink != current_stat.nlink ||
        prior->mode != current_stat.mode || !uid_eq(prior->uid, current_stat.uid) ||
        !gid_eq(prior->gid, current_stat.gid) ||
        prior->mtime.tv_sec != current_stat.mtime.tv_sec ||
        prior->mtime.tv_nsec != current_stat.mtime.tv_nsec ||
        prior->ctime.tv_sec != current_stat.ctime.tv_sec ||
        prior->ctime.tv_nsec != current_stat.ctime.tv_nsec) error = -EAGAIN;
    fput(held);
    return error;
}
static int msu_durable_resolve(const struct msu_durable_document *list,
    struct msu_durable_span package, u32 *uid)
{
    struct msu_durable_span rest = {list->bytes, list->length}, line, name, number;
    u32 found = 0;
    while (msu_durable_line(&rest, &line)) {
        size_t i = 0, start;
        u64 value;
        if (!line.size) continue;
        while (i < line.size && !msu_durable_space(line.data[i])) ++i;
        name.data = line.data; name.size = i;
        while (i < line.size && msu_durable_space(line.data[i])) ++i;
        start = i;
        while (i < line.size && !msu_durable_space(line.data[i])) ++i;
        number.data = line.data + start; number.size = i - start;
        if (!msu_durable_equal(name, package)) continue;
        if (msu_durable_number(number, &value) || !msu_durable_uid(value) || value >= 100000)
            return -EBADMSG;
        if (found && found != value) return -EBADMSG;
        found = value;
    }
    if (!found) return -ENOENT;
    *uid = found;
    return 0;
}
/* Check absence again before publishing a compatibility decision. Modern
 * bin+journal selection never falls back to an older SDK mirror. */
static int msu_durable_modern_absent(void)
{
    struct file *file;
    struct kstat stat;
    int error = msu_kernel_stat_protected_path("/data/adb/maplesu/authorization", true, &file, &stat);
    if (error == -ENOENT) return 0;
    if (error) return error;
    fput(file);
    return -EAGAIN;
}
static int msu_durable_match(const struct msu_durable_row *row,
    const struct msu_su_verified_install *installation)
{
    struct msu_durable_span rest = row->members, package;
    u64 device, inode;
    u32 index = 0;
    bool representative = false;
    while (rest.size) {
        struct file *file;
        struct kstat stat;
        char name[256];
        int error = msu_durable_member(&rest, &package, &device, &inode);
        if (error) return error;
        if (index >= installation->member_count ||
            strlen(installation->members[index].package) != package.size ||
            memcmp(installation->members[index].package, package.data, package.size)) return -ESTALE;
        memcpy(name, package.data, package.size); name[package.size] = 0;
        error = msu_kernel_stat_observed_app_directory(installation->full_uid, name, &file, &stat);
        if (error) return error;
        fput(file);
        if (device != huge_encode_dev(stat.dev) || inode != stat.ino) return -ESTALE;
        if (msu_durable_equal(package, row->package)) {
            if (row->device != device || row->inode != inode) return -ESTALE;
            representative = true;
        }
        ++index;
    }
    return representative && index == installation->member_count ? 0 : -ESTALE;
}
static int msu_durable_compare_uids(const void *a, const void *b)
{
    u32 left = *(const u32 *)a, right = *(const u32 *)b;
    return left < right ? -1 : left != right;
}
static int msu_durable_list(const void *owner, u32 *uids, u32 capacity, u32 *count)
{
    const struct msu_durable_authority *authority = owner;
    struct msu_durable_document document = {0}, list = {0};
    struct msu_durable_span rest, line;
    u32 *values;
    u32 used = 0, i, explicit_count = 0;
    u32 *explicit_uids;
    int error;
    if (!authority || !uids || !count || capacity > MSU_DURABLE_ROWS) return -EINVAL;
    error = msu_su_modern_authority_list(uids, capacity, count);
    if (error != -ENODATA) return error;
    error = msu_durable_read(authority->path, &document);
    if (error) return error;
    values = kcalloc(MSU_DURABLE_ROWS * 2, sizeof(*values), GFP_KERNEL);
    if (!values) { error = -ENOMEM; goto out; }
    explicit_uids = values + MSU_DURABLE_ROWS;
    rest.data = document.bytes; rest.size = document.length;
    while (msu_durable_line(&rest, &line)) {
        struct msu_durable_row row;
        u32 uid;
        if (!line.size) continue;
        error = msu_durable_parse(line, &row);
        if (error) goto free_values;
        if (row.explicit) {
            uid = row.uid;
            for (i = 0; i < explicit_count; ++i)
                if (explicit_uids[i] == uid) { error = -EBADMSG; goto free_values; }
            if (explicit_count == MSU_DURABLE_ROWS) { error = -E2BIG; goto free_values; }
            explicit_uids[explicit_count++] = uid;
        } else {
            if (!list.file) {
                error = msu_kernel_read_protected_document("/data/system/packages.list", MSU_DURABLE_LIMIT,
                    &list.file, &list.bytes, &list.length, &list.stat);
                if (error) goto free_values;
            }
            error = msu_durable_resolve(&list, row.package, &uid);
            if (error == -ENOENT) continue;
            if (error) goto free_values;
        }
        for (i = 0; i < used && values[i] != uid; ++i) {}
        if (i < used) continue;
        if (used == MSU_DURABLE_ROWS) { error = -E2BIG; goto free_values; }
        values[used++] = uid;
    }
    error = msu_durable_revalidate(authority->path, &document);
    if (!error && list.file) error = msu_durable_revalidate("/data/system/packages.list", &list);
    if (!error) error = msu_durable_modern_absent();
    if (error) goto free_values;
    if (used > capacity) { error = -ENOSPC; goto free_values; }
    sort(values, used, sizeof(*values), msu_durable_compare_uids, NULL);
    memcpy(uids, values, used * sizeof(*uids));
    *count = used;
free_values:
    kfree(values);
out:
    msu_durable_drop(&list);
    msu_durable_drop(&document);
    return error;
}
static int msu_durable_grant(const void *owner,
    const struct msu_su_verified_install *installation, struct msu_su_saved_grant *grant)
{
    const struct msu_durable_authority *authority = owner;
    struct msu_durable_document document;
    struct msu_durable_span rest, line;
    struct msu_durable_row selected = {0};
    struct msu_su_saved_grant output = {0};
    bool legacy = false, explicit = false;
    int error;
    u32 i;
    if (!authority || !installation || !installation->pin || !grant ||
        !installation->member_count || installation->member_count > MSU_SU_INSTALL_MAX_MEMBERS ||
        !installation->members) return -EINVAL;
    error = msu_su_modern_authority_grant(installation, grant);
    if (error != -ENODATA) return error;
    error = msu_durable_read(authority->path, &document);
    if (error) return error;
    rest.data = document.bytes; rest.size = document.length;
    while (msu_durable_line(&rest, &line)) {
        struct msu_durable_row row;
        if (!line.size) continue;
        error = msu_durable_parse(line, &row);
        if (error) goto out;
        if (row.explicit && row.uid == installation->full_uid) {
            if (explicit) { error = -EBADMSG; goto out; }
            explicit = true; selected = row;
        } else if (!row.explicit && installation->full_uid < 100000) {
            for (i = 0; i < installation->member_count; ++i) {
                struct msu_durable_span name = {installation->members[i].package,
                    strnlen(installation->members[i].package, 256)};
                if (name.size == 256) { error = -EINVAL; goto out; }
                if (msu_durable_equal(row.package, name)) legacy = true;
            }
        }
    }
    if (!explicit && !legacy) { error = -ENOENT; goto out; }
    if (explicit && selected.decision) {
        error = msu_durable_match(&selected, installation);
        if (error) goto out;
    }
    error = msu_durable_revalidate(authority->path, &document);
    if (!error) error = msu_durable_modern_absent();
    if (error) goto out;
    output.full_uid = installation->full_uid;
    output.decision = explicit ? selected.decision : 1;
    memcpy(output.installation_id, installation->installation_id, sizeof(output.installation_id));
    output.profile.use_default = output.decision != 0;
    output.profile.allow_su = output.decision != 0;
    *grant = output;
out:
    msu_durable_drop(&document);
    return error;
}
static void msu_durable_put(const void *owner)
{
    struct msu_durable_authority *authority = (void *)owner;
    if (authority && refcount_dec_and_test(&authority->references)) kfree(authority);
}
int msu_su_durable_authority_create(const unsigned char name[16],
    struct msu_su_observed_authority *output)
{
    struct msu_su_observed_authority selected = {0};
    struct msu_durable_authority *authority;
    unsigned int i;
    if (!name || !output) return -EINVAL;
    for (i = 0; i < 16; ++i)
        if (!((name[i] >= 'A' && name[i] <= 'Z') || (name[i] >= 'a' && name[i] <= 'z') ||
            (name[i] >= '0' && name[i] <= '9'))) return -EINVAL;
    authority = kzalloc(sizeof(*authority), GFP_KERNEL);
    if (!authority) return -ENOMEM;
    refcount_set(&authority->references, 1);
    memcpy(authority->directory, "/data/", 6);
    memcpy(authority->directory + 6, name, 16);
    authority->directory[22] = name[0];
    snprintf(authority->path, sizeof(authority->path), "%s/su_allowlist.txt", authority->directory);
    selected.owner = authority;
    selected.read_grant = msu_durable_grant;
    selected.put_owner = msu_durable_put;
    selected.list_uids = msu_durable_list;
    memcpy(selected.directory, authority->directory, sizeof(selected.directory));
    memcpy(selected.filename, "su_allowlist.txt", sizeof("su_allowlist.txt"));
    *output = selected;
    return 0;
}
int msu_su_durable_authority_load(const struct msu_su_observed_authority *authority,
    u32 *uids, u32 capacity, u32 *count)
{
    if (!authority || authority->list_uids != msu_durable_list) return -EINVAL;
    return msu_durable_list(authority->owner, uids, capacity, count);
}
