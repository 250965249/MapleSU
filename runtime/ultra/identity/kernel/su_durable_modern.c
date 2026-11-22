// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#include <crypto/sha.h>
#else
#include <crypto/sha2.h>
#endif
#include "protected_install_kernel.h"
#include "su_durable_modern.h"

#define MSU_AUTH_ROOT "/data/adb/maplesu/authorization"
#define MSU_AUTH_MAX_BYTES (1024U * 1024U)
#define MSU_AUTH_MAX_GRANTS 10000U
#define MSU_AUTH_MAX_DIRS 20000U
struct msu_auth_span { const u8 *data; size_t size; };
struct msu_auth_document { struct file *file; void *bytes; size_t size; struct kstat stat; char path[128]; };
struct msu_auth_catalog { struct dir_context context; struct msu_auth_document root; u32 *uids, *locators; u32 count, locator_count, entries; int error; };
struct msu_auth_member { struct msu_auth_span package; u64 installed; u32 signer_count; u8 signers[32][32]; };
struct msu_auth_binary {
    const u8 *data; size_t size, position;
    u32 version, count; bool enabled;
};
struct msu_auth_journal { u64 revision, grant_revision, tomb_revision, profile_revision, max_profile_revision; bool switch_pending, decision_present, profile_present; };
struct msu_auth_marker { u32 uid; u64 revision; bool found; };
struct msu_auth_identity { u32 uid, member_count; struct msu_auth_span bytes; };
struct msu_auth_json { const u8 *data; size_t size, at; };

static int msu_auth_decimal(const u8 *text,size_t size,u64 *output)
{
    size_t i; u64 value = 0;
    if (!size) return -EBADMSG;
    for (i = 0; i < size; ++i) {
        u32 digit = text[i] - '0';
        if (digit > 9 || value > (0x7fffffffffffffffULL - digit) / 10) return -EBADMSG;
        value = value * 10 + digit;
    }
    *output = value; return 0;
}
static bool msu_auth_uid(u64 uid)
{ return uid <= 0x7fffffffU && uid % 100000U >= 10000 && uid % 100000U <= 19999; }
static int msu_auth_u32_compare(const void *a,const void *b)
{ u32 x = *(const u32 *)a,y = *(const u32 *)b; return x < y ? -1 : x != y; }
static void msu_auth_drop(struct msu_auth_document *document)
{
    if (document->file) fput(document->file);
    kvfree(document->bytes); memset(document,0,sizeof(*document));
}
static int msu_auth_read(const char *path,size_t limit,struct msu_auth_document *document)
{
    int error;
    memset(document,0,sizeof(*document));
    if (strscpy(document->path,path,sizeof(document->path)) < 0) return -ENAMETOOLONG;
    error = msu_kernel_read_protected_document(path,limit,&document->file,
        &document->bytes,&document->size,&document->stat);
    if (error) return error;
    if (__kuid_val(document->stat.uid) || document->stat.nlink != 1 ||
        (document->stat.mode & 07777) != 0600) {
        msu_auth_drop(document); return -EPERM;
    }
    return 0;
}
static int msu_auth_revalidate(const struct msu_auth_document *document)
{
    struct file *file; struct kstat stat; const struct kstat *prior = &document->stat;
    int error;
    if (!document->file) {
        error = msu_kernel_stat_protected_path(document->path,false,&file,&stat);
        if (!error) { fput(file); return -EAGAIN; }
        return error == -ENOENT ? 0 : error;
    }
    error = msu_kernel_stat_protected_path(document->path,S_ISDIR(prior->mode),&file,&stat);
    if (error) return error;
    if (file_inode(file) != file_inode(document->file) || prior->ino != stat.ino ||
        prior->dev != stat.dev || prior->size != stat.size || prior->nlink != stat.nlink ||
        prior->mode != stat.mode || !uid_eq(prior->uid,stat.uid) || !gid_eq(prior->gid,stat.gid) ||
        !timespec64_equal(&prior->mtime,&stat.mtime) || !timespec64_equal(&prior->ctime,&stat.ctime))
        error = -EAGAIN;
    fput(file); return error;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define MSU_AUTH_ACTOR_TYPE bool
#define MSU_AUTH_CONTINUE true
#define MSU_AUTH_STOP false
#else
#define MSU_AUTH_ACTOR_TYPE int
#define MSU_AUTH_CONTINUE 0
#define MSU_AUTH_STOP -EINVAL
#endif
MSU_AUTH_ACTOR_TYPE msu_su_authority_directory_actor(struct dir_context *context,
    const char *name,int size,loff_t offset,u64 inode,unsigned int type);
MSU_AUTH_ACTOR_TYPE msu_su_authority_directory_actor(struct dir_context *context,
    const char *name,int size,loff_t offset,u64 inode,unsigned int type)
{
    struct msu_auth_catalog *catalog = container_of(context,struct msu_auth_catalog,context);
    u64 value; u32 i; bool numeric = size > 0;
    (void)offset; (void)inode; (void)type;
    if (++catalog->entries > MSU_AUTH_MAX_DIRS) { catalog->error = -E2BIG; return MSU_AUTH_STOP; }
    for (i = 0; i < size; ++i) if (name[i] < '0' || name[i] > '9') numeric = false;
    if (numeric) {
        if (msu_auth_decimal((const u8 *)name,size,&value) || !msu_auth_uid(value) ||
            (size > 1 && name[0] == '0') || catalog->count == MSU_AUTH_MAX_DIRS) {
            catalog->error = -EBADMSG; return MSU_AUTH_STOP;
        }
        catalog->uids[catalog->count++] = value;
    } else if (size > 15 && !memcmp(name,"user-",5) &&
        !memcmp(name + size - 10,".authority",10)) {
        if (msu_auth_decimal((const u8 *)name + 5,size - 15,&value) ||
            value > 21474U || (size > 16 && name[5] == '0') ||
            catalog->locator_count == MSU_AUTH_MAX_DIRS) {
            catalog->error = -EBADMSG; return MSU_AUTH_STOP;
        }
        catalog->locators[catalog->locator_count++] = value;
    }
    return MSU_AUTH_CONTINUE;
}
static void msu_auth_catalog_drop(struct msu_auth_catalog *catalog)
{ msu_auth_drop(&catalog->root); kvfree(catalog->uids); kvfree(catalog->locators); memset(catalog,0,sizeof(*catalog)); }
static int msu_auth_catalog_read(struct msu_auth_catalog *catalog)
{
    u32 i; int error;
    memset(catalog,0,sizeof(*catalog));
    strscpy(catalog->root.path,MSU_AUTH_ROOT,sizeof(catalog->root.path));
    error = msu_kernel_stat_protected_path(MSU_AUTH_ROOT,true,&catalog->root.file,&catalog->root.stat);
    if (error) return error;
    if (__kuid_val(catalog->root.stat.uid) || (catalog->root.stat.mode & 07777) != 0700) { error = -EPERM; goto fail; }
    catalog->uids = kvmalloc_array(MSU_AUTH_MAX_DIRS,sizeof(u32),GFP_KERNEL);
    catalog->locators = kvmalloc_array(MSU_AUTH_MAX_DIRS,sizeof(u32),GFP_KERNEL);
    if (!catalog->uids || !catalog->locators) { error = -ENOMEM; goto fail; }
    catalog->context.actor = msu_su_authority_directory_actor;
    error = msu_kernel_iterate_protected_directory(MSU_AUTH_ROOT,&catalog->context);
    if (!error) error = catalog->error;
    if (!error) error = msu_auth_revalidate(&catalog->root);
    if (error) goto fail;
    sort(catalog->uids,catalog->count,sizeof(u32),msu_auth_u32_compare,NULL);
    sort(catalog->locators,catalog->locator_count,sizeof(u32),msu_auth_u32_compare,NULL);
    for (i = 1; i < catalog->count; ++i)
        if (catalog->uids[i-1] / 100000U == catalog->uids[i] / 100000U) { error = -EUCLEAN; goto fail; }
    for (i = 0; i < catalog->locator_count; ++i) {
        u32 j;
        if (i && catalog->locators[i-1] == catalog->locators[i]) { error = -EBADMSG; goto fail; }
        for (j = 0; j < catalog->count && catalog->uids[j] / 100000U != catalog->locators[i]; ++j) {}
        if (j == catalog->count) { error = -ESTALE; goto fail; }
    }
    return 0;
fail:
    msu_auth_catalog_drop(catalog); return error;
}
static int msu_auth_selected(struct msu_auth_catalog *catalog,u32 user,u32 *manager,
    struct msu_auth_document *locator,struct msu_auth_document *directory)
{
    char expected[128],path[128];
    u32 i,uid = 0; size_t length; int error;
    for (i = 0; i < catalog->count; ++i)
        if (catalog->uids[i] / 100000U == user) { uid = catalog->uids[i]; break; }
    if (!uid) return -ENODATA;
    snprintf(path,sizeof(path),MSU_AUTH_ROOT "/user-%u.authority",user);
    error = msu_auth_read(path,128,locator);
    if (error && error != -ENOENT) return error;
    if (!error) {
        length = snprintf(expected,sizeof(expected),"MapleSU authorization locator v1\n%u\n%u\n",user,uid);
        if (locator->size != length || memcmp(locator->bytes,expected,length)) return -ESTALE;
    }
    snprintf(directory->path,sizeof(directory->path),MSU_AUTH_ROOT "/%u",uid);
    error = msu_kernel_stat_protected_path(directory->path,true,&directory->file,&directory->stat);
    if (error) return error;
    if (__kuid_val(directory->stat.uid) || (directory->stat.mode & 07777) != 0700) return -EPERM;
    *manager = uid; return 0;
}
static int msu_auth_take(struct msu_auth_binary *binary,size_t size,struct msu_auth_span *span)
{
    if (size > binary->size - binary->position) return -EBADMSG;
    if (span) { span->data = binary->data + binary->position; span->size = size; }
    binary->position += size; return 0;
}
static int msu_auth_number(struct msu_auth_binary *binary,u32 bytes,u64 *value)
{
    struct msu_auth_span span; u32 i; u64 number = 0;
    if (msu_auth_take(binary,bytes,&span)) return -EBADMSG;
    for (i = 0; i < bytes; ++i) number = number << 8 | span.data[i];
    *value = number; return 0;
}
/* DataOutput.writeUTF encodes UTF-16 units using modified UTF-8. Names/hashes
 * must be ASCII; paths may contain valid paired-surrogate modified UTF-8. */
static int msu_auth_utf(struct msu_auth_binary *binary,struct msu_auth_span *text,bool ascii)
{
    u64 size; size_t at = 0; bool high = false;
    if (msu_auth_number(binary,2,&size) || msu_auth_take(binary,size,text)) return -EBADMSG;
    while (at < text->size) {
        u32 c = text->data[at++], unit;
        if (c && c < 128) unit = c;
        else if ((c & 0xe0) == 0xc0) {
            if (at == text->size || (text->data[at] & 0xc0) != 0x80) return -EBADMSG;
            unit = (c & 31) << 6 | (text->data[at++] & 63);
            if (unit && unit < 128) return -EBADMSG;
        } else if ((c & 0xf0) == 0xe0) {
            if (text->size - at < 2 || (text->data[at] & 0xc0) != 0x80 ||
                (text->data[at+1] & 0xc0) != 0x80) return -EBADMSG;
            unit = (c & 15) << 12 | (text->data[at] & 63) << 6 | (text->data[at+1] & 63); at += 2;
            if (unit < 2048) return -EBADMSG;
        } else return -EBADMSG;
        if (ascii && (!unit || unit > 127)) return -EBADMSG;
        if (high && (unit < 0xdc00 || unit > 0xdfff)) return -EBADMSG;
        if (!high && unit >= 0xdc00 && unit <= 0xdfff) return -EBADMSG;
        high = unit >= 0xd800 && unit <= 0xdbff;
    }
    return high ? -EBADMSG : 0;
}
static int msu_auth_hex(u8 c)
{ return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1; }
static int msu_auth_member_read(struct msu_auth_binary *binary,struct msu_auth_member *member)
{
    struct msu_auth_span path,signer; u64 installed,updated,count; u32 i,j; size_t k;
    memset(member,0,sizeof(*member));
    if (msu_auth_utf(binary,&member->package,true) || !member->package.size || member->package.size >= 256 ||
        msu_auth_number(binary,8,&installed) || !installed || installed > 0x7fffffffffffffffULL ||
        msu_auth_number(binary,8,&updated) || updated < installed || updated > 0x7fffffffffffffffULL ||
        msu_auth_utf(binary,&path,false) || !path.size || path.data[0] != '/' ||
        msu_auth_number(binary,4,&count) || !count || count > 32) return -EBADMSG;
    for (k = 0; k < member->package.size; ++k) {
        u8 c = member->package.data[k];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_')) return -EBADMSG;
    }
    member->installed = installed; member->signer_count = count;
    for (i = 0; i < count; ++i) {
        if (msu_auth_utf(binary,&signer,true) || signer.size != 64) return -EBADMSG;
        for (j = 0; j < 32; ++j) {
            int a = msu_auth_hex(signer.data[j*2]),b = msu_auth_hex(signer.data[j*2+1]);
            if (a < 0 || b < 0) return -EBADMSG;
            member->signers[i][j] = a << 4 | b;
        }
        for (j = 0; j < i; ++j) if (!memcmp(member->signers[j],member->signers[i],32)) return -EBADMSG;
        if (binary->version == 3 && i && memcmp(member->signers[i-1],member->signers[i],32) >= 0)
            return -EBADMSG;
    }
    return 0;
}
static int msu_auth_binary_open(struct msu_auth_document *document,struct msu_auth_binary *binary)
{
    u8 digest[32]; u64 magic,version,enabled,count;
    if (document->size < 45) return -EBADMSG;
    sha256(document->bytes,document->size-32,digest);
    if (memcmp(digest,(u8 *)document->bytes + document->size-32,32)) return -EBADMSG;
    memset(binary,0,sizeof(*binary)); binary->data = document->bytes; binary->size = document->size-32;
    if (msu_auth_number(binary,4,&magic) || magic != 0x4d535541U ||
        msu_auth_number(binary,4,&version) || (version != 1 && version != 2 && version != 3) ||
        msu_auth_number(binary,1,&enabled) || enabled > 1 ||
        msu_auth_number(binary,4,&count) || count > MSU_AUTH_MAX_GRANTS) return -EBADMSG;
    binary->version = version; binary->enabled = enabled; binary->count = count; return 0;
}

static void msu_json_space(struct msu_auth_json *json)
{ while (json->at < json->size && (json->data[json->at] == ' ' || json->data[json->at] == '\t' ||
    json->data[json->at] == '\r' || json->data[json->at] == '\n')) ++json->at; }
static bool msu_json_take(struct msu_auth_json *json,u8 character)
{
    msu_json_space(json);
    if (json->at == json->size || json->data[json->at] != character) return false;
    ++json->at; return true;
}
static int msu_json_string(struct msu_auth_json *json,char *text,size_t capacity)
{
    size_t used = 0; u32 high = 0;
    if (!msu_json_take(json,'"')) return -EBADMSG;
    while (json->at < json->size) {
        u32 c = json->data[json->at++],point = c;
        if (c == '"') {
            if (high) return -EBADMSG;
            if (text) { if (used >= capacity) return -E2BIG; text[used] = 0; }
            return 0;
        }
        if (c < 32) return -EBADMSG;
        if (c == '\\') {
            if (json->at == json->size) return -EBADMSG;
            c = json->data[json->at++];
            if (c == 'u') {
                u32 i; point = 0;
                for (i = 0; i < 4; ++i) {
                    int digit;
                    if (json->at == json->size) return -EBADMSG;
                    c = json->data[json->at++];
                    digit = c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 :
                        c >= 'A' && c <= 'F' ? c-'A'+10 : -1;
                    if (digit < 0) return -EBADMSG;
                    point = point << 4 | digit;
                }
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (high) return -EBADMSG;
                    high = point; continue;
                }
                if (point >= 0xdc00 && point <= 0xdfff) {
                    if (!high) return -EBADMSG;
                    point = 0x10000 + ((high-0xd800) << 10) + point-0xdc00; high = 0;
                } else if (high) return -EBADMSG;
            } else {
                if (high) return -EBADMSG;
                if (c == 'b') point = '\b'; else if (c == 'f') point = '\f';
                else if (c == 'n') point = '\n'; else if (c == 'r') point = '\r';
                else if (c == 't') point = '\t';
                else if (c == '"' || c == '\\' || c == '/') point = c;
                else return -EBADMSG;
            }
        } else if (c >= 128) {
            u32 need,minimum,i;
            if ((c & 0xe0) == 0xc0) { need = 1; point = c & 31; minimum = 128; }
            else if ((c & 0xf0) == 0xe0) { need = 2; point = c & 15; minimum = 2048; }
            else if ((c & 0xf8) == 0xf0) { need = 3; point = c & 7; minimum = 65536; }
            else return -EBADMSG;
            if (need > json->size-json->at) return -EBADMSG;
            for (i = 0; i < need; ++i) {
                c = json->data[json->at++]; if ((c & 0xc0) != 0x80) return -EBADMSG;
                point = point << 6 | (c & 63);
            }
            if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff) || high)
                return -EBADMSG;
        } else if (high) return -EBADMSG;
        /* Keys used by the persisted schema are ASCII. Unknown string values
         * are fully validated without copying them into a kernel stack buffer. */
        if (text) {
            if (!point || point > 127 || used + 1 >= capacity) return -EBADMSG;
            text[used] = point;
        }
        ++used;
    }
    return -EBADMSG;
}
static bool msu_json_literal(struct msu_auth_json *json,const char *literal)
{
    size_t size = strlen(literal);
    msu_json_space(json);
    if (size > json->size-json->at || memcmp(json->data + json->at,literal,size)) return false;
    json->at += size; return true;
}
static int msu_json_number(struct msu_auth_json *json,u64 *number)
{
    size_t start;
    msu_json_space(json); start = json->at;
    while (json->at < json->size && json->data[json->at] >= '0' && json->data[json->at] <= '9') ++json->at;
    if (json->at-start > 1 && json->data[start] == '0') return -EBADMSG;
    return msu_auth_decimal(json->data + start,json->at-start,number);
}
static int msu_json_bool(struct msu_auth_json *json,bool *value)
{
    if (msu_json_literal(json,"true")) { *value = true; return 0; }
    if (msu_json_literal(json,"false")) { *value = false; return 0; }
    return -EBADMSG;
}
static int msu_json_skip(struct msu_auth_json *json,u32 depth)
{
    bool object; u64 ignored;
    msu_json_space(json);
    if (!depth || json->at == json->size) return -EBADMSG;
    if (json->data[json->at] == '"') return msu_json_string(json,NULL,0);
    if (json->data[json->at] != '{' && json->data[json->at] != '[') {
        if (msu_json_literal(json,"true") || msu_json_literal(json,"false") || msu_json_literal(json,"null")) return 0;
        return msu_json_number(json,&ignored);
    }
    object = json->data[json->at++] == '{';
    if (msu_json_take(json,object ? '}' : ']')) return 0;
    for (;;) {
        if (object && (msu_json_string(json,NULL,0) || !msu_json_take(json,':'))) return -EBADMSG;
        if (msu_json_skip(json,depth-1)) return -EBADMSG;
        if (msu_json_take(json,object ? '}' : ']')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_json_uid_map(struct msu_auth_json *json,u32 wanted,u64 *revision,bool *present)
{
    char key[16]; u64 uid,value; bool selected = false;
    if (!msu_json_take(json,'{')) return -EBADMSG;
    if (msu_json_take(json,'}')) return 0;
    for (;;) {
        if (msu_json_string(json,key,sizeof(key)) || !msu_json_take(json,':') ||
            msu_auth_decimal((const u8 *)key,strlen(key),&uid) || uid > 0x7fffffffU ||
            msu_json_number(json,&value)) return -EBADMSG;
        if (uid == wanted) { if (selected) return -EBADMSG; *revision = value; selected = true; *present = true; }
        if (msu_json_take(json,'}')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_json_profile_map(struct msu_auth_json *json,u32 wanted,
    struct msu_auth_journal *journal,struct msu_auth_marker *markers,u32 capacity,u32 *count)
{
    char key[16]; u64 uid,value; u32 i;
    if (!msu_json_take(json,'{')) return -EBADMSG;
    if (msu_json_take(json,'}')) return 0;
    for (;;) {
        if (msu_json_string(json,key,sizeof(key)) || !msu_json_take(json,':') ||
            (key[0] == '0' && key[1]) || msu_auth_decimal((const u8 *)key,strlen(key),&uid) ||
            !msu_auth_uid(uid) || msu_json_number(json,&value) || !value) return -EBADMSG;
        if (uid == wanted) {
            if (journal->profile_present) return -EBADMSG;
            journal->profile_revision = value; journal->profile_present = true;
        }
        if (value > journal->max_profile_revision) journal->max_profile_revision = value;
        if (markers) {
            if (*count == capacity) return -E2BIG;
            for (i = 0; i < *count; ++i) if (markers[i].uid == uid) return -EBADMSG;
            markers[*count].uid = uid; markers[*count].revision = value; markers[*count].found = false;
            ++*count;
        }
        if (msu_json_take(json,'}')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_json_tombs(struct msu_auth_json *json,u32 wanted,u64 *revision,bool *present)
{
    char key[64];
    if (!msu_json_take(json,'[')) return -EBADMSG;
    if (msu_json_take(json,']')) return 0;
    for (;;) {
        u64 uid = 0,rev = 0,ignored; u32 fields = 0,bit;
        if (!msu_json_take(json,'{')) return -EBADMSG;
        if (msu_json_take(json,'}')) return -EBADMSG;
        for (;;) {
            if (msu_json_string(json,key,sizeof(key)) || !msu_json_take(json,':')) return -EBADMSG;
            bit = !strcmp(key,"uid") ? 1 : !strcmp(key,"rev") ? 2 :
                !strcmp(key,"packageName") ? 4 : !strcmp(key,"at") ? 8 : 0;
            if (bit && (fields & bit)) return -EBADMSG;
            fields |= bit;
            if (bit == 1) { if (msu_json_number(json,&uid) || uid > 0x7fffffffU) return -EBADMSG; }
            else if (bit == 2) { if (msu_json_number(json,&rev)) return -EBADMSG; }
            else if (bit == 4) { if (msu_json_string(json,NULL,0)) return -EBADMSG; }
            else if (bit == 8) { if (msu_json_number(json,&ignored)) return -EBADMSG; }
            else if (msu_json_skip(json,16)) return -EBADMSG;
            if (msu_json_take(json,'}')) break;
            if (!msu_json_take(json,',')) return -EBADMSG;
        }
        if (fields != 15) return -EBADMSG;
        if (uid == wanted) { *present = true; if (rev > *revision) *revision = rev; }
        if (msu_json_take(json,']')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_json_switch(struct msu_auth_json *json,u64 *revision)
{
    char key[64]; u64 version = 1; bool target; u32 fields = 0,bit;
    if (!msu_json_take(json,'{')) return -EBADMSG;
    if (msu_json_take(json,'}')) return -EBADMSG;
    for (;;) {
        if (msu_json_string(json,key,sizeof(key)) || !msu_json_take(json,':')) return -EBADMSG;
        bit = !strcmp(key,"version") ? 1 : !strcmp(key,"target") ? 2 : !strcmp(key,"rev") ? 4 : 0;
        if (bit && (fields & bit)) return -EBADMSG;
        fields |= bit;
        if (bit == 1) { if (msu_json_number(json,&version)) return -EBADMSG; }
        else if (bit == 2) { if (msu_json_bool(json,&target)) return -EBADMSG; }
        else if (bit == 4) { if (msu_json_number(json,revision)) return -EBADMSG; }
        else if (msu_json_skip(json,16)) return -EBADMSG;
        if (msu_json_take(json,'}')) break;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
    return version == 1 && (fields & 6) == 6 && *revision ? 0 : -EBADMSG;
}
static int msu_json_metadata(struct msu_auth_json *json,bool unresolved)
{
    char key[64];
    if (!msu_json_take(json,'[')) return -EBADMSG;
    if (msu_json_take(json,']')) return 0;
    for (;;) {
        u32 fields = 0,bit; u64 number; bool boolean;
        if (!msu_json_take(json,'{') || msu_json_take(json,'}')) return -EBADMSG;
        for (;;) {
            if (msu_json_string(json,key,sizeof(key)) || !msu_json_take(json,':')) return -EBADMSG;
            if (unresolved) bit = !strcmp(key,"source") ? 1 : !strcmp(key,"uid") ? 2 :
                !strcmp(key,"packageName") ? 4 : !strcmp(key,"reason") ? 8 : !strcmp(key,"at") ? 16 : 0;
            else bit = !strcmp(key,"backend") ? 1 : !strcmp(key,"rev") ? 2 :
                !strcmp(key,"at") ? 4 : !strcmp(key,"ok") ? 8 : !strcmp(key,"detail") ? 16 : 0;
            if (bit && (fields & bit)) return -EBADMSG;
            fields |= bit;
            if (unresolved && (bit == 2 || bit == 4) && msu_json_literal(json,"null")) {}
            else if ((unresolved && (bit == 1 || bit == 4 || bit == 8)) ||
                (!unresolved && (bit == 1 || bit == 16))) {
                if (msu_json_string(json,NULL,0)) return -EBADMSG;
            } else if (!unresolved && bit == 8) { if (msu_json_bool(json,&boolean)) return -EBADMSG; }
            else if (bit) { if (msu_json_number(json,&number) || (unresolved && bit == 2 && number > 0x7fffffffU)) return -EBADMSG; }
            else if (msu_json_skip(json,16)) return -EBADMSG;
            if (msu_json_take(json,'}')) break;
            if (!msu_json_take(json,',')) return -EBADMSG;
        }
        if ((fields & (unresolved ? 31U : 15U)) != (unresolved ? 31U : 15U)) return -EBADMSG;
        if (msu_json_take(json,']')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_json_migrations(struct msu_auth_json *json)
{
    u64 value;
    if (!msu_json_take(json,'{')) return -EBADMSG;
    if (msu_json_take(json,'}')) return 0;
    for (;;) {
        if (msu_json_string(json,NULL,0) || !msu_json_take(json,':') || msu_json_number(json,&value)) return -EBADMSG;
        if (msu_json_take(json,'}')) return 0;
        if (!msu_json_take(json,',')) return -EBADMSG;
    }
}
static int msu_auth_journal_decode(const struct msu_auth_document *document,u32 uid,
    struct msu_auth_journal *journal,struct msu_auth_marker *markers,u32 capacity,u32 *count)
{
    struct msu_auth_json json = {document->bytes,document->size,0};
    u64 schema = 1,pending_apply = 0,switch_revision = 0; u32 fields = 0,bit; char key[64];
    bool pending_present = false;
    memset(journal,0,sizeof(*journal));
    if (count) *count = 0;
    if (!document->file) return 0;
    if (!msu_json_take(&json,'{')) return -EBADMSG;
    if (!msu_json_take(&json,'}')) for (;;) {
        if (msu_json_string(&json,key,sizeof(key)) || !msu_json_take(&json,':')) return -EBADMSG;
        bit = !strcmp(key,"schema") ? 1 : !strcmp(key,"rev") ? 2 : !strcmp(key,"uidRev") ? 4 :
            !strcmp(key,"tombs") ? 8 : !strcmp(key,"pendingSwitch") ? 16 : !strcmp(key,"pendingApplyRev") ? 32 :
            !strcmp(key,"applied") ? 64 : !strcmp(key,"migrated") ? 128 : !strcmp(key,"unresolved") ? 256 :
            !strcmp(key,"profileRev") ? 512 : 0;
        if (bit && (fields & bit)) return -EBADMSG;
        fields |= bit;
        if (bit == 1) { if (msu_json_number(&json,&schema)) return -EBADMSG; }
        else if (bit == 2) { if (msu_json_number(&json,&journal->revision)) return -EBADMSG; }
        else if (bit == 4) { if (msu_json_uid_map(&json,uid,&journal->grant_revision,&journal->decision_present)) return -EBADMSG; }
        else if (bit == 8) { if (msu_json_tombs(&json,uid,&journal->tomb_revision,&journal->decision_present)) return -EBADMSG; }
        else if (bit == 16) {
            if (!msu_json_literal(&json,"null")) {
                if (msu_json_switch(&json,&switch_revision)) return -EBADMSG;
                journal->switch_pending = true;
            }
        } else if (bit == 32) {
            if (!msu_json_literal(&json,"null")) {
                if (msu_json_number(&json,&pending_apply)) return -EBADMSG;
                pending_present = true;
            }
        } else if (bit == 64) { if (msu_json_metadata(&json,false)) return -EBADMSG; }
        else if (bit == 128) { if (msu_json_migrations(&json)) return -EBADMSG; }
        else if (bit == 256) { if (msu_json_metadata(&json,true)) return -EBADMSG; }
        else if (bit == 512) {
            if (msu_json_profile_map(&json,uid,journal,markers,capacity,count)) return -EBADMSG;
        }
        else if (msu_json_skip(&json,16)) return -EBADMSG;
        if (msu_json_take(&json,'}')) break;
        if (!msu_json_take(&json,',')) return -EBADMSG;
    }
    msu_json_space(&json);
    if (json.at != json.size || schema != 1 || journal->max_profile_revision > journal->revision ||
        (pending_present && (!pending_apply || pending_apply > journal->revision)) ||
        (journal->switch_pending && (switch_revision != journal->revision || pending_apply != switch_revision)))
        return -EBADMSG;
    return 0;
}
static int msu_auth_journal_read(const struct msu_auth_document *document,u32 uid,
    struct msu_auth_journal *journal)
{ return msu_auth_journal_decode(document,uid,journal,NULL,0,NULL); }

static int msu_auth_profile_text(struct msu_auth_binary *binary,char *output,size_t capacity)
{
    struct msu_auth_span text; size_t at = 0,used = 0; u32 high = 0;
    if (msu_auth_utf(binary,&text,false)) return -EBADMSG;
    while (at < text.size) {
        u32 c = text.data[at++],point = c,n,i; u8 encoded[4];
        if (c >= 128 && (c & 0xe0) == 0xc0) { point = (c & 31) << 6 | (text.data[at] & 63); ++at; }
        else if (c >= 128) { point = (c & 15) << 12 | (text.data[at] & 63) << 6 | (text.data[at+1] & 63); at += 2; }
        if (!point) return -EBADMSG;
        if (point >= 0xd800 && point <= 0xdbff) { high = point; continue; }
        if (high) { point = 0x10000 + ((high - 0xd800) << 10) + point - 0xdc00; high = 0; }
        if (point < 128) { n = 1; encoded[0] = point; }
        else if (point < 2048) { n = 2; encoded[0] = 0xc0 | (point >> 6); encoded[1] = 0x80 | (point & 63); }
        else if (point < 65536) { n = 3; encoded[0] = 0xe0 | (point >> 12); encoded[1] = 0x80 | ((point >> 6) & 63); encoded[2] = 0x80 | (point & 63); }
        else { n = 4; encoded[0] = 0xf0 | (point >> 18); encoded[1] = 0x80 | ((point >> 12) & 63); encoded[2] = 0x80 | ((point >> 6) & 63); encoded[3] = 0x80 | (point & 63); }
        if (n >= capacity - used) return -EBADMSG;
        for (i = 0; i < n; ++i) output[used++] = encoded[i];
    }
    output[used] = 0; return 0;
}
static int msu_auth_profile_bool(struct msu_auth_binary *binary,bool *output)
{
    u64 value; if (msu_auth_number(binary,1,&value) || value > 1) return -EBADMSG;
    *output = value; return 0;
}
static int msu_auth_profile_read(struct msu_auth_binary *binary,struct msu_su_profile *profile)
{
    u64 value,count,mask = 0; u32 i;
    memset(profile,0,sizeof(*profile));
    if (msu_auth_number(binary,4,&value) || value != 1 ||
        msu_auth_profile_text(binary,profile->name,sizeof(profile->name)) || !profile->name[0] ||
        msu_auth_profile_bool(binary,&profile->allow_su) ||
        msu_auth_profile_bool(binary,&profile->use_default) ||
        msu_auth_profile_bool(binary,&profile->template_present)) return -EBADMSG;
    if (profile->template_present && msu_auth_profile_text(binary,profile->template_name,
        sizeof(profile->template_name))) return -EBADMSG;
    if (msu_auth_number(binary,4,&value) || value > 0x7fffffffU) return -EBADMSG;
    profile->uid = value;
    if (msu_auth_number(binary,4,&value) || value > 0x7fffffffU) return -EBADMSG;
    profile->gid = value;
    if (msu_auth_number(binary,4,&count) || count > MSU_SU_PROFILE_GROUPS) return -EBADMSG;
    profile->groups_count = count;
    for (i = 0; i < count; ++i) {
        if (msu_auth_number(binary,4,&value) || value > 0x7fffffffU) return -EBADMSG;
        profile->groups[i] = value;
    }
    if (msu_auth_number(binary,4,&count) || count > 64) return -EBADMSG;
    for (i = 0; i < count; ++i) {
        if (msu_auth_number(binary,4,&value) || value > 63 || (mask & (1ULL << value))) return -EBADMSG;
        mask |= 1ULL << value;
    }
    profile->effective = mask;
    if (msu_auth_profile_text(binary,profile->selinux_domain,sizeof(profile->selinux_domain)) ||
        msu_auth_number(binary,4,&value) || value > 2) return -EBADMSG;
    profile->namespace_mode = value;
    if (msu_auth_profile_bool(binary,&profile->non_root_use_default) ||
        msu_auth_profile_bool(binary,&profile->umount_modules) ||
        msu_auth_number(binary,8,&value) || (value & ~1ULL)) return -EBADMSG;
    profile->flags = value; profile->non_root = !profile->allow_su;
    profile->explicit_profile = true;
    return 0;
}
static int msu_auth_identity_read(struct msu_auth_binary *binary,struct msu_auth_member *member,
    struct msu_auth_span *names,const struct msu_su_verified_install *installation,bool verify,
    struct msu_auth_identity *identity)
{
    u64 uid,count = 1; u32 j,k; size_t start = binary->position;
    if (msu_auth_number(binary,4,&uid) || !msu_auth_uid(uid) ||
        (binary->version >= 2 && msu_auth_number(binary,4,&count)) || !count || count > 1024)
        return -EBADMSG;
    if (installation && installation->full_uid == uid && count != installation->member_count)
        return -ESTALE;
    for (j = 0; j < count; ++j) {
        int error = msu_auth_member_read(binary,member);
        if (error) return error;
        for (k = 0; k < j; ++k)
            if (names[k].size == member->package.size &&
                !memcmp(names[k].data,member->package.data,member->package.size)) return -EBADMSG;
        if (binary->version == 3 && j) {
            size_t common = min(names[j-1].size,member->package.size);
            int order = memcmp(names[j-1].data,member->package.data,common);
            if (order > 0 || (!order && names[j-1].size >= member->package.size)) return -EBADMSG;
        }
        names[j] = member->package;
        if (installation && installation->full_uid == uid && verify) {
            char package[256];
            memcpy(package,member->package.data,member->package.size); package[member->package.size] = 0;
            for (k = 0; k < installation->member_count; ++k)
                if (!strcmp(package,installation->members[k].package)) break;
            if (k == installation->member_count) return -ESTALE;
            error = msu_su_observed_match_saved_member(installation,package,
                member->installed,member->signers,member->signer_count);
            if (error) return error;
        }
    }
    identity->uid = uid; identity->member_count = count;
    identity->bytes.data = binary->data + start; identity->bytes.size = binary->position - start;
    return 0;
}
static int msu_auth_add_uid(u32 *uids,u32 capacity,u32 *used,u32 uid)
{
    u32 i;
    if (!uids) return 0;
    for (i = 0; i < *used; ++i) if (uids[i] == uid) return 0;
    if (*used == capacity) return -ENOSPC;
    uids[(*used)++] = uid; return 0;
}
static int msu_auth_binary_scan(struct msu_auth_document *document,
    struct msu_auth_document *journal_document,u32 wanted,
    const struct msu_su_verified_install *installation,
    u32 *uids,u32 capacity,u32 *count,struct msu_su_saved_grant *grant)
{
    struct msu_auth_binary binary; struct msu_auth_member *member;
    struct msu_auth_span *names; struct msu_auth_identity *grants;
    struct msu_auth_marker *markers; struct msu_su_profile *profile;
    u32 *profile_uids = NULL; u32 i,j,used = 0,marker_count = 0,marker_capacity; u64 profile_count = 0;
    struct msu_su_saved_grant *selected; bool found = false;
    int error = msu_auth_binary_open(document,&binary);
    if (error) return error;
    grants = kvmalloc_array(binary.count ? binary.count : 1,sizeof(*grants),GFP_KERNEL);
    marker_capacity = min(MSU_AUTH_MAX_GRANTS,(u32)(journal_document->size / 4 + 1));
    markers = kvmalloc_array(marker_capacity,sizeof(*markers),GFP_KERNEL);
    names = kvmalloc_array(1024,sizeof(*names),GFP_KERNEL);
    member = kmalloc(sizeof(*member),GFP_KERNEL);
    profile = kmalloc(sizeof(*profile),GFP_KERNEL);
    selected = kzalloc(sizeof(*selected),GFP_KERNEL);
    if (!grants || !markers || !names || !member || !profile || !selected) { error = -ENOMEM; goto out; }
    /* Validate the complete journal even an empty/disabled binary cannot grant.
     * Relevant decision watermarks are selected separately for each full UID. */
    { struct msu_auth_journal journal;
      error = msu_auth_journal_decode(journal_document,~0U,&journal,markers,marker_capacity,&marker_count);
      if (error) goto out;
    }
    for (i = 0; i < binary.count; ++i) {
        struct msu_auth_journal journal; struct msu_auth_binary preview = binary; u64 uid;
        bool allowed;
        if (msu_auth_number(&preview,4,&uid)) { error = -EBADMSG; goto out; }
        error = msu_auth_journal_read(journal_document,uid,&journal);
        if (error) goto out;
        allowed = binary.enabled && !journal.switch_pending && journal.tomb_revision <= journal.grant_revision;
        error = msu_auth_identity_read(&binary,member,names,installation,allowed,&grants[i]);
        if (error) goto out;
        for (j = 0; j < i; ++j) if (grants[j].uid == uid) { error = -EBADMSG; goto out; }
        if (allowed) { error = msu_auth_add_uid(uids,capacity,&used,uid); if (error) goto out; }
        if (wanted != ~0U && wanted == uid) {
            found = true; selected->full_uid = uid; selected->decision = allowed;
            selected->profile.use_default = true;
            selected->profile.allow_su = true;
            if (installation) memcpy(selected->installation_id,installation->installation_id,sizeof(selected->installation_id));
        }
    }
    if (binary.version == 3) {
        if (msu_auth_number(&binary,4,&profile_count) || !profile_count || profile_count > MSU_AUTH_MAX_GRANTS) { error = -EBADMSG; goto out; }
        profile_uids = kvmalloc_array(profile_count ? profile_count : 1,sizeof(*profile_uids),GFP_KERNEL);
        if (!profile_uids) { error = -ENOMEM; goto out; }
        for (i = 0; i < profile_count; ++i) {
            struct msu_auth_identity identity; struct msu_auth_journal journal; bool has_grant = false;
            error = msu_auth_identity_read(&binary,member,names,installation,true,&identity);
            if (error) goto out;
            for (j = 0; j < i; ++j) if (profile_uids[j] == identity.uid) { error = -EBADMSG; goto out; }
            profile_uids[i] = identity.uid;
            error = msu_auth_profile_read(&binary,profile);
            if (error) goto out;
            for (j = 0; j < identity.member_count; ++j)
                if (names[j].size == strlen(profile->name) && !memcmp(names[j].data,profile->name,names[j].size)) break;
            if (j == identity.member_count) { error = -EBADMSG; goto out; }
            for (j = 0; j < binary.count; ++j) if (grants[j].uid == identity.uid) {
                if (!profile->allow_su || grants[j].bytes.size != identity.bytes.size ||
                    memcmp(grants[j].bytes.data,identity.bytes.data,identity.bytes.size)) { error = -EBADMSG; goto out; }
                has_grant = true; break;
            }
            if (profile->allow_su != has_grant) { error = -EBADMSG; goto out; }
            error = msu_auth_journal_read(journal_document,identity.uid,&journal);
            if (error) goto out;
            if (!journal.profile_present) { error = -EBADMSG; goto out; }
            for (j = 0; j < marker_count; ++j) if (markers[j].uid == identity.uid) markers[j].found = true;
            error = msu_auth_add_uid(uids,capacity,&used,identity.uid);
            if (error) goto out;
            if (wanted == identity.uid) {
                found = true; selected->full_uid = identity.uid;
                selected->decision = profile->allow_su && binary.enabled && !journal.switch_pending &&
                    journal.tomb_revision <= journal.grant_revision;
                selected->profile = *profile;
                if (installation) memcpy(selected->installation_id,installation->installation_id,sizeof(selected->installation_id));
            }
        }
    }
    for (i = 0; i < marker_count; ++i) if (!markers[i].found) { error = -EBADMSG; goto out; }
    if (binary.position != binary.size) { error = -EBADMSG; goto out; }
    if (wanted != ~0U && !found) { error = -ENOENT; goto out; }
    if (uids) { sort(uids,used,sizeof(*uids),msu_auth_u32_compare,NULL); *count = used; }
    if (grant) *grant = *selected;
    error = 0;
out:
    kvfree(grants); kvfree(markers); kvfree(profile_uids); kvfree(names);
    kfree(member); kfree(profile); kfree(selected); return error;
}
static int msu_auth_catalog_unchanged(const struct msu_auth_catalog *catalog)
{
    struct msu_auth_catalog after; int error = msu_auth_revalidate(&catalog->root);
    if (error) return error;
    error = msu_auth_catalog_read(&after);
    if (error) return error;
    if (catalog->count != after.count || catalog->locator_count != after.locator_count ||
        memcmp(catalog->uids,after.uids,catalog->count * sizeof(u32)) ||
        memcmp(catalog->locators,after.locators,catalog->locator_count * sizeof(u32))) error = -EAGAIN;
    msu_auth_catalog_drop(&after); return error;
}
static int msu_auth_one_store(struct msu_auth_catalog *catalog,u32 manager,u32 wanted,
    const struct msu_su_verified_install *installation,u32 *uids,u32 capacity,u32 *count,
    struct msu_su_saved_grant *grant)
{
    struct msu_auth_document *documents,*locator,*directory,*binary,*journal;
    struct msu_su_saved_grant selected = {0}; struct msu_auth_journal state;
    char path[128]; bool found = false; int error;
    documents = kcalloc(4,sizeof(*documents),GFP_KERNEL);
    if (!documents) return -ENOMEM;
    locator = documents; directory = documents + 1; binary = documents + 2; journal = documents + 3;
    error = msu_auth_selected(catalog,manager / 100000U,&manager,locator,directory);
    if (error) goto out;
    snprintf(path,sizeof(path),MSU_AUTH_ROOT "/%u/authorizations.bin",manager);
    error = msu_auth_read(path,MSU_AUTH_MAX_BYTES,binary);
    if (error && error != -ENOENT) goto out;
    snprintf(path,sizeof(path),MSU_AUTH_ROOT "/%u/superuser-journal.json",manager);
    error = msu_auth_read(path,512U*1024U,journal);
    if (error && error != -ENOENT) goto out;
    error = msu_auth_journal_read(journal,wanted,&state);
    if (error) goto out;
    if (!binary->file && state.max_profile_revision) { error = -EBADMSG; goto out; }
    if (binary->file) {
        error = msu_auth_binary_scan(binary,journal,wanted,installation,uids,capacity,count,&selected);
        if (error && error != -ENOENT) goto out;
        if (!error && wanted != ~0U) found = true;
    } else if (uids) *count = 0;
    if (wanted != ~0U && !found && state.decision_present) {
        /* The existing journal's newer denial remains authority even after a
         * partial/failed binary update removed its old row. */
        selected.full_uid = wanted;
        if (installation) memcpy(selected.installation_id,installation->installation_id,sizeof(selected.installation_id));
        found = true;
    }
    error = msu_auth_revalidate(locator);
    if (!error) error = msu_auth_revalidate(binary);
    if (!error) error = msu_auth_revalidate(journal);
    if (!error) error = msu_auth_revalidate(directory);
    if (!error && wanted != ~0U) { if (!found) error = -ENOENT; else *grant = selected; }
out:
    msu_auth_drop(locator); msu_auth_drop(directory); msu_auth_drop(binary); msu_auth_drop(journal);
    kfree(documents); return error;
}
static int msu_auth_modern_read(const struct msu_su_verified_install *installation,
    u32 *uids,u32 capacity,u32 *count,struct msu_su_saved_grant *grant)
{
    struct msu_auth_catalog catalog; struct msu_su_saved_grant *scratch,*selected,*candidate;
    u32 store,used = 0,claims = 0,i; int error = msu_auth_catalog_read(&catalog);
    if (error == -ENOENT) return -ENODATA;
    if (error) return error;
    scratch = kcalloc(2,sizeof(*scratch),GFP_KERNEL);
    if (!scratch) { msu_auth_catalog_drop(&catalog); return -ENOMEM; }
    selected = scratch; candidate = scratch + 1;
    for (store = 0; store < catalog.count; ++store) {
        u32 added = 0;
        error = msu_auth_one_store(&catalog,catalog.uids[store],installation ? installation->full_uid : ~0U,
            installation,uids ? uids + used : NULL,capacity-used,&added,candidate);
        if (error == -ENOENT && installation) continue;
        if (error) goto out;
        if (installation) {
            if (++claims != 1) { error = -EUCLEAN; goto out; }
            *selected = *candidate;
        } else used += added;
    }
    if (uids) {
        sort(uids,used,sizeof(*uids),msu_auth_u32_compare,NULL);
        for (i = 1; i < used; ++i) if (uids[i-1] == uids[i]) { error = -EUCLEAN; goto out; }
        /* A second store's explicit denial must not be lost by unioning only
         * enabled grants. Resolve each proposed UID against every real store. */
        for (i = 0; i < used; ++i) {
            u32 owners = 0;
            for (store = 0; store < catalog.count; ++store) {
                error = msu_auth_one_store(&catalog,catalog.uids[store],uids[i],NULL,NULL,0,NULL,candidate);
                if (error == -ENOENT) continue;
                if (error) goto out;
                if (++owners > 1) { error = -EUCLEAN; goto out; }
            }
        }
    }
    error = msu_auth_catalog_unchanged(&catalog);
    if (!error) {
        if (installation) { if (!claims) error = -ENOENT; else *grant = *selected; }
        else *count = used;
    }
out:
    kfree(scratch); msu_auth_catalog_drop(&catalog); return error;
}
int msu_su_modern_authority_list(u32 *uids,u32 capacity,u32 *count)
{
    u32 *candidate,used; int error;
    if (!uids || !count || capacity > MSU_SU_REGISTRY_MAX_UIDS) return -EINVAL;
    candidate = kvmalloc_array(capacity ? capacity : 1,sizeof(*candidate),GFP_KERNEL);
    if (!candidate) return -ENOMEM;
    error = msu_auth_modern_read(NULL,candidate,capacity,&used,NULL);
    if (!error) { memcpy(uids,candidate,used*sizeof(*uids)); *count = used; }
    kvfree(candidate); return error;
}
int msu_su_modern_authority_grant(const struct msu_su_verified_install *installation,
    struct msu_su_saved_grant *grant)
{
    struct msu_su_saved_grant candidate; int error;
    if (!installation || !installation->pin || !installation->members ||
        !installation->member_count || !grant) return -EINVAL;
    error = msu_auth_modern_read(installation,NULL,0,NULL,&candidate);
    if (!error) *grant = candidate;
    return error;
}
