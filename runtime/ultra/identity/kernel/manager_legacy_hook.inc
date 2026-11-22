/* SPDX-License-Identifier: GPL-3.0-only */
/* Included after the management helpers. Legacy EXEC uses the same resource,
 * shared-value and publication tables as the Owner transport. */
#include "manager_dynamic_layout.h"
#if (defined(MSU_MANAGEMENT_NATIVE_TEXT_OWNER) && MSU_MANAGEMENT_NATIVE_TEXT_OWNER) || \
    (defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER)

static bool msu_legacy_hook_gateway_caller(const struct msu_legacy_gateway *gateway,
    unsigned long caller)
{
    return gateway && gateway->id && caller >= gateway->base &&
        caller - gateway->base < gateway->bytes;
}

static noinline u64 __nocfi msu_legacy_hook_bind(u64 base, u64 bytes)
{
    unsigned long caller = (unsigned long)__builtin_return_address(0), flags;
    struct msu_legacy_gateway *gateway = NULL;
    u32 word;
    unsigned int i;
    if (!msu_management_sleepable() || !READ_ONCE(management.ready) ||
        base < 0xffff000000000000ULL || (base & 3) || bytes < 4 || (bytes & 3) || bytes > PAGE_SIZE ||
        bytes > ~0ULL - base || caller < base || caller - base >= bytes ||
        copy_from_kernel_nofault(&word, (const void *)(unsigned long)base, sizeof(word)) ||
        copy_from_kernel_nofault(&word, (const void *)(unsigned long)(base + bytes - 4), sizeof(word)))
        return 0;
    raw_spin_lock_irqsave(&msu_management_lock, flags);
    for (i = 0; i < MSU_MANAGEMENT_SLOTS; ++i) {
        struct msu_legacy_gateway *value = &management.legacy_gateways[i];
        if (value->id && value->base == base && value->bytes == bytes) {
            gateway = value;
            break;
        }
        if (!value->id && !gateway) gateway = value;
    }
    if (management.ready && gateway && !gateway->id) {
        gateway->base = base;
        gateway->bytes = bytes;
        gateway->id = (gateway - management.legacy_gateways) + 1;
    }
    raw_spin_unlock_irqrestore(&msu_management_lock, flags);
    return gateway ? gateway->id : 0;
}

static noinline u64 __nocfi msu_legacy_hook_begin(u64 gateway_id)
{
    struct msu_management_session *session;
    struct msu_legacy_gateway *gateway;
    const struct cred *old;
    unsigned long flags, caller = (unsigned long)__builtin_return_address(0);
    unsigned int slot;
    u64 id = 0;
    if (!msu_runtime_layout_ready() || !msu_management_sleepable() || !READ_ONCE(management.ready) ||
        !gateway_id || gateway_id > MSU_MANAGEMENT_SLOTS || !MSU_DYN_FIELD(current, task_struct, mm) ||
        (MSU_DYN_FIELD(current, task_struct, flags) & PF_EXITING) || msu_dynamic_current_cred() != msu_dynamic_current_real_cred()) return 0;
    gateway = &management.legacy_gateways[gateway_id - 1];
    if (!msu_legacy_hook_gateway_caller(gateway, caller)) return 0;
    session = msu_management_get(0);
    if (session) {
        mutex_lock(&session->operation);
        if (session->legacy_gateway == gateway && !session->legacy_active &&
            session->attached && msu_management_task_matches(session)) {
            /* Raw legacy packets can create a fresh private cred. Rebind only
             * at this authenticated producer boundary; typed packets retain
             * their current object without preparing reply credentials. */
            old = session->active;
            session->active = msu_dynamic_get_current_cred();
            msu_dynamic_put_cred(old);
            session->legacy_active = true;
            id = session->id;
        }
        mutex_unlock(&session->operation);
        msu_management_put(session);
        return id;
    }
    raw_spin_lock_irqsave(&msu_management_lock, flags);
    if (!management.ready || management.live_sessions == MSU_MANAGEMENT_SLOTS ||
        !management.next_session) {
        raw_spin_unlock_irqrestore(&msu_management_lock, flags);
        return 0;
    }
    ++management.live_sessions;
    raw_spin_unlock_irqrestore(&msu_management_lock, flags);
    session = kzalloc(sizeof(*session), GFP_KERNEL);
    if (!session) goto unreserve;
    mutex_init(&session->operation);
    INIT_WORK(&session->cleanup, msu_management_cleanup);
    session->task = current;
    msu_dynamic_get_task_struct(current);
    session->mm = MSU_DYN_FIELD(current, task_struct, mm);
    msu_dynamic_mmgrab(session->mm);
    session->original = msu_dynamic_get_current_cred();
    session->active = msu_dynamic_get_cred(session->original);
    session->exec_id = MSU_DYN_FIELD(current, task_struct, self_exec_id);
    session->principal_uid = __kuid_val(msu_dynamic_current_uid());
    session->epoch = 1; /* Legacy provenance, never an Owner authorization. */
    session->legacy_gateway = gateway;
    session->legacy_active = true;
    session->references = 1; /* The table owns the idle, cross-EXEC session. */
    raw_spin_lock_irqsave(&msu_management_lock, flags);
    for (slot = 0; slot < MSU_MANAGEMENT_SLOTS; ++slot)
        if (!management.sessions[slot]) break;
    if (!management.ready || slot == MSU_MANAGEMENT_SLOTS || !management.next_session) {
        raw_spin_unlock_irqrestore(&msu_management_lock, flags);
        msu_dynamic_put_cred(session->active); msu_dynamic_put_cred(session->original);
        msu_dynamic_mmdrop(session->mm); msu_dynamic_put_task_struct(session->task); kfree(session);
        goto unreserve;
    }
    id = session->id = management.next_session++;
    session->attached = true;
    management.sessions[slot] = session;
    raw_spin_unlock_irqrestore(&msu_management_lock, flags);
    return id;
unreserve:
    raw_spin_lock_irqsave(&msu_management_lock, flags);
    --management.live_sessions;
    raw_spin_unlock_irqrestore(&msu_management_lock, flags);
    return 0;
}

static noinline int __nocfi msu_legacy_hook_end(u64 scope)
{
    struct msu_management_session *session;
    int error = -ESTALE;
    if (!msu_management_sleepable() || !scope) return -EINVAL;
    session = msu_management_get(scope);
    /* The producer ends only the scope returned by BEGIN. CLOSE can already
     * have detached it inside the JIT; this idempotent end is not a resource
     * release receipt. The command response carries that result. */
    if (!session) return 0;
    mutex_lock(&session->operation);
    if (session->legacy_gateway && session->legacy_active &&
        msu_management_task_matches(session)) {
        session->legacy_active = false;
        if (!session->legacy_opened) msu_management_retire(session);
        error = 0;
    }
    mutex_unlock(&session->operation);
    msu_management_put(session);
    return error;
}

static int __nocfi msu_legacy_hook_dispatch(u64 scope, u32 command,
    const maplesu_management_v3 *operation, maplesu_response_owner_v3 *response)
{
    struct msu_management_session *session;
    struct msu_management_resource *resource;
    struct msu_publication *publication;
    struct msu_shared_bool *shared;
    unsigned long flags;
    int error = -EINVAL, post_error;
    bool closing = command == MAPLESU_REQUEST_SESSION_CLOSE;
    if (!response) return -EINVAL;
    memset(response, 0, sizeof(*response));
    response->version = MAPLESU_OWNER_PROTOCOL_VERSION;
    response->length = sizeof(*response);
    response->command = command;
    response->status = -EINVAL;
    if (!msu_management_sleepable()) { error = -EWOULDBLOCK; goto finish; }
    if (!operation || !READ_ONCE(management.ready) ||
        !msu_management_host_matches(operation->host) ||
        !msu_management_shape(command, operation) ||
        (command == MAPLESU_REQUEST_WRITE && operation->flags)) goto finish;
    session = msu_management_get(scope);
    if (!session) { error = -ESTALE; goto finish; }
    mutex_lock(&session->operation);
    if (!session->legacy_gateway ||
        (!session->legacy_active && !(closing && scope == session->id)) ||
        (scope && scope != session->id) ||
        (!closing && command != MAPLESU_REQUEST_SESSION_OPEN && operation->session != session->id)) {
        error = -EPERM;
        goto unlock;
    }
    if (closing) {
        /* Only this task's exact producer scope may clean up after END when
         * delivery fails. Closing grants no new operation or Owner authority. */
        if (!msu_management_task_matches(session)) {
            msu_management_retire(session);
            error = -ESTALE;
            goto unlock;
        }
        msu_management_retire(session);
        error = msu_management_release_all(session, &response->metadata_length);
        response->metadata_length |= MAPLESU_EFFECT_SESSION_CLOSED;
        goto unlock;
    }
    error = msu_management_check(session);
    if (error) goto unlock;
    switch (command) {
    case MAPLESU_REQUEST_SESSION_OPEN:
        session->legacy_opened = true;
        management.ever_opened = true;
        response->result = session->id;
        break;
    case MAPLESU_REQUEST_ALLOC:
        error = msu_management_alloc(session, operation, response);
        break;
    case MAPLESU_REQUEST_EXEC:
        error = msu_management_exec(session, operation, response);
        break;
    case MAPLESU_REQUEST_WRITE:
        error = msu_management_write(session, operation, response);
        break;
    case MAPLESU_REQUEST_RELEASE:
        resource = msu_management_resource(session, operation->handle);
        error = !resource ? -ESTALE : resource->publication ? -EBUSY :
            msu_management_release(resource, &response->metadata_length);
        break;
    case MAPLESU_REQUEST_CRED_ROOT:
    case MAPLESU_REQUEST_CRED_CAPS:
        error = msu_management_credentials(session, operation,
            command == MAPLESU_REQUEST_CRED_ROOT, response);
        break;
    case MAPLESU_REQUEST_CRED_PROCATTR:
        error = msu_management_procattr(session, operation, response);
        break;
    case MAPLESU_REQUEST_TASK_STATE:
#if defined(MSU_MANAGEMENT_TASK_STATE_VERIFIED) && MSU_MANAGEMENT_TASK_STATE_VERIFIED
        error = msu_task_state_release_current(msu_management_validate_credentials,
            session, &response->metadata_length, &response->result);
#else
        error = -EOPNOTSUPP;
#endif
        break;
    case MAPLESU_REQUEST_PUBLICATION_PREPARE:
        error = msu_publication_prepare(session, operation, response);
        break;
    case MAPLESU_REQUEST_PUBLICATION_PUBLISH:
    case MAPLESU_REQUEST_PUBLICATION_DISABLE:
    case MAPLESU_REQUEST_PUBLICATION_RETIRE:
        response->metadata_address = operation->handle;
        raw_spin_lock_irqsave(&msu_management_lock, flags);
        publication = msu_publication_find(operation->handle);
        raw_spin_unlock_irqrestore(&msu_management_lock, flags);
        if (!publication) { error = -ESTALE; break; }
        mutex_lock(&publication->operation);
        if (publication->id != operation->handle || !publication->legacy ||
            (!publication->ever_exposed && !publication->canceled && publication->session != session))
            error = -ESTALE;
        else if (command == MAPLESU_REQUEST_PUBLICATION_PUBLISH)
            error = msu_publication_publish(session, publication, response);
        else if (command == MAPLESU_REQUEST_PUBLICATION_DISABLE)
            error = msu_publication_disable(publication, session, response);
        else error = msu_publication_retire(publication, session, response);
        mutex_unlock(&publication->operation);
        break;
    case MAPLESU_REQUEST_SHARED_BOOL_CREATE:
        error = msu_shared_bool_create(session, operation, response);
        break;
    case MAPLESU_REQUEST_SHARED_BOOL_STORE:
    case MAPLESU_REQUEST_SHARED_BOOL_RELEASE:
        response->metadata_address = operation->handle;
        error = msu_shared_bool_update(session, operation,
            command == MAPLESU_REQUEST_SHARED_BOOL_RELEASE, response);
        break;
    default:
        error = -EOPNOTSUPP;
    }
    post_error = msu_management_check(session);
    if (!error) error = post_error;
    if (error && command == MAPLESU_REQUEST_SHARED_BOOL_CREATE && response->metadata_address) {
        raw_spin_lock_irqsave(&msu_management_lock, flags);
        shared = msu_shared_bool_find(response->metadata_address);
        raw_spin_unlock_irqrestore(&msu_management_lock, flags);
        if (shared) {
            mutex_lock(&shared->operation);
            (void)msu_shared_bool_drop_creator(shared, session, &response->metadata_length);
            mutex_unlock(&shared->operation);
        }
        response->result = response->metadata_address = 0;
    }
    if (error && command == MAPLESU_REQUEST_PUBLICATION_PREPARE &&
        (response->metadata_length & MAPLESU_EFFECT_PUBLICATION_PREPARED)) {
        raw_spin_lock_irqsave(&msu_management_lock, flags);
        publication = msu_publication_find(response->result);
        raw_spin_unlock_irqrestore(&msu_management_lock, flags);
        if (publication) {
            mutex_lock(&publication->operation);
            if (publication->id == response->result && publication->session == session &&
                !publication->ever_exposed)
                (void)msu_publication_release_unexposed(publication, &response->metadata_length);
            mutex_unlock(&publication->operation);
        }
        response->result = response->metadata_address = 0;
    }
    if (error && command == MAPLESU_REQUEST_ALLOC) {
        response->result = response->metadata_address = 0;
        if (post_error) (void)msu_management_release_all(session, &response->metadata_length);
    }
unlock:
    if (!READ_ONCE(session->attached)) response->metadata_length |= MAPLESU_EFFECT_SESSION_CLOSED;
    mutex_unlock(&session->operation);
    msu_management_put(session);
finish:
    response->status = error;
    response->completion_magic = MAPLESU_RESPONSE_MAGIC;
    return error;
}

static int msu_legacy_hook_init(void)
{
    struct maplesu_legacy_hook_provider *provider = &management.legacy_provider;
    int error;
    provider->magic = MAPLESU_LEGACY_HOOK_MAGIC;
    provider->schema = MAPLESU_LEGACY_HOOK_SCHEMA;
    provider->length = sizeof(*provider);
    provider->host = management.host;
    provider->capabilities = msu_management_capabilities() &
        (MAPLESU_CAP_SESSION | MAPLESU_CAP_ALLOC | MAPLESU_CAP_WRITE |
            MAPLESU_CAP_EXEC | MAPLESU_CAP_RELEASE | MAPLESU_CAP_CODE_RESERVE |
            MAPLESU_CAP_PUBLICATION | MAPLESU_CAP_SHARED_BOOL | MAPLESU_KEY_CREDENTIAL_QUERY);
    provider->bind_function = (unsigned long)msu_legacy_hook_bind;
    provider->begin_function = (unsigned long)msu_legacy_hook_begin;
    provider->end_function = (unsigned long)msu_legacy_hook_end;
    provider->dispatch_function = (unsigned long)msu_legacy_hook_dispatch;
    error = maplesu_legacy_hook_provider_register(provider, &management);
    if (!error) management.legacy_registered = true;
    return error;
}

static int msu_legacy_hook_shutdown(void)
{
    int error;
    if (!management.legacy_registered) return 0;
    error = maplesu_legacy_hook_provider_unregister(&management);
    if (!error) management.legacy_registered = false;
    return error;
}
#else
static int msu_legacy_hook_init(void) { return 0; }
static int msu_legacy_hook_shutdown(void) { return 0; }
#endif
