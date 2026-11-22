/* SPDX-License-Identifier: GPL-2.0-only */
/* Included by kernel/kprobes.c after its get_kprobe/flags definitions. */
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/hashtable.h>
#include <linux/user_namespace.h>
#ifdef CONFIG_ARM64
/* UID scans are finite and never sleep. The actual target config supplies
 * PREEMPT/TREE/TINY RCU semantics here; generated code does not infer them. */
void maplesu_legacy_uid_rcu_lock(void)
{
	rcu_read_lock();
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_rcu_lock);

void maplesu_legacy_uid_rcu_unlock(void)
{
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_rcu_unlock);

int maplesu_legacy_uid_synchronize_rcu(void)
{
	if (in_atomic() || irqs_disabled())
		return -EWOULDBLOCK;
	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_synchronize_rcu);

/* Immutable companion indexes leave the old control/list bytes unchanged.
 * Only the serialized authorization writer prepares or forgets an index.
 * Forget precedes freeing its table; exposed table readers drain separately
 * through the existing native RCU contract. */
#define MAPLESU_UID_BUCKET_BITS 8
#define MAPLESU_UID_MAX 4095U
struct maplesu_legacy_uid_index {
	struct hlist_node node;
	struct rcu_head rcu;
	unsigned long table;
	u32 count;
	u32 buckets[1U << MAPLESU_UID_BUCKET_BITS];
	struct { u32 uid, next; } entries[];
};
static DEFINE_HASHTABLE(maplesu_legacy_uid_indexes, 6);
static DEFINE_MUTEX(maplesu_legacy_uid_index_lock);

static int maplesu_legacy_uid_mutation_context(void)
{
	if (in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
	if (current_user_ns() != &init_user_ns ||
	    __kuid_val(current_uid()) || __kuid_val(current_euid())) return -EPERM;
	return 0;
}

int maplesu_legacy_uid_index_prepare(unsigned long table, u32 count)
{
	struct maplesu_legacy_uid_index *index, *existing;
	u32 i, uid, previous = 0, bucket;
	int error = maplesu_legacy_uid_mutation_context();
	if (error) return error;
	if ((u64)table < 0xffff000000000000ULL || (table & 3U) ||
	    !count || count > MAPLESU_UID_MAX ||
	    table > ~0UL - (count + 1UL) * sizeof(u32)) return -EINVAL;
	index = kzalloc(struct_size(index, entries, count), GFP_KERNEL);
	if (!index) return -ENOMEM;
	index->table = table;
	index->count = count;
	for (i = 0; i < count; ++i) {
		if (copy_from_kernel_nofault(&uid, (u32 *)table + i, sizeof(uid))) {
			error = -EFAULT;
			goto fail;
		}
		if (uid <= previous || uid > 0x7fffffffU) {
			error = -EINVAL;
			goto fail;
		}
		previous = uid;
		bucket = hash_32(uid, MAPLESU_UID_BUCKET_BITS);
		index->entries[i].uid = uid;
		index->entries[i].next = index->buckets[bucket];
		index->buckets[bucket] = i + 1;
	}
	if (copy_from_kernel_nofault(&uid, (u32 *)table + count, sizeof(uid))) {
		error = -EFAULT;
		goto fail;
	}
	if (uid) { error = -EINVAL; goto fail; }
	mutex_lock(&maplesu_legacy_uid_index_lock);
	hash_for_each_possible(maplesu_legacy_uid_indexes, existing, node, table) {
		if (existing->table != table) continue;
		error = existing->count == count &&
			!memcmp(existing->entries, index->entries,
				count * sizeof(index->entries[0])) ? 0 : -ESTALE;
		mutex_unlock(&maplesu_legacy_uid_index_lock);
		goto fail;
	}
	hash_add_rcu(maplesu_legacy_uid_indexes, &index->node, table);
	mutex_unlock(&maplesu_legacy_uid_index_lock);
	return 0;
fail:
	kfree(index);
	return error;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_index_prepare);

int maplesu_legacy_uid_index_forget(unsigned long table)
{
	struct maplesu_legacy_uid_index *index;
	int error = maplesu_legacy_uid_mutation_context();
	if (error) return error;
	mutex_lock(&maplesu_legacy_uid_index_lock);
	hash_for_each_possible(maplesu_legacy_uid_indexes, index, node, table) {
		if (index->table != table) continue;
		hash_del_rcu(&index->node);
		kfree_rcu(index, rcu);
		break;
	}
	mutex_unlock(&maplesu_legacy_uid_index_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_index_forget);

u64 maplesu_legacy_uid_lookup(unsigned long control)
{
	const u32 uid = __kuid_val(current_uid());
	struct maplesu_legacy_uid_index *index;
	unsigned long table;
	u32 i, value;
	u64 allowed = 0;
	if (!uid) return 1;
	if (!control) return 0;
	rcu_read_lock();
	table = smp_load_acquire((unsigned long *)control);
	if (!table) goto out;
	hash_for_each_possible_rcu(maplesu_legacy_uid_indexes, index, node, table) {
		if (index->table != table) continue;
		i = index->buckets[hash_32(uid, MAPLESU_UID_BUCKET_BITS)];
		while (i) {
			--i;
			if (index->entries[i].uid == uid) { allowed = 1; goto out; }
			i = index->entries[i].next;
		}
		goto out;
	}
	/* Old writers/modules may still publish a plain list. No header is read
	 * before or after that allocation, and its original admission is retained. */
	for (i = 0; i <= MAPLESU_UID_MAX; ++i) {
		value = READ_ONCE(((u32 *)table)[i]);
		if (!value) break;
		if (value == uid) { allowed = 1; break; }
	}
out:
	rcu_read_unlock();
	return allowed;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_uid_lookup);


/* One resident provider, with a real get/put interval for each dispatch/scope.
 * Task-owned leases also cover an EXEC which abandons its stack in do_exit.
 * Exit cleanup runs under the scheduler tracepoint's atomic context. */
static DEFINE_RAW_SPINLOCK(maplesu_legacy_provider_lock);
static DECLARE_WAIT_QUEUE_HEAD(maplesu_legacy_provider_wait);
struct maplesu_legacy_provider_lease {
	struct list_head node;
	struct task_struct *task;
};
static LIST_HEAD(maplesu_legacy_provider_leases);
static struct {
	const struct maplesu_legacy_hook_provider *table;
	const void *owner;
	struct module *module;
	unsigned int references;
	bool draining;
} maplesu_legacy_provider;

int maplesu_legacy_hook_provider_register(const struct maplesu_legacy_hook_provider *table,
					const void *owner)
{
	struct module *module = NULL;
	unsigned long flags;
	int error = 0;
	if (!table || !owner || table->magic != MAPLESU_LEGACY_HOOK_MAGIC ||
	    table->schema != MAPLESU_LEGACY_HOOK_SCHEMA || table->length != sizeof(*table) ||
	    !table->bind_function || !table->begin_function || !table->end_function ||
	    !table->dispatch_function)
		return -EINVAL;
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	if (maplesu_legacy_provider.owner) {
		error = -EBUSY;
		goto unlock;
	}
	preempt_disable();
	module = __module_address((unsigned long)table);
	if (module && !try_module_get(module)) {
		preempt_enable();
		error = -ENODEV;
		goto unlock;
	}
	preempt_enable();
	maplesu_legacy_provider.table = table;
	maplesu_legacy_provider.owner = owner;
	maplesu_legacy_provider.module = module;
	maplesu_legacy_provider.draining = false;
unlock:
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	return error;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_hook_provider_register);

int maplesu_legacy_hook_provider_get(const struct maplesu_legacy_hook_provider **table,
				   void **lease)
{
	struct maplesu_legacy_provider_lease *entry;
	unsigned long flags;
	int error = 0;
	if (!table || !lease)
		return -EINVAL;
	*table = NULL;
	*lease = NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->task = current;
	get_task_struct(entry->task);
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	if (!maplesu_legacy_provider.table || maplesu_legacy_provider.draining)
		error = -ENOENT;
	else if (maplesu_legacy_provider.references == ~0U)
		error = -EOVERFLOW;
	else {
		++maplesu_legacy_provider.references;
		list_add_tail(&entry->node, &maplesu_legacy_provider_leases);
		*table = maplesu_legacy_provider.table;
		*lease = entry;
	}
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	if (error) {
		put_task_struct(entry->task);
		kfree(entry);
	}
	return error;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_hook_provider_get);

void maplesu_legacy_hook_provider_put(void *lease)
{
	struct maplesu_legacy_provider_lease *entry, *found = NULL;
	unsigned long flags;
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	list_for_each_entry(entry, &maplesu_legacy_provider_leases, node) {
		if (entry == lease && entry->task == current) {
			found = entry;
			list_del(&entry->node);
			--maplesu_legacy_provider.references;
			break;
		}
	}
	if (found && !maplesu_legacy_provider.references)
		wake_up_all(&maplesu_legacy_provider_wait);
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	if (WARN_ON_ONCE(!found))
		return;
	put_task_struct(found->task);
	kfree(found);
}
EXPORT_SYMBOL_GPL(maplesu_legacy_hook_provider_put);

void maplesu_legacy_hook_provider_task_exit(struct task_struct *task)
{
	struct maplesu_legacy_provider_lease *entry, *next;
	unsigned long flags;
	LIST_HEAD(expired);
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	list_for_each_entry_safe(entry, next, &maplesu_legacy_provider_leases, node) {
		if (entry->task != task)
			continue;
		list_move_tail(&entry->node, &expired);
		--maplesu_legacy_provider.references;
	}
	if (!list_empty(&expired) && !maplesu_legacy_provider.references)
		wake_up_all(&maplesu_legacy_provider_wait);
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	list_for_each_entry_safe(entry, next, &expired, node) {
		list_del(&entry->node);
		put_task_struct(entry->task);
		kfree(entry);
	}
}
EXPORT_SYMBOL_GPL(maplesu_legacy_hook_provider_task_exit);

int maplesu_legacy_hook_provider_unregister(const void *owner)
{
	struct module *module;
	unsigned long flags;
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	if (!owner || maplesu_legacy_provider.owner != owner) {
		raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
		return -ESTALE;
	}
	if (maplesu_legacy_provider.draining) {
		raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
		return -EINPROGRESS;
	}
	maplesu_legacy_provider.draining = true;
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	wait_event(maplesu_legacy_provider_wait,
		   !READ_ONCE(maplesu_legacy_provider.references));
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	module = maplesu_legacy_provider.module;
	maplesu_legacy_provider.table = NULL;
	maplesu_legacy_provider.owner = NULL;
	maplesu_legacy_provider.module = NULL;
	maplesu_legacy_provider.draining = false;
	raw_spin_unlock_irqrestore(&maplesu_legacy_provider_lock, flags);
	if (module)
		module_put(module);
	return 0;
}
EXPORT_SYMBOL_GPL(maplesu_legacy_hook_provider_unregister);

struct kprobe_text_owner {
	struct list_head node;
	void *address;
	const void *owner;
	struct module *module;
	u32 original, branch;
	bool enabled;
};

static LIST_HEAD(kprobe_text_owners);

static struct kprobe_text_owner *kprobe_text_owner_find(void *address)
{
	struct kprobe_text_owner *entry;
	list_for_each_entry_rcu(entry, &kprobe_text_owners, node,
			       lockdep_is_held(&kprobe_mutex))
		if (entry->address == address)
			return entry;
	return NULL;
}
NOKPROBE_SYMBOL(kprobe_text_owner_find);

bool kprobe_text_owner_lookup(void *address, u32 *original, u32 *branch)
{
	struct kprobe_text_owner *entry = kprobe_text_owner_find(address);
	if (!entry || !READ_ONCE(entry->enabled))
		return false;
	if (original)
		*original = entry->original;
	if (branch)
		*branch = entry->branch;
	return true;
}
NOKPROBE_SYMBOL(kprobe_text_owner_lookup);

static int kprobe_text_owner_snapshot(void *address, u32 *logical,
				     u32 *physical, struct kprobe **probe)
{
	struct kprobe *p = get_kprobe(address);
	u32 original;
	if (p && (kprobe_gone(p) || kprobe_ftrace(p) || kprobe_optimized(p)))
		return -EOPNOTSUPP;
	if (copy_from_kernel_nofault(physical, address, sizeof(*physical)))
		return -EFAULT;
	original = p ? le32_to_cpu(p->opcode) : *physical;
	if (kprobe_text_owner_lookup(address, NULL, logical)) {
		/* The overlay branch is the logical instruction, not the BRK. */
	} else {
		*logical = original;
	}
	*probe = p;
	return 0;
}

int kprobe_text_owner_read(void *address, u32 *logical, u32 *physical)
{
	struct kprobe *probe;
	int error;
	if (!address || ((unsigned long)address & 3) || !logical || !physical)
		return -EINVAL;
	mutex_lock(&kprobe_mutex);
	cpus_read_lock();
	mutex_lock(&text_mutex);
	error = kprobe_text_owner_snapshot(address, logical, physical, &probe);
	mutex_unlock(&text_mutex);
	cpus_read_unlock();
	mutex_unlock(&kprobe_mutex);
	return error;
}
EXPORT_SYMBOL_GPL(kprobe_text_owner_read);

int kprobe_text_owner_claim(void *address, u32 expected, u32 branch,
			    const void *owner, u32 *effects)
{
	struct kprobe_text_owner *entry;
	struct kprobe *probe;
	struct module *module = NULL;
	u32 logical, physical, desired;
	int error;
	if (effects)
		*effects = 0;
	if (!effects || !owner || !address || ((unsigned long)address & 3) ||
	    (branch & 0xfc000000U) != 0x14000000U)
		return -EINVAL;
	/* Other architectures/optimized detours need their own native proof. */
	if (IS_ENABLED(CONFIG_OPTPROBES))
		return -EOPNOTSUPP;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	mutex_lock(&kprobe_mutex);
	if (kprobe_text_owner_find(address)) {
		error = -EBUSY;
		goto unlock;
	}
	preempt_disable();
	if (!core_kernel_text((unsigned long)address)) {
		module = __module_text_address((unsigned long)address);
		if (!module || !try_module_get(module)) {
			preempt_enable();
			error = -ENODEV;
			goto unlock;
		}
	}
	preempt_enable();
	cpus_read_lock();
	mutex_lock(&text_mutex);
	error = kprobe_text_owner_snapshot(address, &logical, &physical, &probe);
	if (error)
		goto unlock_text;
	if (logical != expected) {
		error = -EBUSY;
		goto unlock_text;
	}
	desired = probe && !kprobe_disabled(probe) && !kprobes_all_disarmed ?
		0xd4200080U : branch;
	if (physical != expected && physical != desired) {
		error = -EBUSY;
		goto unlock_text;
	}
	entry->address = address;
	entry->owner = owner;
	entry->module = module;
	entry->original = expected;
	entry->branch = branch;
	entry->enabled = true;
	list_add_tail_rcu(&entry->node, &kprobe_text_owners);
	*effects |= KPROBE_TEXT_OWNER_RETAINED;
	module = NULL;
	if (physical != desired) {
		*effects |= KPROBE_TEXT_OWNER_ATTEMPTED;
		error = arch_kprobe_text_owner_patch(address, desired);
		if (!error)
			*effects |= KPROBE_TEXT_OWNER_WRITTEN;
	}
	if (!error && (copy_from_kernel_nofault(&physical, address, sizeof(physical)) ||
		       physical != desired))
		error = -EIO;
unlock_text:
	mutex_unlock(&text_mutex);
	cpus_read_unlock();
unlock:
	mutex_unlock(&kprobe_mutex);
	if (module)
		module_put(module);
	if (!(*effects & KPROBE_TEXT_OWNER_RETAINED))
		kfree(entry);
	return error;
}
EXPORT_SYMBOL_GPL(kprobe_text_owner_claim);

int kprobe_text_owner_disable(void *address, const void *owner, u32 *effects)
{
	struct kprobe_text_owner *entry;
	struct kprobe *probe;
	u32 physical, desired;
	int error = 0;
	if (effects)
		*effects = 0;
	if (!effects || !owner || !address || ((unsigned long)address & 3))
		return -EINVAL;
	mutex_lock(&kprobe_mutex);
	entry = kprobe_text_owner_find(address);
	if (!entry || entry->owner != owner) {
		error = -ESTALE;
		goto unlock;
	}
	*effects |= KPROBE_TEXT_OWNER_RETAINED;
	if (!entry->enabled) {
		*effects |= KPROBE_TEXT_OWNER_DISABLED;
		goto unlock;
	}
	cpus_read_lock();
	mutex_lock(&text_mutex);
	probe = get_kprobe(address);
	if (probe && (kprobe_gone(probe) || kprobe_ftrace(probe) ||
		      kprobe_optimized(probe) || le32_to_cpu(probe->opcode) != entry->original)) {
		error = -ESTALE;
		goto unlock_text;
	}
	desired = probe && !kprobe_disabled(probe) && !kprobes_all_disarmed ?
		0xd4200080U : entry->original;
	if (copy_from_kernel_nofault(&physical, address, sizeof(physical))) {
		error = -EFAULT;
		goto unlock_text;
	}
	if (physical != desired && physical != entry->branch) {
		error = -EBUSY;
		goto unlock_text;
	}
	if (physical != desired) {
		*effects |= KPROBE_TEXT_OWNER_ATTEMPTED;
		error = arch_kprobe_text_owner_patch(address, desired);
		if (!error)
			*effects |= KPROBE_TEXT_OWNER_WRITTEN;
	}
	if (!error && (copy_from_kernel_nofault(&physical, address, sizeof(physical)) ||
		       physical != desired))
		error = -EIO;
	if (!error)
		WRITE_ONCE(entry->enabled, false);
unlock_text:
	mutex_unlock(&text_mutex);
	cpus_read_unlock();
unlock:
	mutex_unlock(&kprobe_mutex);
	if (!error) {
		/* Native exception readers disable preemption. This covers their
		 * pre-handler, B simulation and post-handler, not a sleepable
		 * original/gate after exception return: the publisher owns that. */
		synchronize_rcu();
		*effects |= KPROBE_TEXT_OWNER_DISABLED;
	}
	return error;
}
EXPORT_SYMBOL_GPL(kprobe_text_owner_disable);

int kprobe_text_owner_release(void *address, const void *owner, u32 *effects)
{
	struct kprobe_text_owner *entry;
	int error = 0;
	if (effects)
		*effects = 0;
	if (!effects || !owner || !address || ((unsigned long)address & 3))
		return -EINVAL;
	mutex_lock(&kprobe_mutex);
	entry = kprobe_text_owner_find(address);
	if (!entry || entry->owner != owner) {
		error = -ESTALE;
	} else if (entry->enabled) {
		*effects |= KPROBE_TEXT_OWNER_RETAINED;
		error = -EBUSY;
	} else {
		list_del_rcu(&entry->node);
	}
	mutex_unlock(&kprobe_mutex);
	if (error)
		return error;
	synchronize_rcu();
	if (entry->module)
		module_put(entry->module);
	kfree(entry);
	*effects = KPROBE_TEXT_OWNER_RELEASED;
	return 0;
}
EXPORT_SYMBOL_GPL(kprobe_text_owner_release);
#endif
