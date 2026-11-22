/* SPDX-License-Identifier: GPL-3.0-only */
/* Resident-only provider registry; native-text builds retain their native
 * registry. Included after the management helpers, before legacy dispatch.
 * A valid lease pins this instance through put, even after admission closes. */
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
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
	if (!msu_management_sleepable())
		return -EWOULDBLOCK;
	if (!READ_ONCE(management.ready))
		return -EAGAIN;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->task = current;
	get_task_struct(entry->task);
	raw_spin_lock_irqsave(&maplesu_legacy_provider_lock, flags);
	if (!READ_ONCE(management.ready) || !maplesu_legacy_provider.table ||
	    maplesu_legacy_provider.draining)
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


#endif
