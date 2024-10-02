#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

#include "peerlookup.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmitrii Ermakov <demonihin@gmail.com>");

static size_t pre_seed_cnt = 1000;
static size_t iter_peers = 1000;
static size_t iterations = 100000;

module_param(pre_seed_cnt, ulong, 0644);
module_param(iter_peers, ulong, 0644);
module_param(iterations, ulong, 0644);

struct index_hashtable *peers = NULL;

static void clear_hashtable(struct index_hashtable *table)
{
	for (size_t i = 0; i < HASH_SIZE(table->hashtable); i++) {
		struct index_hashtable_entry *entry;
		struct hlist_node *n;

		hlist_for_each_entry_safe(entry, n, &table->hashtable[i],
					  index_hash) {
			// Do not free the pointer which is "head".
			if (&entry->index_hash == table->hashtable[i].first) {
				continue;
			}

			hlist_del(&entry->index_hash);
			kvfree(entry);
		}
	}
}

static void clear_hashmap(void)
{
	clear_hashtable(peers);
	kvfree(peers);
	peers = NULL;
}

static int pre_seed(size_t count)
{
	if (peers) {
		pr_err("Peers must not be initizlized\n");
		return EINVAL;
	}

	peers = wg_index_hashtable_alloc();
	if (!peers)
		return ENOMEM;

	for (size_t i = 0; i < count; i++) {
		struct index_hashtable_entry *entry = kmalloc(
			sizeof(struct index_hashtable_entry), GFP_KERNEL);
		if (!entry) {
			goto cleanup;
		}

		wg_index_hashtable_insert(peers, entry);
	}

	return 0;

cleanup:
	clear_hashmap();
	return ENOMEM;
}

static int do_ins_del(void)
{
	// Allocate peers and try to insers/replace/remove them for ITERATIONS times.
	// Measure execution time.
	struct index_hashtable_entry *work_peers =
		kcalloc(iter_peers, sizeof(*work_peers), GFP_KERNEL);
	if (!work_peers) {
		pr_err("Can not allocate memory for peers: %d\n", ENOMEM);
		goto work_peers_init_fail;
	}

	// Insert/delete.
	pr_info("Starting insert/delete\n");
	unsigned long jf_tot = 0;
	ktime_t kt_tot = 0;
	for (int i = 0; i < iterations; i++) {
		for (int pi = 0; pi < iter_peers; pi++) {
			unsigned long jf = jiffies;
			ktime_t kt = ktime_get();

			wg_index_hashtable_insert(peers, &work_peers[pi]);

			jf_tot += jiffies - jf;
			kt_tot += ktime_get() - kt;
		}

		for (int pi = 0; pi < iter_peers; pi++) {
			unsigned long jf = jiffies;
			ktime_t kt = ktime_get();

			wg_index_hashtable_remove(peers, &work_peers[pi]);

			jf_tot += jiffies - jf;
			kt_tot += ktime_get() - kt;
		}
	}

	pr_info("Insert/delete done, jiffies total = %lu, duration msec = %u, ktime_diff = %lli\n",
		jf_tot, jiffies_to_msecs(jf_tot), kt_tot);

	kfree(work_peers);

	return 0;

work_peers_init_fail:
	return ENOMEM;
}

static int do_replaces(void)
{
	int ret;
	struct index_hashtable_entry *init_peers =
		kcalloc(iter_peers, sizeof(*init_peers), GFP_KERNEL);
	if (!init_peers) {
		pr_err("Can not allocate memory for initial peers: %d\n",
		       ENOMEM);
		ret = ENOMEM;
		goto alloc_init_peers_fail;
	}

	struct index_hashtable_entry *replace_peers =
		kcalloc(iter_peers, sizeof(*init_peers), GFP_KERNEL);
	if (!init_peers) {
		pr_err("Can not allocate memory for replacemet peers: %d\n",
		       ENOMEM);
		ret = ENOMEM;
		goto alloc_replace_peers_fail;
	}

	unsigned long jiff_tot = 0;
	ktime_t ktime_tot = 0;

	for (int iter = 0; iter < iterations; iter++) {
		// Insert initial peers.
		for (int pi = 0; pi < iter_peers; pi++) {
			wg_index_hashtable_insert(peers, &init_peers[pi]);
		}

		// Do replacements.
		for (int pi = 0; pi < iter_peers; pi++) {
			unsigned long jf_start = jiffies;
			ktime_t kt_start = ktime_get();

			wg_index_hashtable_replace(peers, &init_peers[pi],
						   &replace_peers[pi]);

			jiff_tot += jiffies - jf_start;
			ktime_tot += ktime_get() - kt_start;
		}

		// Remove initial and replaced peers.
		for (int pi = 0; pi < iter_peers; pi++) {
			wg_index_hashtable_remove(peers, &init_peers[pi]);
			wg_index_hashtable_remove(peers, &replace_peers[pi]);
		}
	}

	// Do summary.
	pr_info("Replacements done, jiffies total = %lu, duration msec = %u, ktime total = %lli\n",
		jiff_tot, jiffies_to_msecs(jiff_tot), ktime_tot);

	kfree(init_peers);
	kfree(replace_peers);

	return 0;

alloc_replace_peers_fail:
	kfree(init_peers);

alloc_init_peers_fail:
	return ret;
}

static int do_step(void)
{
	int ret;
	pr_info("Step: pre-seed with %lu peers, manipulate with %lu peers, %lu iterations\n",
		pre_seed_cnt, iter_peers, iterations);

	ret = pre_seed(pre_seed_cnt);
	if (ret)
		goto pre_seed_fail;

	ret = do_ins_del();
	if (ret) {
		pr_err("Insert/delete failed with %d\n", ret);
		goto step_fail;
	}

	// Do ITERATIONS replaces.
	do_replaces();

	// Do ITERATIONS lookups.

	// Cleanup.
	clear_hashmap();

	return 0;

step_fail:
	clear_hashmap();

pre_seed_fail:
	return ret;
}

static int mod_init(void)
{
	return do_step();
}

static void mod_exit(void)
{
}

module_init(mod_init);
module_exit(mod_exit);
