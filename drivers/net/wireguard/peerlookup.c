// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "peerlookup.h"
#include "linux/compiler.h"
#include "linux/rcupdate.h"
#include "linux/rhashtable-types.h"
#include "linux/rhashtable.h"
#include "linux/siphash.h"
#include "peer.h"
#include "noise.h"

static const struct rhashtable_params index_ht_params = {
	.head_offset = offsetof(struct index_hashtable_entry, index_hash),
	.key_offset = offsetof(struct index_hashtable_entry, index),
	.key_len = sizeof(__le32),
	.automatic_shrinking = true,
};

static inline u32 wg_peer_obj_hashfn(const void *data, u32 len, u32 seed)
{
  struct wg_peer* peer = data;

	return 0;
}

static inline int wg_peer_cmpfn(struct rhashtable_compare_arg *arg,
				const void *obj)
{
  return 0;
}

static const struct rhashtable_params pubkey_ht_params = {
	.head_offset = offsetof(struct wg_peer, pubkey_hash),
	.key_offset = offsetof(struct wg_peer, handshake),
	.key_len = sizeof(struct noise_handshake),
	.obj_hashfn = wg_peer_obj_hashfn,
	.obj_cmpfn = wg_peer_cmpfn,
	.automatic_shrinking = true,
};

static struct hlist_head *pubkey_bucket(struct pubkey_hashtable *table,
					const u8 pubkey[NOISE_PUBLIC_KEY_LEN])
{
	/* siphash gives us a secure 64bit number based on a random key. Since
	 * the bits are uniformly distributed, we can then mask off to get the
	 * bits we need.
	 */
	const u64 hash = siphash(pubkey, NOISE_PUBLIC_KEY_LEN, &table->key);

	return &table->hashtable[hash & (HASH_SIZE(table->hashtable) - 1)];
}

struct pubkey_hashtable *wg_pubkey_hashtable_alloc(void)
{
	struct pubkey_hashtable *table = kvmalloc(sizeof(*table), GFP_KERNEL);

	if (!table)
		return NULL;

	get_random_bytes(&table->key, sizeof(table->key));
	hash_init(table->hashtable);
	mutex_init(&table->lock);
	return table;
}

void wg_pubkey_hashtable_add(struct pubkey_hashtable *table,
			     struct wg_peer *peer)
{
	mutex_lock(&table->lock);
	//	rhashtable_insert_fast(struct rhashtable *ht, struct rhash_head *obj, const struct rhashtable_params params)
	rhashtable_insert_slow();
	hlist_add_head_rcu(&peer->pubkey_hash,
			   pubkey_bucket(table, peer->handshake.remote_static));
	mutex_unlock(&table->lock);
}

void wg_pubkey_hashtable_remove(struct pubkey_hashtable *table,
				struct wg_peer *peer)
{
	mutex_lock(&table->lock);
	hlist_del_init_rcu(&peer->pubkey_hash);
	mutex_unlock(&table->lock);
}

/* Returns a strong reference to a peer */
struct wg_peer *
wg_pubkey_hashtable_lookup(struct pubkey_hashtable *table,
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct wg_peer *iter_peer, *peer = NULL;

	rcu_read_lock_bh();
	hlist_for_each_entry_rcu_bh(iter_peer, pubkey_bucket(table, pubkey),
				    pubkey_hash) {
		if (!memcmp(pubkey, iter_peer->handshake.remote_static,
			    NOISE_PUBLIC_KEY_LEN)) {
			peer = iter_peer;
			break;
		}
	}
	peer = wg_peer_get_maybe_zero(peer);
	rcu_read_unlock_bh();
	return peer;
}

struct index_hashtable *wg_index_hashtable_alloc(void)
{
	struct index_hashtable *table = kvmalloc(sizeof(*table), GFP_KERNEL);

	if (!table)
		return NULL;

	if (rhashtable_init(&table->rhashtable, &index_ht_params)) {
		kvfree(table);
		return NULL;
	}

	spin_lock_init(&table->lock);
	return table;
}

/* At the moment, we limit ourselves to 2^20 total peers, which generally might
 * amount to 2^20*3 items in this hashtable. The algorithm below works by
 * picking a random number and testing it. We can see that these limits mean we
 * usually succeed pretty quickly:
 *
 * >>> def calculation(tries, size):
 * ...     return (size / 2**32)**(tries - 1) *  (1 - (size / 2**32))
 * ...
 * >>> calculation(1, 2**20 * 3)
 * 0.999267578125
 * >>> calculation(2, 2**20 * 3)
 * 0.0007318854331970215
 * >>> calculation(3, 2**20 * 3)
 * 5.360489012673497e-07
 * >>> calculation(4, 2**20 * 3)
 * 3.9261394135792216e-10
 *
 * At the moment, we don't do any masking, so this algorithm isn't exactly
 * constant time in either the random guessing or in the hash list lookup. We
 * could require a minimum of 3 tries, which would successfully mask the
 * guessing. this would not, however, help with the growing hash lengths, which
 * is another thing to consider moving forward.
 */

__le32 wg_index_hashtable_insert(struct index_hashtable *table,
				 struct index_hashtable_entry *entry)
{
	spin_lock_bh(&table->lock);
	rhashtable_remove_fast(&table->rhashtable, &entry->index_hash, index_ht_params);
	spin_unlock_bh(&table->lock);

	rcu_read_lock_bh();

search_unused_slot:
	/* First we try to find an unused slot, randomly, while unlocked. */
	entry->index = (__force __le32)get_random_u32();
	if (rhashtable_lookup(&table->rhashtable, &entry->index, index_ht_params)) {
		/* If it's already in use, we continue searching. */
		goto search_unused_slot;
	}

	/* Once we've found an unused slot, we lock it, and then double-check
	 * that nobody else stole it from us.
	 */
	spin_lock_bh(&table->lock);
	if (rhashtable_lookup(&table->rhashtable, &entry->index,
			      index_ht_params)) {
		spin_unlock_bh(&table->lock);
		/* If it was stolen, we start over. */
		goto search_unused_slot;
	}

	/* Otherwise, we know we have it exclusively (since we're locked),
	 * so we insert.
	 */
	rhashtable_insert_fast(&table->rhashtable, &entry->index_hash, index_ht_params);
	spin_unlock_bh(&table->lock);

	rcu_read_unlock_bh();

	return entry->index;
}

bool wg_index_hashtable_replace(struct index_hashtable *table,
				struct index_hashtable_entry *old,
				struct index_hashtable_entry *new)
{
	bool ret;

	spin_lock_bh(&table->lock);
	ret = rhashtable_lookup_fast(&table->rhashtable, &old->index, index_ht_params);
	if (unlikely(!ret))
		goto out;

	new->index = old->index;
	rhashtable_replace_fast(&table->rhashtable, &old->index_hash,
				&new->index_hash, index_ht_params);

out:
	spin_unlock_bh(&table->lock);
	return ret;
}

void wg_index_hashtable_remove(struct index_hashtable *table,
			       struct index_hashtable_entry *entry)
{
	spin_lock_bh(&table->lock);
	rhashtable_remove_fast(&table->rhashtable, &entry->index_hash, index_ht_params);
	spin_unlock_bh(&table->lock);
}

/* Returns a strong reference to a entry->peer */
struct index_hashtable_entry *
wg_index_hashtable_lookup(struct index_hashtable *table,
			  const enum index_hashtable_type type_mask,
			  const __le32 index, struct wg_peer **peer)
{
	struct index_hashtable_entry *entry = NULL;

	rcu_read_lock_bh();
	entry = rhashtable_lookup(&table->rhashtable, &index, index_ht_params);
	if (unlikely(!entry)) {
		rcu_read_unlock_bh();
		return entry;
	}

	if (likely(entry && (entry->type & type_mask))) {
		entry->peer = wg_peer_get_maybe_zero(entry->peer);
		if (likely(entry->peer))
			*peer = entry->peer;
		else
			entry = NULL;
	}
	rcu_read_unlock_bh();
	return entry;
}
