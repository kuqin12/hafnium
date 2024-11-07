/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

void plat_ffa_disable_vm_interrupts(struct vm_locked vm_locked);

void plat_ffa_vm_init(struct mpool *ppool);

struct vm_locked plat_ffa_nwd_vm_create(ffa_id_t vm_id);

bool plat_ffa_vm_supports_indirect_messages(struct vm *vm);

bool plat_ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
					uint32_t *lists_sizes,
					uint32_t *lists_count,
					uint32_t ids_count_max);

/** Get NWd VM's structure. */
struct vm_locked plat_ffa_vm_find_locked(ffa_id_t vm_id);

struct vm_locked plat_ffa_vm_find_locked_create(ffa_id_t vm_id);

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked);

/** Reclaim all resources belonging to VM in aborted state. */
void plat_ffa_free_vm_resources(struct vm_locked vm_locked);

/** Checks whether managed exit is supported by given SP. */
bool plat_ffa_vm_managed_exit_supported(struct vm *vm);
