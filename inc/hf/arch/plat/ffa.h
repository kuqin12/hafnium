/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/manifest.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

/**
 * The following enum relates to a state machine to guide the handling of the
 * Scheduler Receiver Interrupt.
 * The SRI is used to signal the receiver scheduler that there are pending
 * notifications for the receiver, and it is sent when there is a valid call to
 * FFA_NOTIFICATION_SET.
 * The FFA_NOTIFICATION_INFO_GET interface must be called in the SRI handler,
 * after which the FF-A driver should process the returned list, and request
 * the receiver scheduler to give the receiver CPU cycles to process the
 * notification.
 * The use of the following state machine allows for synchronized sending
 * and handling of the SRI, as well as avoiding the occurrence of spurious
 * SRI. A spurious SRI would be one such that upon handling a call to
 * FFA_NOTIFICATION_INFO_GET would return error FFA_NO_DATA, which is plausible
 * in an MP system.
 * The state machine also aims at resolving the delay of the SRI by setting
 * flag FFA_NOTIFICATIONS_FLAG_DELAY_SRI in the arguments of the set call. By
 * delaying, the SRI is sent in context switching to the primary endpoint.
 * The SPMC is implemented under the assumption the receiver scheduler is a
 * NWd endpoint, hence the SRI is triggered at the world switch.
 * If concurrently another notification is set that requires immediate action,
 * the SRI is triggered immediately within that same execution context.
 *
 * HANDLED is the initial state, and means a new SRI can be sent. The following
 * state transitions are possible:
 * * HANDLED => DELAYED: Setting notification, and requesting SRI delay.
 * * HANDLED => TRIGGERED: Setting notification, and not requesting SRI delay.
 * * DELAYED => TRIGGERED: SRI was delayed, and the context switch to the
 * receiver scheduler is being done.
 * * DELAYED => HANDLED: the scheduler called FFA_NOTIFICATION_INFO_GET.
 * * TRIGGERED => HANDLED: the scheduler called FFA_NOTIFICATION_INFO_GET.
 */
enum plat_ffa_sri_state {
	HANDLED = 0,
	DELAYED,
	TRIGGERED,
};

/** Returns information on features that are specific to the platform. */
struct ffa_value plat_ffa_features(uint32_t function_feature_id);
/** Returns the SPMC ID. */
struct ffa_value plat_ffa_spmc_id_get(void);

void plat_ffa_log_init(void);
void plat_ffa_init(bool tee_enabled);
bool plat_ffa_is_memory_send_valid(ffa_vm_id_t receiver_vm_id,
				   uint32_t share_func);

bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id);
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id);
bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm);
bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret);
bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id);

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id);
bool plat_ffa_notifications_update_bindings_forward(
	ffa_vm_id_t receiver_id, ffa_vm_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret);

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id);

bool plat_ffa_notification_set_forward(ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id,
				       uint32_t flags,
				       ffa_notifications_bitmap_t bitmap,
				       struct ffa_value *ret);

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id);

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret);

bool plat_ffa_notifications_get_call(ffa_vm_id_t receiver_id, uint32_t vcpu_id,
				     uint32_t flags, struct ffa_value *ret);

/**
 * Checks whether managed exit is supported by given SP.
 */
bool plat_ffa_vm_managed_exit_supported(struct vm *vm);

/**
 * Encodes memory handle according to section 5.10.2 of the FF-A v1.0 spec.
 */
ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index);

/**
 * Checks whether given handle was allocated by current world, according to
 * handle encoding rules.
 */
bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle);

/**
 * Return the FF-A partition info VM/SP properties given the VM id.
 */
ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target);

/**
 * Get NWd VM's structure.
 */
struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id);

/**
 * Creates a bitmap for the VM of the given ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count);

/**
 * Issues a FFA_NOTIFICATION_BITMAP_CREATE.
 * Returns true if the call goes well, and false if call returns with
 * FFA_ERROR_32.
 */
bool plat_ffa_notifications_bitmap_create_call(ffa_vm_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count);

/**
 * Destroys the notifications bitmap for the given VM ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id);

/**
 * Helper to get the struct notifications, depending on the sender's id.
 */
struct notifications *plat_ffa_vm_get_notifications_senders_world(
	struct vm_locked vm_locked, ffa_vm_id_t sender_id);

/**
 * Helper to check if FF-A ID is a VM ID.
 */
bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id);

/**
 * Forward normal world calls of FFA_RUN ABI to other world.
 */
bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret);

bool plat_ffa_notification_info_get_call(struct ffa_value *ret);

bool plat_ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
					uint32_t *lists_sizes,
					uint32_t *lists_count,
					const uint32_t ids_count_max);

/** Helper to set SRI current state. */
void plat_ffa_sri_state_set(enum plat_ffa_sri_state state);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if there has been
 * a call to FFA_NOTIFICATION_SET, and the SRI has been delayed.
 * To be called at a context switch to the NWd.
 */
void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if it hasn't been
 * delayed in call to FFA_NOTIFICATION_SET.
 */
void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu);

/**
 * Initialize Schedule Receiver Interrupts needed in the context of
 * notifications support.
 */
void plat_ffa_sri_init(struct cpu *cpu);

void plat_ffa_notification_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					    uint32_t *lists_sizes,
					    uint32_t *lists_count,
					    const uint32_t ids_count_max);

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current);
bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current);

/**
 * Check if current SP can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu *current, ffa_vm_id_t target_vm_id,
			 ffa_vcpu_index_t vcpu_idx, struct ffa_value *run_ret,
			 struct vcpu **next);

/**
 * Deactivate interrupt.
 */
int64_t plat_ffa_interrupt_deactivate(uint32_t pint_id, uint32_t vint_id,
				      struct vcpu *current);

void plat_ffa_secure_interrupt(struct vcpu *current, struct vcpu **next);
struct ffa_value plat_ffa_delegate_ffa_interrupt(struct vcpu *current,
						 struct vcpu **next);
struct ffa_value plat_ffa_normal_world_resume(struct vcpu *current,
					      struct vcpu **next);
struct ffa_value plat_ffa_preempted_vcpu_resume(struct vcpu *current,
						struct vcpu **next);

void plat_ffa_inject_notification_pending_interrupt_context_switch(
	struct vcpu *next, struct vcpu *current);

void plat_ffa_partition_info_get_forward(const struct ffa_uuid *uuid,
					 const uint32_t flags,
					 struct ffa_partition_info *partitions,
					 ffa_vm_count_t *ret_count);

void plat_ffa_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
				       paddr_t fdt_addr,
				       size_t fdt_allocated_size,
				       const struct manifest_vm *manifest_vm,
				       struct mpool *ppool);
