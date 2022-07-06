/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"
#include "hf/arch/ffa.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"

#include "hf/api.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory.h"
#include "hf/ffa_memory_internal.h"
#include "hf/std.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "msr.h"
#include "smc.h"
#include "sysregs.h"

static bool ffa_tee_enabled;

alignas(FFA_PAGE_SIZE) static uint8_t other_world_send_buffer[HF_MAILBOX_SIZE];
alignas(FFA_PAGE_SIZE) static uint8_t other_world_recv_buffer[HF_MAILBOX_SIZE];

/**
 * Buffer for retrieving memory region information from the other world for when
 * a region is reclaimed by a VM. Access to this buffer must be guarded by the
 * VM lock of the other world VM.
 */
alignas(PAGE_SIZE) static uint8_t
	other_world_retrieve_buffer[HF_MAILBOX_SIZE * MAX_FRAGMENTS];

/** Returns information on features specific to the NWd. */
struct ffa_value plat_ffa_features(uint32_t function_feature_id)
{
	switch (function_feature_id) {
	case FFA_MSG_POLL_32:
	case FFA_YIELD_32:
	case FFA_MSG_SEND_32:
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	default:
		return ffa_error(FFA_NOT_SUPPORTED);
	}
}

struct ffa_value plat_ffa_spmc_id_get(void)
{
	if (ffa_tee_enabled) {
		/*
		 * Fetch the SPMC ID from the SPMD using FFA_SPM_ID_GET.
		 * DEN0077A FF-A v1.1 Beta0 section 13.9.2
		 * "FFA_SPM_ID_GET invocation at a non-secure physical FF-A
		 * instance returns the ID of the SPMC."
		 */
		return smc_ffa_call(
			(struct ffa_value){.func = FFA_SPM_ID_GET_32});
	}

	return (struct ffa_value){.func = FFA_ERROR_32,
				  .arg2 = FFA_NOT_SUPPORTED};
}

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (Hypervisor)\n");
}

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	ffa_tee_enabled = tee_enabled;
}

static void plat_ffa_rxtx_map_spmc(paddr_t recv, paddr_t send,
				   uint64_t page_count)
{
	struct ffa_value ret;

	ret = arch_other_world_call((struct ffa_value){.func = FFA_RXTX_MAP_64,
						       .arg1 = pa_addr(recv),
						       .arg2 = pa_addr(send),
						       .arg3 = page_count});
	CHECK(ret.func == FFA_SUCCESS_32);
}

void plat_ffa_init(struct mpool *ppool)
{
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;

	(void)ppool;

	if (!ffa_tee_enabled) {
		return;
	}

	CHECK(other_world_vm != NULL);

	arch_ffa_init();

	/*
	 * Call FFA_VERSION so the SPMC can store the hypervisor's
	 * version. This may be useful if there is a mismatch of
	 * versions.
	 */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_VERSION_32, .arg1 = FFA_VERSION_COMPILED});
	if (ret.func == (uint32_t)FFA_NOT_SUPPORTED) {
		panic("Hypervisor and SPMC versions are not compatible.\n");
	}

	/* Setup TEE VM RX/TX buffers */
	other_world_vm->mailbox.send = &other_world_send_buffer;
	other_world_vm->mailbox.recv = &other_world_recv_buffer;

	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	plat_ffa_rxtx_map_spmc(
		pa_from_va(va_from_ptr(other_world_vm->mailbox.recv)),
		pa_from_va(va_from_ptr(other_world_vm->mailbox.send)),
		HF_MAILBOX_SIZE / FFA_PAGE_SIZE);

	ffa_tee_enabled = true;

	dlog_verbose("TEE finished setting up buffers.\n");
}

bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	/*
	 * VM's requests should be forwarded to the SPMC, if target is an SP.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_RUN_32, ffa_vm_vcpu(vm_id, vcpu_idx)});
		return true;
	}

	return false;
}

/**
 * Check validity of the FF-A memory send function attempt.
 */
bool plat_ffa_is_memory_send_valid(ffa_vm_id_t receiver_vm_id,
				   uint32_t share_func)
{
	/*
	 * Currently memory interfaces are not forwarded from hypervisor to
	 * SPMC. However, in absence of SPMC this function should allow
	 * NS-endpoint to SP memory send in order for trusty tests to work.
	 */

	(void)share_func;
	(void)receiver_vm_id;
	return true;
}

/**
 * Check validity of a FF-A direct message request.
 */
bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * The primary VM can send direct message request to
	 * any other VM (but itself) or SP, but can't spoof
	 * a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       current_vm_id == HF_PRIMARY_VM_ID;
}

/**
 * Check validity of a FF-A notifications bitmap create.
 */
bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id)
{
	/*
	 * Call should only be used by the Hypervisor, so any attempt of
	 * invocation from NWd FF-A endpoints should fail.
	 */
	(void)current;
	(void)vm_id;

	return false;
}

bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm)
{
	(void)sender_vm;
	(void)receiver_vm;

	/*
	 * As Hypervisor is only meant to be used as a test artifact, allow
	 * direct messaging for all VMs.
	 */
	return true;
}

/**
 * Check validity of a FF-A direct message response.
 */
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * Secondary VMs can send direct message responses to
	 * the PVM, but can't spoof a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       receiver_vm_id == HF_PRIMARY_VM_ID;
}

bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret)
{
	if (!ffa_tee_enabled) {
		return false;
	}

	/*
	 * VM's requests should be forwarded to the SPMC, if receiver is an SP.
	 */
	if (!vm_id_is_current_world(receiver_vm_id)) {
		dlog_verbose("%s calling SPMC %#x %#x %#x %#x %#x\n", __func__,
			     args.func, args.arg1, args.arg2, args.arg3,
			     args.arg4);
		*ret = arch_other_world_call(args);
		return true;
	}

	return false;
}

bool plat_ffa_rx_release_forward(struct vm_locked vm_locked,
				 struct ffa_value *ret)
{
	struct vm *vm = vm_locked.vm;
	ffa_vm_id_t vm_id = vm->id;

	if (!ffa_tee_enabled || (vm->ffa_version < MAKE_FFA_VERSION(1, 1))) {
		*ret = (struct ffa_value){.func = FFA_SUCCESS_32};
		return true;
	}

	CHECK(vm_id_is_current_world(vm_id));

	/* Hypervisor always forward VM's RX_RELEASE to SPMC. */
	*ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RX_RELEASE_32, .arg1 = vm_id});

	return ret->func == FFA_SUCCESS_32;
}

/**
 * In FF-A v1.1 with SPMC enabled the SPMC owns the RX buffers for NWd VMs,
 * hence the SPMC is handling FFA_RX_RELEASE calls for NWd VMs too.
 * The Hypervisor's view of a VM's RX buffer can be out of sync, reset it to
 * 'empty' if the FFA_RX_RELEASE call has been successfully forwarded to the
 * SPMC.
 */
bool plat_ffa_rx_release_forwarded(struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;

	if (ffa_tee_enabled && (vm->ffa_version > MAKE_FFA_VERSION(1, 0))) {
		dlog_verbose(
			"RX_RELEASE forwarded, reset MB state for VM ID %#x.\n",
			vm->id);
		vm->mailbox.state = MAILBOX_STATE_EMPTY;
		return true;
	}

	return false;
}

/**
 * Acquire the RX buffer of a VM from the SPM.
 *
 * VM RX/TX buffers must have been previously mapped in the SPM either
 * by forwarding VM's RX_TX_MAP API or another way if buffers were
 * declared in manifest.
 */
bool plat_ffa_acquire_receiver_rx(struct vm_locked to_locked,
				  struct ffa_value *ret)
{
	if (!ffa_tee_enabled) {
		return true;
	}

	if (to_locked.vm->ffa_version < MAKE_FFA_VERSION(1, 1)) {
		return true;
	}

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RX_ACQUIRE_32, .arg1 = to_locked.vm->id});

	return ret->func == FFA_SUCCESS_32;
}

bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
					struct vm_locked receiver_locked)
{
	(void)sender_locked;
	(void)receiver_locked;

	/*
	 * Hypervisor is only for testing purposes, always allow indirect
	 * messages from VM.
	 */
	return true;
}

bool plat_ffa_msg_send2_forward(ffa_vm_id_t receiver_vm_id,
				ffa_vm_id_t sender_vm_id, struct ffa_value *ret)
{
	/* FFA_MSG_SEND2 is forwarded to SPMC when the receiver is an SP. */
	if (!vm_id_is_current_world(receiver_vm_id)) {
		/*
		 * Set the sender in arg1 to allow the SPMC to retrieve
		 * VM's TX buffer to copy in SP's RX buffer.
		 */
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_MSG_SEND2_32, .arg1 = sender_vm_id << 16});
		if (ffa_func_id(*ret) != FFA_SUCCESS_32) {
			dlog_verbose(
				"Failed forwarding FFA_MSG_SEND2_32 to the "
				"SPMC, got error (%d).\n",
				ret->arg2);
		}

		return true;
	}

	return false;
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return index | FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
}

bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle)
{
	return (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	       FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
}

uint32_t plat_ffa_other_world_mode(void)
{
	return 0U;
}

uint32_t plat_ffa_owner_world_mode(ffa_vm_id_t owner_id)
{
	(void)owner_id;
	return plat_ffa_other_world_mode();
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	/*
	 * VMs support indirect messaging only in the Normal World.
	 * Primary VM cannot receive direct requests.
	 * Secondary VMs cannot send direct requests.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		result &= ~FFA_PARTITION_INDIRECT_MSG;
	}
	if (target->id == HF_PRIMARY_VM_ID) {
		result &= ~FFA_PARTITION_DIRECT_REQ_RECV;
	} else {
		result &= ~FFA_PARTITION_DIRECT_REQ_SEND;
	}
	return result;
}

bool plat_ffa_vm_managed_exit_supported(struct vm *vm)
{
	(void)vm;

	return false;
}

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;
	/** If Hafnium is hypervisor, receiver needs to be current vm. */
	return sender_id != receiver_id && current_vm_id == receiver_id;
}

bool plat_ffa_notifications_update_bindings_forward(
	ffa_vm_id_t receiver_id, ffa_vm_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret)
{
	CHECK(ret != NULL);

	if (vm_id_is_current_world(receiver_id) &&
	    !vm_id_is_current_world(sender_id)) {
		dlog_verbose(
			"Forward notifications bind/unbind to other world.\n");
		*ret = arch_other_world_call((struct ffa_value){
			.func = is_bind ? FFA_NOTIFICATION_BIND_32
					: FFA_NOTIFICATION_UNBIND_32,
			.arg1 = (sender_id << 16) | (receiver_id),
			.arg2 = is_bind ? flags : 0U,
			.arg3 = (uint32_t)(bitmap),
			.arg4 = (uint32_t)(bitmap >> 32),
		});
		return true;
	}
	return false;
}

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, sender needs to be current vm. */
	return sender_id == current_vm_id && sender_id != receiver_id;
}

bool plat_ffa_notification_set_forward(ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id,
				       uint32_t flags,
				       ffa_notifications_bitmap_t bitmap,
				       struct ffa_value *ret)
{
	/* Forward only if receiver is an SP. */
	if (vm_id_is_current_world(receiver_vm_id)) {
		return false;
	}

	dlog_verbose("Forwarding notification set to SPMC.\n");

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_SET_32,
		.arg1 = (sender_vm_id << 16) | receiver_vm_id,
		.arg2 = flags,
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});

	if (ret->func == FFA_ERROR_32) {
		dlog_verbose("Failed to set notifications from SPMC.\n");
	}

	return true;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id, uint32_t flags)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	(void)flags;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_notifications_bitmap_create_call(ffa_vm_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count)
{
	struct ffa_value ret;

	if (ffa_tee_enabled) {
		ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_BITMAP_CREATE_32,
			.arg1 = vm_id,
			.arg2 = vcpu_count,
		});

		if (ret.func == FFA_ERROR_32) {
			dlog_error(
				"Failed to create notifications bitmap "
				"to VM: %#x; error: %#x.\n",
				vm_id, ffa_error_code(ret));
			return false;
		}
	}

	return true;
}

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked_create(ffa_vm_id_t vm_id)
{
	return plat_ffa_vm_find_locked(vm_id);
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	return vm_id_is_current_world(vm_id);
}

void plat_ffa_notification_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					    uint32_t *lists_sizes,
					    uint32_t *lists_count,
					    const uint32_t ids_count_max)
{
	CHECK(ids != NULL);
	CHECK(ids_count != NULL);
	CHECK(lists_sizes != NULL);
	CHECK(lists_count != NULL);
	CHECK(ids_count_max == FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	uint32_t local_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS];
	struct ffa_value ret;

	dlog_verbose("Forwarding notification info get to SPMC.\n");

	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_INFO_GET_64,
	});

	if (ret.func == FFA_ERROR_32) {
		dlog_verbose("No notifications returned by SPMC.\n");
		return;
	}

	*lists_count = ffa_notification_info_get_lists_count(ret);

	if (*lists_count > ids_count_max) {
		*lists_count = 0;
		return;
	}

	/*
	 * The count of ids should be at least the number of lists, to
	 * encompass for at least the ids of the FF-A endpoints. List
	 * sizes will be between 0 and 3, and relates to the counting of
	 * vCPU of the endpoint that have pending notifications.
	 * If `lists_count` is already ids_count_max, each list size
	 * must be 0.
	 */
	*ids_count = *lists_count;

	for (uint32_t i = 0; i < *lists_count; i++) {
		local_lists_sizes[i] =
			ffa_notification_info_get_list_size(ret, i + 1);

		/*
		 * ... sum the counting of each list size that are part
		 * of the main list.
		 */
		*ids_count += local_lists_sizes[i];
	}

	/*
	 * Sanity check returned `lists_count` and determined
	 * `ids_count`. If something wrong, reset arguments to 0 such
	 * that hypervisor's handling of FFA_NOTIFICATION_INFO_GET can
	 * proceed without SPMC's values.
	 */
	if (*ids_count > ids_count_max) {
		*ids_count = 0;
		return;
	}

	/* Copy now lists sizes, as return sizes have been validated. */
	memcpy_s(lists_sizes, sizeof(lists_sizes[0]) * ids_count_max,
		 local_lists_sizes, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	/* Unpack the notifications info from the return. */
	memcpy_s(ids, sizeof(ids[0]) * ids_count_max, &ret.arg3,
		 sizeof(ret.arg3) * FFA_NOTIFICATIONS_INFO_GET_REGS_RET);
}

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret)
{
	ffa_vm_id_t receiver_id = receiver_locked.vm->id;

	assert(from_sp != NULL && ret != NULL);

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_GET_32,
		.arg1 = (vcpu_id << 16) | receiver_id,
		.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SP,
	});

	if (ret->func == FFA_ERROR_32) {
		return false;
	}

	*from_sp = ffa_notification_get_from_sp(*ret);

	return true;
}

bool plat_ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	uint32_t flags, ffa_vcpu_index_t vcpu_id, struct ffa_value *ret)
{
	ffa_vm_id_t receiver_id = receiver_locked.vm->id;
	ffa_notifications_bitmap_t spm_notifications = 0;

	(void)flags;

	assert(from_fwk != NULL);
	assert(ret != NULL);

	/* Get SPMC notifications. */
	if (ffa_tee_enabled) {
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_GET_32,
			.arg1 = (vcpu_id << 16) | receiver_id,
			.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SPM,
		});

		if (ffa_func_id(*ret) == FFA_ERROR_32) {
			return false;
		}

		spm_notifications = ffa_notification_get_from_framework(*ret);
	}

	/* Merge notifications from SPMC and Hypervisor. */
	*from_fwk = spm_notifications |
		    vm_notifications_framework_get_pending(receiver_locked);

	return true;
}

bool plat_ffa_vm_notifications_info_get(     // NOLINTNEXTLINE
	uint16_t *ids, uint32_t *ids_count,  // NOLINTNEXTLINE
	uint32_t *lists_sizes,		     // NOLINTNEXTLINE
	uint32_t *lists_count, const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;

	return false;
}

void plat_ffa_rxtx_map_forward(struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;
	struct vm *other_world;

	if (!ffa_tee_enabled) {
		return;
	}

	if (vm->ffa_version < MAKE_FFA_VERSION(1, 1)) {
		return;
	}

	/* Hypervisor always forward the call to the SPMC. */

	other_world = vm_find(HF_OTHER_WORLD_ID);

	/* Fill the buffers descriptor in SPMC's RX buffer. */
	ffa_endpoint_rx_tx_descriptor_init(
		(struct ffa_endpoint_rx_tx_descriptor *)
			other_world->mailbox.recv,
		vm->id, (uintptr_t)vm->mailbox.recv,
		(uintptr_t)vm->mailbox.send);

	plat_ffa_rxtx_map_spmc(pa_init(0), pa_init(0), 0);
}

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	/* Hypervisor never frees VM structs. */
	(void)to_destroy_locked;
}

void plat_ffa_rxtx_unmap_forward(struct vm_locked vm_locked)
{
	struct ffa_value ret;
	uint64_t func;
	ffa_vm_id_t id;

	assert(vm_locked.vm != NULL);

	id = vm_locked.vm->id;

	if (!ffa_tee_enabled) {
		return;
	}

	if (vm_locked.vm->ffa_version < MAKE_FFA_VERSION(1, 1)) {
		return;
	}

	/* Hypervisor always forwards forward RXTX_UNMAP to SPMC. */
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RXTX_UNMAP_32,
				   .arg1 = id << FFA_RXTX_ALLOCATOR_SHIFT});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == SMCCC_ERROR_UNKNOWN) {
		panic("Unknown error forwarding RXTX_UNMAP.\n");
	} else if (func == FFA_ERROR_32) {
		panic("Error %d forwarding RX/TX buffers.\n", ret.arg2);
	} else if (func != FFA_SUCCESS_32) {
		panic("Unexpected function %#x returned forwarding RX/TX "
		      "buffers.",
		      ret.func);
	}
}

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current)
{
	(void)current;
	return has_vhe_support();
}

bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current)
{
	(void)current;
	return has_vhe_support();
}

/**
 * Check if current VM can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu *current, ffa_vm_id_t target_vm_id,
			 ffa_vcpu_index_t vcpu_idx, struct ffa_value *run_ret,
			 struct vcpu **next)
{
	(void)next;
	(void)vcpu_idx;

	/* Only the primary VM can switch vCPUs. */
	if (current->vm->id != HF_PRIMARY_VM_ID) {
		run_ret->arg2 = FFA_DENIED;
		return false;
	}

	/* Only secondary VM vCPUs can be run. */
	if (target_vm_id == HF_PRIMARY_VM_ID) {
		return false;
	}

	return true;
}

struct ffa_value plat_ffa_handle_secure_interrupt(struct vcpu *current,
						  struct vcpu **next,
						  bool from_normal_world)
{
	(void)current;
	(void)next;
	(void)from_normal_world;

	/*
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to
	 * SPMC. Execution should not reach hypervisor with this ABI.
	 */
	CHECK(false);

	return ffa_error(FFA_NOT_SUPPORTED);
}

void plat_ffa_sri_state_set(enum plat_ffa_sri_state state)
{
	(void)state;
}

/**
 * An Hypervisor should send the SRI to the Primary Endpoint. Not implemented
 * as Hypervisor is only interesting for us for the sake of having a test
 * intrastructure that encompasses the NWd, and we are not interested on
 * in testing the flow of notifications between VMs only.
 */
void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu)
{
	(void)cpu;
}

void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu)
{
	(void)cpu;
}

void plat_ffa_sri_init(struct cpu *cpu)
{
	(void)cpu;
}

bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu *current,
	struct vm_locked receiver_locked)
{
	(void)target_locked;
	(void)current;
	(void)receiver_locked;

	return false;
}

/*
 * Forward helper for FFA_PARTITION_INFO_GET.
 * Emits FFA_PARTITION_INFO_GET from Hypervisor to SPMC if allowed.
 */
void plat_ffa_partition_info_get_forward(const struct ffa_uuid *uuid,
					 const uint32_t flags,
					 struct ffa_partition_info *partitions,
					 ffa_vm_count_t *ret_count)
{
	const struct vm *tee = vm_find(HF_TEE_VM_ID);
	struct ffa_partition_info *tee_partitions;
	ffa_vm_count_t tee_partitions_count;
	ffa_vm_count_t vm_count = *ret_count;
	struct ffa_value ret;

	CHECK(tee != NULL);
	CHECK(vm_count < MAX_VMS);

	/*
	 * Allow forwarding from the Hypervisor if TEE or SPMC exists and
	 * declared as such in the Hypervisor manifest.
	 */
	if (!ffa_tee_enabled) {
		return;
	}

	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_PARTITION_INFO_GET_32,
				   .arg1 = uuid->uuid[0],
				   .arg2 = uuid->uuid[1],
				   .arg3 = uuid->uuid[2],
				   .arg4 = uuid->uuid[3],
				   .arg5 = flags});
	if (ffa_func_id(ret) != FFA_SUCCESS_32) {
		dlog_verbose(
			"Failed forwarding FFA_PARTITION_INFO_GET to "
			"the SPMC.\n");
		return;
	}

	tee_partitions_count = ffa_partition_info_get_count(ret);
	if (tee_partitions_count == 0 || tee_partitions_count > MAX_VMS) {
		dlog_verbose("Invalid number of SPs returned by the SPMC.\n");
		return;
	}

	if ((flags & FFA_PARTITION_COUNT_FLAG_MASK) ==
	    FFA_PARTITION_COUNT_FLAG) {
		vm_count += tee_partitions_count;
	} else {
		tee_partitions = (struct ffa_partition_info *)tee->mailbox.send;
		for (ffa_vm_count_t index = 0; index < tee_partitions_count;
		     index++) {
			partitions[vm_count] = tee_partitions[index];
			++vm_count;
		}

		/* Release the RX buffer. */
		ret = arch_other_world_call(
			(struct ffa_value){.func = FFA_RX_RELEASE_32});
		CHECK(ret.func == FFA_SUCCESS_32);
	}

	*ret_count = vm_count;
}

void plat_ffa_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
				       paddr_t fdt_addr,
				       size_t fdt_allocated_size,
				       const struct manifest_vm *manifest_vm,
				       struct mpool *ppool)
{
	struct fdt partition_fdt;

	/*
	 * If the partition is an FF-A partition and is not
	 * hypervisor loaded, the manifest is passed in the
	 * partition package and is parsed during
	 * manifest_init() and secondary fdt should be empty.
	 */
	CHECK(manifest_vm->is_hyp_loaded);
	CHECK(mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_allocated_size), MM_MODE_R,
			      ppool) != NULL);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	CHECK(fdt_init_from_ptr(&partition_fdt, (void *)pa_addr(fdt_addr),
				fdt_allocated_size) == true);
	CHECK(parse_ffa_manifest(&partition_fdt,
				 (struct manifest_vm *)manifest_vm,
				 NULL) == MANIFEST_SUCCESS);
	CHECK(mm_unmap(stage1_locked, fdt_addr,
		       pa_add(fdt_addr, fdt_allocated_size), ppool) == true);
}

/**
 * Returns FFA_ERROR as FFA_SECONDARY_EP_REGISTER is not supported at the
 * non-secure FF-A instances.
 */
bool plat_ffa_is_secondary_ep_register_supported(void)
{
	return false;
}

/**
 * The invocation of FFA_MSG_WAIT at non-secure virtual FF-A instance is made
 * to be compliant with version v1.0 of the FF-A specification. It serves as
 * a blocking call.
 */
struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu *current,
					   struct vcpu **next)
{
	return api_ffa_msg_recv(true, current, next);
}

bool plat_ffa_check_runtime_state_transition(
	struct vcpu *current, ffa_vm_id_t vm_id, ffa_vm_id_t receiver_vm_id,
	struct vcpu *receiver_vcpu, uint32_t func, enum vcpu_state *next_state)
{
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_vcpu;

	switch (func) {
	case FFA_YIELD_32:
		/* Check if a direct message is ongoing. */
		if (current->direct_request_origin_vm_id != HF_INVALID_VM_ID) {
			return false;
		}

		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_RUN_32:
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
		*next_state = VCPU_STATE_WAITING;
		return true;
	default:
		return false;
	}
}

void plat_ffa_init_schedule_mode_ffa_run(struct vcpu *current,
					 struct vcpu_locked target_locked)
{
	/* Scheduling mode not supported in the Hypervisor/VMs. */
	(void)current;
	(void)target_locked;
}

void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)receiver_vcpu_locked;
}

void plat_ffa_unwind_call_chain_ffa_direct_resp(struct vcpu *current,
						struct vcpu *next)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current;
	(void)next;
}

void plat_ffa_enable_virtual_maintenance_interrupts(
	struct vcpu_locked current_locked)
{
	(void)current_locked;
}

/** Forwards a memory send message on to the other world. */
static struct ffa_value memory_send_other_world_forward(
	struct vm_locked other_world_locked, ffa_vm_id_t sender_vm_id,
	uint32_t share_func, struct ffa_memory_region *memory_region,
	uint32_t memory_share_length, uint32_t fragment_length)
{
	struct ffa_value ret;

	/* Use its own RX buffer. */
	memcpy_s(other_world_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 memory_region, fragment_length);
	other_world_locked.vm->mailbox.recv_size = fragment_length;
	other_world_locked.vm->mailbox.recv_sender = sender_vm_id;
	other_world_locked.vm->mailbox.recv_func = share_func;
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_RECEIVED;
	ret = arch_other_world_call(
		(struct ffa_value){.func = share_func,
				   .arg1 = memory_share_length,
				   .arg2 = fragment_length});
	/*
	 * After the call to the other world completes it must have finished
	 * reading its RX buffer, so it is ready for another message.
	 */
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Validates a call to donate, lend or share memory to the other world and then
 * updates the stage-2 page tables. Specifically, check if the message length
 * and number of memory region constituents match, and if the transition is
 * valid for the type of memory sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and the
 * other world VM, and copied the memory region descriptor from the sender's TX
 * buffer to a freshly allocated page from Hafnium's internal pool. The caller
 * must have also validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
static struct ffa_value ffa_memory_other_world_send(
	struct vm_locked from_locked, struct vm_locked to_locked,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length, uint32_t share_func, struct mpool *page_pool)
{
	struct ffa_value ret;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(from_locked, memory_region,
				       memory_share_length, fragment_length,
				       share_func);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fit in one message. */
		struct ffa_composite_memory_region *composite =
			ffa_memory_region_get_composite(memory_region, 0);
		struct ffa_memory_region_constituent *constituents =
			composite->constituents;
		struct mpool local_page_pool;
		uint32_t orig_from_mode;

		/*
		 * Use a local page pool so that we can roll back if necessary.
		 */
		mpool_init_with_fallback(&local_page_pool, page_pool);

		ret = ffa_send_check_update(
			from_locked, &constituents,
			&composite->constituent_count, 1, share_func,
			memory_region->receivers, memory_region->receiver_count,
			&local_page_pool,
			memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
			&orig_from_mode);
		if (ret.func != FFA_SUCCESS_32) {
			mpool_fini(&local_page_pool);
			goto out;
		}

		/* Forward memory send message on to other world. */
		ret = memory_send_other_world_forward(
			to_locked, from_locked.vm->id, share_func,
			memory_region, memory_share_length, fragment_length);

		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"Other world didn't successfully complete "
				"memory send operation; returned %#x (%d). "
				"Rolling back.\n",
				ret.func, ret.arg2);

			/*
			 * The other world failed to complete the send
			 * operation, so roll back the page table update for the
			 * VM. This can't fail because it won't try to allocate
			 * more memory than was freed into the `local_page_pool`
			 * by `ffa_send_check_update` in the initial update.
			 */
			CHECK(ffa_region_group_identity_map(
				from_locked, &constituents,
				&composite->constituent_count, 1,
				orig_from_mode, &local_page_pool, true));
		}

		mpool_fini(&local_page_pool);
	} else {
		struct share_states_locked share_states = share_states_lock();
		ffa_memory_handle_t handle;

		/*
		 * We need to wait for the rest of the fragments before we can
		 * check whether the transaction is valid and unmap the memory.
		 * Call the other world so it can do its initial validation and
		 * assign a handle, and allocate a share state to keep what we
		 * have so far.
		 */
		ret = memory_send_other_world_forward(
			to_locked, from_locked.vm->id, share_func,
			memory_region, memory_share_length, fragment_length);
		if (ret.func == FFA_ERROR_32) {
			goto out_unlock;
		} else if (ret.func != FFA_MEM_FRAG_RX_32) {
			dlog_warning(
				"Got %#x from other world in response to %#x "
				"for "
				"fragment with %d/%d, expected "
				"FFA_MEM_FRAG_RX.\n",
				ret.func, share_func, fragment_length,
				memory_share_length);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}
		handle = ffa_frag_handle(ret);
		if (ret.arg3 != fragment_length) {
			dlog_warning(
				"Got unexpected fragment offset %d for "
				"FFA_MEM_FRAG_RX from other world (expected "
				"%d).\n",
				ret.arg3, fragment_length);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}
		if (ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_warning(
				"Got unexpected sender ID %d for "
				"FFA_MEM_FRAG_RX from other world (expected "
				"%d).\n",
				ffa_frag_sender(ret), from_locked.vm->id);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}

		if (!allocate_share_state(share_states, share_func,
					  memory_region, fragment_length,
					  handle, NULL)) {
			dlog_verbose("Failed to allocate share state.\n");
			ret = ffa_error(FFA_NO_MEMORY);
			goto out_unlock;
		}
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	out_unlock:
		share_states_unlock(&share_states);
	}

out:
	if (memory_region != NULL) {
		mpool_free(page_pool, memory_region);
	}
	dump_share_states();
	return ret;
}

struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool)
{
	struct vm *to;
	struct ffa_value ret;

	to = vm_find(HF_OTHER_WORLD_ID);

	/*
	 * The 'to' VM lock is only needed in the case that it is the
	 * TEE VM.
	 */
	struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

	/* Check if the `to` VM has the mailbox busy. */
	if (vm_is_mailbox_busy(vm_to_from_lock.vm1)) {
		dlog_verbose("The other world VM has a message. %x\n",
			     vm_to_from_lock.vm1.vm->id);
		ret = ffa_error(FFA_BUSY);
	} else {
		ret = ffa_memory_other_world_send(
			vm_to_from_lock.vm2, vm_to_from_lock.vm1,
			*memory_region, length, fragment_length, share_func,
			page_pool);
		/*
		 * ffa_other_world_memory_send takes ownership of the
		 * memory_region, so make sure we don't free it.
		 */
		*memory_region = NULL;
	}

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

/**
 * Reclaims the given memory from the other world. To do this space is first
 * reserved in the <to> VM's page table, then the reclaim request is sent on to
 * the other world. then (if that is successful) the memory is mapped back into
 * the <to> VM's page table.
 *
 * This function requires the calling context to hold the <to> lock.
 *
 * Returns:
 *  In case of error, one of the following values is returned:
 *   1) FFA_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   2) FFA_NO_MEMORY - Hafnium did not have sufficient memory to complete
 *     the request.
 *  Success is indicated by FFA_SUCCESS.
 */
static struct ffa_value ffa_other_world_reclaim_check_update(
	struct vm_locked to_locked, ffa_memory_handle_t handle,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes, bool clear,
	struct mpool *page_pool)
{
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;
	ffa_memory_region_flags_t other_world_flags;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	if (!is_aligned(constituents, 8)) {
		dlog_verbose("Constituents not aligned.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	ret = ffa_retrieve_check_transition(to_locked, FFA_MEM_RECLAIM_32,
					    &constituents, &constituent_count,
					    1, memory_to_attributes, &to_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition.\n");
		return ret;
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if the
	 * clear fails.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/*
	 * First reserve all required memory for the new page table entries in
	 * the recipient page tables without committing, to make sure the entire
	 * operation will succeed without exhausting the page pool.
	 */
	if (!ffa_region_group_identity_map(to_locked, &constituents,
					   &constituent_count, 1, to_mode,
					   page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		dlog_verbose(
			"Insufficient memory to update recipient page "
			"table.\n");
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Forward the request to the other world and see what happens.
	 */
	other_world_flags = 0;
	if (clear) {
		other_world_flags |= FFA_MEMORY_REGION_FLAG_CLEAR;
	}
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_RECLAIM_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = other_world_flags});

	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose(
			"Got %#x (%d) from other world in response to "
			"FFA_MEM_RECLAIM, "
			"expected FFA_SUCCESS.\n",
			ret.func, ret.arg2);
		goto out;
	}

	/*
	 * The other world was happy with it, so complete the reclaim by mapping
	 * the memory into the recipient. This won't allocate because the
	 * transaction was already prepared above, so it doesn't need to use the
	 * `local_page_pool`.
	 */
	CHECK(ffa_region_group_identity_map(to_locked, &constituents,
					    &constituent_count, 1, to_mode,
					    page_pool, true));

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was an
	 * error) or merging entries into blocks where possible (on success).
	 */
	vm_ptable_defrag(to_locked, page_pool);

	return ret;
}

static struct ffa_value plat_ffa_hyp_memory_retrieve(
	struct vm_locked to_locked, struct vm_locked from_locked,
	ffa_memory_handle_t handle, struct ffa_memory_region **memory_region)
{
	uint32_t request_length = ffa_memory_lender_retrieve_request_init(
		from_locked.vm->mailbox.recv, handle, to_locked.vm->id);
	struct ffa_value other_world_ret;
	uint32_t length;
	uint32_t fragment_length;
	uint32_t fragment_offset;

	CHECK(request_length <= HF_MAILBOX_SIZE);
	CHECK(from_locked.vm->id == HF_OTHER_WORLD_ID);

	/* Retrieve memory region information from the other world. */
	other_world_ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_RETRIEVE_REQ_32,
				   .arg1 = request_length,
				   .arg2 = request_length});
	if (other_world_ret.func == FFA_ERROR_32) {
		dlog_verbose("Got error %d from EL3.\n", other_world_ret.arg2);
		return other_world_ret;
	}
	if (other_world_ret.func != FFA_MEM_RETRIEVE_RESP_32) {
		dlog_verbose(
			"Got %#x from EL3, expected FFA_MEM_RETRIEVE_RESP.\n",
			other_world_ret.func);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	length = other_world_ret.arg1;
	fragment_length = other_world_ret.arg2;

	if (fragment_length > HF_MAILBOX_SIZE || fragment_length > length ||
	    length > sizeof(other_world_retrieve_buffer)) {
		dlog_verbose("Invalid fragment length %d/%d (max %d/%d).\n",
			     fragment_length, length, HF_MAILBOX_SIZE,
			     sizeof(other_world_retrieve_buffer));
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Copy the first fragment of the memory region descriptor to an
	 * internal buffer.
	 */
	memcpy_s(other_world_retrieve_buffer,
		 sizeof(other_world_retrieve_buffer),
		 from_locked.vm->mailbox.send, fragment_length);

	/* Fetch the remaining fragments into the same buffer. */
	fragment_offset = fragment_length;
	while (fragment_offset < length) {
		other_world_ret = arch_other_world_call(
			(struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					   .arg1 = (uint32_t)handle,
					   .arg2 = (uint32_t)(handle >> 32),
					   .arg3 = fragment_offset});
		if (other_world_ret.func != FFA_MEM_FRAG_TX_32) {
			dlog_verbose(
				"Got %#x (%d) from other world in response to "
				"FFA_MEM_FRAG_RX, expected FFA_MEM_FRAG_TX.\n",
				other_world_ret.func, other_world_ret.arg2);
			return other_world_ret;
		}
		if (ffa_frag_handle(other_world_ret) != handle) {
			dlog_verbose(
				"Got FFA_MEM_FRAG_TX for unexpected handle %#x "
				"in response to FFA_MEM_FRAG_RX for handle "
				"%#x.\n",
				ffa_frag_handle(other_world_ret), handle);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		if (ffa_frag_sender(other_world_ret) != 0) {
			dlog_verbose(
				"Got FFA_MEM_FRAG_TX with unexpected sender %d "
				"(expected 0).\n",
				ffa_frag_sender(other_world_ret));
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		fragment_length = other_world_ret.arg3;
		if (fragment_length > HF_MAILBOX_SIZE ||
		    fragment_offset + fragment_length > length) {
			dlog_verbose(
				"Invalid fragment length %d at offset %d (max "
				"%d).\n",
				fragment_length, fragment_offset,
				HF_MAILBOX_SIZE);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		memcpy_s(other_world_retrieve_buffer + fragment_offset,
			 sizeof(other_world_retrieve_buffer) - fragment_offset,
			 from_locked.vm->mailbox.send, fragment_length);

		fragment_offset += fragment_length;
	}

	*memory_region =
		(struct ffa_memory_region *)other_world_retrieve_buffer;

	return other_world_ret;
}

/**
 * Validates that the reclaim transition is allowed for the memory region with
 * the given handle which was previously shared with the SPMC. Tells the
 * SPMC to mark it as reclaimed, and updates the page table of the reclaiming
 * VM.
 *
 * To do this information about the memory region is first fetched from the
 * SPMC.
 */
static struct ffa_value ffa_memory_other_world_reclaim(
	struct vm_locked to_locked, struct vm_locked from_locked,
	ffa_memory_handle_t handle, ffa_memory_region_flags_t flags,
	struct mpool *page_pool)
{
	struct ffa_memory_region *memory_region = NULL;
	struct ffa_composite_memory_region *composite;
	uint32_t memory_to_attributes = MM_MODE_R | MM_MODE_W | MM_MODE_X;
	struct ffa_value hyp_retr_ret;

	/* Retrieve memory region from the SPMC. */
	hyp_retr_ret = plat_ffa_hyp_memory_retrieve(to_locked, from_locked,
						    handle, &memory_region);

	if (hyp_retr_ret.func == FFA_ERROR_32) {
		return hyp_retr_ret;
	}

	assert(memory_region != NULL);

	if (memory_region->receiver_count != 1) {
		/* Only one receiver supported by Hafnium for now. */
		dlog_verbose(
			"Multiple recipients not supported (got %d, expected "
			"1).\n",
			memory_region->receiver_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (memory_region->handle != handle) {
		dlog_verbose(
			"Got memory region handle %#x from other world but "
			"requested handle %#x.\n",
			memory_region->handle, handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* The original sender must match the caller. */
	if (to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %#x attempted to reclaim memory handle %#x "
			"originally sent by VM %#x.\n",
			to_locked.vm->id, handle, memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Validate that the reclaim transition is allowed for the given memory
	 * region, forward the request to the other world and then map the
	 * memory back into the caller's stage-2 page table.
	 */
	return ffa_other_world_reclaim_check_update(
		to_locked, handle, composite->constituents,
		composite->constituent_count, memory_to_attributes,
		flags & FFA_MEM_RECLAIM_CLEAR, page_pool);
}

struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm *from = vm_find(HF_TEE_VM_ID);
	struct two_vm_locked vm_to_from_lock;

	if (!ffa_tee_enabled) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RECLAIM.\n",
			     handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	vm_to_from_lock = vm_lock_both(to, from);

	ret = ffa_memory_other_world_reclaim(vm_to_from_lock.vm1,
					     vm_to_from_lock.vm2, handle, flags,
					     page_pool);

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}
