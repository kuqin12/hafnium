/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/gicv3.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/plat/ffa/vm.h"
#include "hf/arch/sve.h"

#include "hf/api.h"
#include "hf/bits.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/plat/interrupts.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

#include "./spmc/vm.h"

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (SPMC)\n");
}

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	(void)tee_enabled;
}

void plat_ffa_init(struct mpool *ppool)
{
	arch_ffa_init();
	plat_ffa_vm_init(ppool);
}

bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

	return false;
}

static bool is_predecessor_in_call_chain(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked)
{
	struct vcpu *prev_node;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *target = target_locked.vcpu;

	assert(current != NULL);
	assert(target != NULL);

	prev_node = current->call_chain.prev_node;

	while (prev_node != NULL) {
		if (prev_node == target) {
			return true;
		}

		/* The target vCPU is not it's immediate predecessor. */
		prev_node = prev_node->call_chain.prev_node;
	}

	/* Search terminated. Reached start of call chain. */
	return false;
}

/**
 * Validates the Runtime model for FFA_RUN. Refer to section 7.2 of the FF-A
 * v1.1 EAC0 spec.
 */
static bool plat_ffa_check_rtm_ffa_run(struct vcpu_locked current_locked,
				       struct vcpu_locked locked_vcpu,
				       uint32_t func,
				       enum vcpu_state *next_state)
{
	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		/* Fall through. */
	case FFA_RUN_32: {
		/* Rules 1,2 section 7.2 EAC0 spec. */
		if (is_predecessor_in_call_chain(current_locked, locked_vcpu)) {
			return false;
		}
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 4 section 7.2 EAC0 spec. Fall through. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_YIELD_32:
		/* Rule 5 section 7.2 EAC0 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 3 section 7.2 EAC0 spec. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for FFA_MSG_SEND_DIRECT_REQ and
 * FFA_MSG_SEND_DIRECT_REQ2. Refer to section 8.3 of the FF-A
 * v1.2 spec.
 */
static bool plat_ffa_check_rtm_ffa_dir_req(struct vcpu_locked current_locked,
					   struct vcpu_locked locked_vcpu,
					   ffa_id_t receiver_vm_id,
					   uint32_t func,
					   enum vcpu_state *next_state)
{
	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		/* Fall through. */
	case FFA_RUN_32: {
		/* Rules 1,2. */
		if (is_predecessor_in_call_chain(current_locked, locked_vcpu)) {
			return false;
		}

		*next_state = VCPU_STATE_BLOCKED;
		return true;
	}
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32: {
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 3. */
		if (current_locked.vcpu->direct_request_origin.vm_id ==
		    receiver_vm_id) {
			*next_state = VCPU_STATE_WAITING;
			return true;
		}

		return false;
	}
	case FFA_YIELD_32:
		/* Rule 3, section 8.3 of FF-A v1.2 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Rule 4. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for Secure interrupt handling. Refer to section
 * 8.4 of the FF-A v1.2 ALP0 spec.
 */
static bool plat_ffa_check_rtm_sec_interrupt(struct vcpu_locked current_locked,
					     struct vcpu_locked locked_vcpu,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *vcpu = locked_vcpu.vcpu;

	CHECK(current->scheduling_mode == SPMC_MODE);

	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		/* Rule 3. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_RUN_32: {
		/* Rule 6. */
		if (vcpu->state == VCPU_STATE_PREEMPTED) {
			*next_state = VCPU_STATE_BLOCKED;
			return true;
		}

		return false;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 2. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_YIELD_32:
		/* Rule 3, section 8.4 of FF-A v1.2 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 5. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for SP initialization. Refer to section
 * 8.3 of the FF-A v1.2 ALP0 spec.
 */
static bool plat_ffa_check_rtm_sp_init(struct vcpu_locked locked_vcpu,
				       uint32_t func,
				       enum vcpu_state *next_state)
{
	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64: {
		struct vcpu *vcpu = locked_vcpu.vcpu;

		assert(vcpu != NULL);
		/* Rule 1. */
		if (vcpu->rt_model != RTM_SP_INIT) {
			*next_state = VCPU_STATE_BLOCKED;
			return true;
		}

		return false;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 2. Fall through. */
	case FFA_ERROR_32:
		/* Rule 3. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_YIELD_32:
		/* Rule 4. Fall through. */
	case FFA_RUN_32:
		/* Rule 6. Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 5. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Check if the runtime model (state machine) of the current SP supports the
 * given FF-A ABI invocation. If yes, next_state represents the state to which
 * the current vcpu would transition upon the FF-A ABI invocation as determined
 * by the Partition runtime model.
 */
bool plat_ffa_check_runtime_state_transition(struct vcpu_locked current_locked,
					     ffa_id_t vm_id,
					     ffa_id_t receiver_vm_id,
					     struct vcpu_locked locked_vcpu,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	bool allowed = false;
	struct vcpu *current = current_locked.vcpu;

	assert(current != NULL);

	/* Perform state transition checks only for Secure Partitions. */
	if (!vm_id_is_current_world(vm_id)) {
		return true;
	}

	switch (current->rt_model) {
	case RTM_FFA_RUN:
		allowed = plat_ffa_check_rtm_ffa_run(
			current_locked, locked_vcpu, func, next_state);
		break;
	case RTM_FFA_DIR_REQ:
		allowed = plat_ffa_check_rtm_ffa_dir_req(
			current_locked, locked_vcpu, receiver_vm_id, func,
			next_state);
		break;
	case RTM_SEC_INTERRUPT:
		allowed = plat_ffa_check_rtm_sec_interrupt(
			current_locked, locked_vcpu, func, next_state);
		break;
	case RTM_SP_INIT:
		allowed = plat_ffa_check_rtm_sp_init(locked_vcpu, func,
						     next_state);
		break;
	default:
		dlog_error(
			"Illegal Runtime Model specified by SP%x on CPU%zx\n",
			current->vm->id, cpu_index(current->cpu));
		allowed = false;
		break;
	}

	if (!allowed) {
		dlog_verbose("State transition denied\n");
	}

	return allowed;
}

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id)
{
	return (vm_id >= EL3_SPMD_LP_ID_START && vm_id <= EL3_SPMD_LP_ID_END);
}

/**
 * Enforce action of an SP in response to non-secure or other-secure interrupt
 * by changing the priority mask. Effectively, physical interrupts shall not
 * trigger which has the same effect as queueing interrupts.
 */
static void plat_ffa_vcpu_queue_interrupts(
	struct vcpu_locked receiver_vcpu_locked)
{
	struct vcpu *receiver_vcpu = receiver_vcpu_locked.vcpu;
	uint8_t current_priority;

	/* Save current value of priority mask. */
	current_priority = plat_interrupts_get_priority_mask();
	receiver_vcpu->prev_interrupt_priority = current_priority;

	if (receiver_vcpu->vm->other_s_interrupts_action ==
		    OTHER_S_INT_ACTION_QUEUED ||
	    receiver_vcpu->scheduling_mode == SPMC_MODE) {
		/*
		 * If secure interrupts not masked yet, mask them now. We could
		 * enter SPMC scheduled mode when an EL3 SPMD Logical partition
		 * sends a direct request, and we are making the IMPDEF choice
		 * to mask interrupts when such a situation occurs. This keeps
		 * design simple.
		 */
		if (current_priority > SWD_MASK_ALL_INT) {
			plat_interrupts_set_priority_mask(SWD_MASK_ALL_INT);
		}
	} else if (receiver_vcpu->vm->ns_interrupts_action ==
		   NS_ACTION_QUEUED) {
		/* If non secure interrupts not masked yet, mask them now. */
		if (current_priority > SWD_MASK_NS_INT) {
			plat_interrupts_set_priority_mask(SWD_MASK_NS_INT);
		}
	}
}

/**
 * If the interrupts were indeed masked by SPMC before an SP's vCPU was resumed,
 * restore the priority mask thereby allowing the interrupts to be delivered.
 */
static void plat_ffa_vcpu_allow_interrupts(struct vcpu *current)
{
	plat_interrupts_set_priority_mask(current->prev_interrupt_priority);
}

/**
 * Check if current VM can resume target VM using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu_locked current_locked,
			 ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			 struct ffa_value *run_ret, struct vcpu **next)
{
	/*
	 * Under the Partition runtime model specified in FF-A v1.1-Beta0 spec,
	 * SP can invoke FFA_RUN to resume target SP.
	 */
	struct vcpu *target_vcpu;
	struct vcpu *current = current_locked.vcpu;
	bool ret = true;
	struct vm *vm;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;

	vm = vm_find(target_vm_id);
	if (vm == NULL) {
		return false;
	}

	if (vm_is_mp(vm) && vm_is_mp(current->vm) &&
	    vcpu_idx != cpu_index(current->cpu)) {
		dlog_verbose("vcpu_idx (%d) != pcpu index (%zu)\n", vcpu_idx,
			     cpu_index(current->cpu));
		return false;
	}

	target_vcpu = api_ffa_get_vm_vcpu(vm, current);

	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, target_vcpu);
	current_locked = vcpus_locked.vcpu1;
	target_locked = vcpus_locked.vcpu2;

	/* Only the primary VM can turn ON a vCPU that is currently OFF. */
	if (!vm_is_primary(current->vm) &&
	    target_vcpu->state == VCPU_STATE_OFF) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	/*
	 * An SPx can resume another SPy only when SPy is in PREEMPTED or
	 * BLOCKED state.
	 */
	if (vm_id_is_current_world(current->vm->id) &&
	    vm_id_is_current_world(target_vm_id)) {
		/* Target SP must be in preempted or blocked state. */
		if (target_vcpu->state != VCPU_STATE_PREEMPTED &&
		    target_vcpu->state != VCPU_STATE_BLOCKED) {
			run_ret->arg2 = FFA_DENIED;
			ret = false;
			goto out;
		}
	}

	/* A SP cannot invoke FFA_RUN to resume a normal world VM. */
	if (!vm_id_is_current_world(target_vm_id)) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	vcpu_secondary_reset_and_start(target_locked, vm->secondary_ep, 0);

	if (vm_id_is_current_world(current->vm->id)) {
		/*
		 * Refer FF-A v1.1 EAC0 spec section 8.3.2.2.1
		 * Signaling an Other S-Int in blocked state
		 */
		if (current->preempted_vcpu != NULL) {
			/*
			 * After the target SP execution context has handled
			 * the interrupt, it uses the FFA_RUN ABI to resume
			 * the request due to which it had entered the blocked
			 * state earlier.
			 * Deny the state transition if the SP didnt perform the
			 * deactivation of the secure virtual interrupt.
			 */
			if (!vcpu_is_interrupt_queue_empty(current_locked)) {
				run_ret->arg2 = FFA_DENIED;
				ret = false;
				goto out;
			}

			/*
			 * Refer Figure 8.13 Scenario 1: Implementation choice:
			 * SPMC left all intermediate SP execution contexts in
			 * blocked state. Hence, SPMC now bypasses the
			 * intermediate these execution contexts and resumes the
			 * SP execution context that was originally preempted.
			 */
			*next = current->preempted_vcpu;
			if (target_vcpu != current->preempted_vcpu) {
				dlog_verbose("Skipping intermediate vCPUs\n");
			}
			/*
			 * This flag should not have been set by SPMC when it
			 * signaled the virtual interrupt to the SP while SP was
			 * in WAITING or BLOCKED states. Refer the embedded
			 * comment in vcpu.h file for further description.
			 */
			assert(!current->requires_deactivate_call);

			/*
			 * Clear fields corresponding to secure interrupt
			 * handling.
			 */
			vcpu_secure_interrupt_complete(current_locked);
		}
	}

	/* Check if a vCPU of SP is being resumed. */
	if (vm_id_is_current_world(target_vm_id)) {
		/*
		 * A call chain cannot span CPUs. The target vCPU can only be
		 * resumed by FFA_RUN on present CPU.
		 */
		if ((target_vcpu->call_chain.prev_node != NULL ||
		     target_vcpu->call_chain.next_node != NULL) &&
		    (target_vcpu->cpu != current->cpu)) {
			run_ret->arg2 = FFA_DENIED;
			ret = false;
			goto out;
		}

		if (!vcpu_is_interrupt_queue_empty(target_locked)) {
			/*
			 * Consider the following scenarios: a secure interrupt
			 * triggered in normal world and is targeted to an SP.
			 * Scenario A): The target SP's vCPU was preempted by a
			 *              non secure interrupt.
			 * Scenario B): The target SP's vCPU was in blocked
			 *              state after it yielded CPU cycles to
			 *              normal world using FFA_YIELD.
			 * In both the scenarios, SPMC would have injected a
			 * virtual interrupt and set the appropriate flags after
			 * de-activating the secure physical interrupt. SPMC did
			 * not resume the target vCPU at that moment.
			 */
			assert(target_vcpu->state == VCPU_STATE_PREEMPTED ||
			       target_vcpu->state == VCPU_STATE_BLOCKED);
			assert(vcpu_interrupt_count_get(target_locked) > 0);

			/*
			 * This check is to ensure the target SP vCPU could
			 * only be a part of NWd scheduled call chain. FF-A v1.1
			 * spec prohibits an SPMC scheduled call chain to be
			 * preempted by a non secure interrupt.
			 */
			CHECK(target_vcpu->scheduling_mode == NWD_MODE);
		}
	}

out:
	vcpu_unlock(&target_locked);
	return ret;
}

/**
 * SPMC scheduled call chain is completely unwound.
 */
static void plat_ffa_exit_spmc_schedule_mode(struct vcpu_locked current_locked)
{
	struct vcpu *current;

	current = current_locked.vcpu;
	assert(current->call_chain.next_node == NULL);
	CHECK(current->scheduling_mode == SPMC_MODE);

	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;
}

/**
 * A SP in running state could have been pre-empted by a secure interrupt. SPM
 * would switch the execution to the vCPU of target SP responsible for interupt
 * handling. Upon completion of interrupt handling, vCPU performs interrupt
 * signal completion through FFA_MSG_WAIT ABI (provided it was in waiting state
 * when interrupt was signaled).
 *
 * SPM then resumes the original SP that was initially pre-empted.
 */
static struct ffa_value plat_ffa_preempted_vcpu_resume(
	struct vcpu_locked current_locked, struct vcpu **next)
{
	struct ffa_value ffa_ret = (struct ffa_value){.func = FFA_MSG_WAIT_32};
	struct vcpu *target_vcpu;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;

	CHECK(current->preempted_vcpu != NULL);
	CHECK(current->preempted_vcpu->state == VCPU_STATE_PREEMPTED);

	target_vcpu = current->preempted_vcpu;
	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, target_vcpu);
	current_locked = vcpus_locked.vcpu1;
	target_locked = vcpus_locked.vcpu2;

	/* Reset the fields tracking secure interrupt processing. */
	vcpu_secure_interrupt_complete(current_locked);

	/* SPMC scheduled call chain is completely unwound. */
	plat_ffa_exit_spmc_schedule_mode(current_locked);
	assert(current->call_chain.prev_node == NULL);

	current->state = VCPU_STATE_WAITING;

	vcpu_set_running(target_locked, NULL);

	vcpu_unlock(&target_locked);

	/* Restore interrupt priority mask. */
	plat_ffa_vcpu_allow_interrupts(current);

	/* The pre-empted vCPU should be run. */
	*next = target_vcpu;

	return ffa_ret;
}

static bool sp_boot_next(struct vcpu_locked current_locked, struct vcpu **next)
{
	static bool spmc_booted = false;
	struct vcpu *vcpu_next = NULL;
	struct vcpu *current = current_locked.vcpu;

	if (spmc_booted) {
		return false;
	}

	assert(current->rt_model == RTM_SP_INIT);

	if (!atomic_load_explicit(&current->vm->aborting,
				  memory_order_relaxed)) {
		/* vCPU has just returned from successful initialization. */
		dlog_info("Initialized VM: %#x, boot_order: %u\n",
			  current->vm->id, current->vm->boot_order);
	}

	current->state = VCPU_STATE_WAITING;

	/*
	 * Pick next vCPU to be booted. Once all SPs have booted
	 * (next_boot is NULL), then return execution to NWd.
	 */
	vcpu_next = vcpu_get_next_boot(current);

	if (vcpu_next == NULL) {
		dlog_notice("Finished initializing all VMs.\n");
		spmc_booted = true;
		return false;
	}

	current->rt_model = RTM_NONE;
	current->scheduling_mode = NONE;

	CHECK(vcpu_next->rt_model == RTM_SP_INIT);
	arch_regs_reset(vcpu_next);
	vcpu_next->cpu = current->cpu;
	vcpu_next->state = VCPU_STATE_RUNNING;
	vcpu_next->regs_available = false;
	vcpu_set_phys_core_idx(vcpu_next);
	vcpu_set_boot_info_gp_reg(vcpu_next);

	*next = vcpu_next;

	return true;
}

/**
 * Run the vCPU in SPMC schedule mode under the runtime model for secure
 * interrupt handling.
 */
static void plat_ffa_run_in_sec_interrupt_rtm(
	struct vcpu_locked target_vcpu_locked)
{
	struct vcpu *target_vcpu;

	target_vcpu = target_vcpu_locked.vcpu;

	/* Mark the registers as unavailable now. */
	target_vcpu->regs_available = false;
	target_vcpu->scheduling_mode = SPMC_MODE;
	target_vcpu->rt_model = RTM_SEC_INTERRUPT;
	target_vcpu->state = VCPU_STATE_RUNNING;
	target_vcpu->requires_deactivate_call = false;
}

bool plat_ffa_intercept_call(struct vcpu_locked current_locked,
			     struct vcpu_locked next_locked,
			     struct ffa_value *signal_interrupt)
{
	uint32_t intid;

	/*
	 * Check if there are any pending virtual secure interrupts to be
	 * handled.
	 */
	if (vcpu_interrupt_queue_peek(current_locked, &intid)) {
		/*
		 * Prepare to signal virtual secure interrupt to S-EL0/S-EL1 SP
		 * in WAITING state. Refer to FF-A v1.2 Table 9.1 and Table 9.2
		 * case 1.
		 */
		*signal_interrupt = api_ffa_interrupt_return(intid);

		/*
		 * Prepare to resume this partition's vCPU in SPMC
		 * schedule mode to handle virtual secure interrupt.
		 */
		plat_ffa_run_in_sec_interrupt_rtm(current_locked);

		current_locked.vcpu->preempted_vcpu = next_locked.vcpu;
		next_locked.vcpu->state = VCPU_STATE_PREEMPTED;

		dlog_verbose("%s: Pending interrup, intercepting FF-A call.\n",
			     __func__);

		return true;
	}

	return false;
}

static struct ffa_value ffa_msg_wait_complete(struct vcpu_locked current_locked,
					      struct vcpu **next)
{
	struct vcpu *current = current_locked.vcpu;

	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;

	/* Relinquish control back to the NWd. */
	*next = api_switch_to_other_world(
		current_locked, (struct ffa_value){.func = FFA_MSG_WAIT_32},
		VCPU_STATE_WAITING);

	return api_ffa_interrupt_return(0);
}

/**
 * Deals with the common case of intercepting an FFA_MSG_WAIT call.
 */
static bool plat_ffa_msg_wait_intercept(struct vcpu_locked current_locked,
					struct vcpu **next,
					struct ffa_value *ffa_ret)
{
	struct two_vcpu_locked both_vcpu_locks;
	struct vcpu *current = current_locked.vcpu;
	bool ret = false;

	assert(next != NULL);
	assert(*next != NULL);

	vcpu_unlock(&current_locked);

	both_vcpu_locks = vcpu_lock_both(current, *next);

	/*
	 * Check if there are any pending secure virtual interrupts to
	 * be handled. The `next` should have a pointer to the current
	 * vCPU. Intercept call will set `ret` to FFA_INTERRUPT and the
	 * respective interrupt id.
	 */
	if (plat_ffa_intercept_call(both_vcpu_locks.vcpu1,
				    both_vcpu_locks.vcpu2, ffa_ret)) {
		*next = NULL;
		ret = true;
	}

	vcpu_unlock(&both_vcpu_locks.vcpu2);

	return ret;
}

/**
 * The invocation of FFA_MSG_WAIT at secure virtual FF-A instance is compliant
 * with FF-A v1.1 EAC0 specification. It only performs the state transition
 * from RUNNING to WAITING for the following Partition runtime models:
 * RTM_FFA_RUN, RTM_SEC_INTERRUPT, RTM_SP_INIT.
 */
struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu_locked current_locked,
					   struct vcpu **next)
{
	struct ffa_value ret = api_ffa_interrupt_return(0);
	struct vcpu *current = current_locked.vcpu;

	switch (current->rt_model) {
	case RTM_SP_INIT:
		if (!sp_boot_next(current_locked, next)) {
			ret = ffa_msg_wait_complete(current_locked, next);

			if (plat_ffa_msg_wait_intercept(current_locked, next,
							&ret)) {
			}
		}
		break;
	case RTM_SEC_INTERRUPT:
		/*
		 * Either resume the preempted SP or complete the FFA_MSG_WAIT.
		 */
		assert(current->preempted_vcpu != NULL);
		plat_ffa_preempted_vcpu_resume(current_locked, next);

		if (plat_ffa_msg_wait_intercept(current_locked, next, &ret)) {
			break;
		}

		/*
		 * If CPU cycles were allocated through FFA_RUN interface,
		 * allow the interrupts(if they were masked earlier) before
		 * returning control to NWd.
		 */
		plat_ffa_vcpu_allow_interrupts(current);
		break;
	case RTM_FFA_RUN:
		ret = ffa_msg_wait_complete(current_locked, next);

		if (plat_ffa_msg_wait_intercept(current_locked, next, &ret)) {
			break;
		}

		/*
		 * If CPU cycles were allocated through FFA_RUN interface,
		 * allow the interrupts(if they were masked earlier) before
		 * returning control to NWd.
		 */
		plat_ffa_vcpu_allow_interrupts(current);

		break;
	default:
		panic("%s: unexpected runtime model %x for [%x %x]",
		      current->rt_model, current->vm->id,
		      cpu_index(current->cpu));
	}

	vcpu_unlock(&current_locked);

	return ret;
}

/*
 * Initialize the scheduling mode and/or Partition Runtime model of the target
 * SP upon being resumed by an FFA_RUN ABI.
 */
void plat_ffa_init_schedule_mode_ffa_run(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked)
{
	struct vcpu *vcpu = target_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;

	/*
	 * Scenario 1 in Table 8.4; Therefore SPMC could be resuming a vCPU
	 * that was part of NWd scheduled mode.
	 */
	CHECK(vcpu->scheduling_mode != SPMC_MODE);

	/* Section 8.2.3 bullet 4.2 of spec FF-A v1.1 EAC0. */
	if (vcpu->state == VCPU_STATE_WAITING) {
		assert(vcpu->rt_model == RTM_SP_INIT ||
		       vcpu->rt_model == RTM_NONE);
		vcpu->rt_model = RTM_FFA_RUN;

		if (!vm_id_is_current_world(current->vm->id) ||
		    (current->scheduling_mode == NWD_MODE)) {
			vcpu->scheduling_mode = NWD_MODE;
		}
	} else {
		/* SP vCPU would have been pre-empted earlier or blocked. */
		CHECK(vcpu->state == VCPU_STATE_PREEMPTED ||
		      vcpu->state == VCPU_STATE_BLOCKED);
	}

	plat_ffa_vcpu_queue_interrupts(target_locked);
}

/*
 * Start winding the call chain or continue to wind the present one upon the
 * invocation of FFA_MSG_SEND_DIRECT_REQ or FFA_MSG_SEND_DIRECT_REQ2 (FF-A v1.2)
 * ABI.
 */
void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id)
{
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *receiver_vcpu = receiver_vcpu_locked.vcpu;

	CHECK(receiver_vcpu->scheduling_mode == NONE);
	CHECK(receiver_vcpu->call_chain.prev_node == NULL);
	CHECK(receiver_vcpu->call_chain.next_node == NULL);
	CHECK(receiver_vcpu->rt_model == RTM_NONE);

	receiver_vcpu->rt_model = RTM_FFA_DIR_REQ;

	if (!vm_id_is_current_world(sender_vm_id)) {
		/* Start of NWd scheduled call chain. */
		receiver_vcpu->scheduling_mode = NWD_MODE;
	} else if (plat_ffa_is_spmd_lp_id(sender_vm_id)) {
		receiver_vcpu->scheduling_mode = SPMC_MODE;
	} else {
		/* Adding a new node to an existing call chain. */
		vcpu_call_chain_extend(current_locked, receiver_vcpu_locked);
		receiver_vcpu->scheduling_mode = current->scheduling_mode;
	}
	plat_ffa_vcpu_queue_interrupts(receiver_vcpu_locked);
}

/*
 * Unwind the present call chain upon the invocation of
 * FFA_MSG_SEND_DIRECT_RESP ABI. The function also returns
 * the partition ID to which the caller must return to. In
 * case the call chain was started by an SPMD logical
 * partition direct message, at the end of the call chain,
 * we need to return other world's id so that the SPMC can
 * return to the SPMD.
 */
void plat_ffa_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked)
{
	struct vcpu *next = next_locked.vcpu;
	ffa_id_t receiver_vm_id = next->vm->id;
	struct vcpu *current = current_locked.vcpu;

	assert(current->call_chain.next_node == NULL);
	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;

	/* Allow interrupts if they were masked earlier. */
	plat_ffa_vcpu_allow_interrupts(current);

	if (!vm_id_is_current_world(receiver_vm_id)) {
		/* End of NWd scheduled call chain. */
		assert(current->call_chain.prev_node == NULL);
	} else {
		/* Removing a node from an existing call chain. */
		vcpu_call_chain_remove_node(current_locked, next_locked);
	}
}

struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id, uint32_t size,
				   struct vcpu *current, struct vcpu **next)
{
	(void)sender_vm_id;
	(void)receiver_vm_id;
	(void)size;
	(void)current;
	(void)next;

	return ffa_error(FFA_NOT_SUPPORTED);
}

/*
 * Prepare to yield execution back to the VM/SP that allocated CPU cycles and
 * move to BLOCKED state. If the CPU cycles were allocated to the current
 * execution context by the SPMC to handle secure virtual interrupt, then
 * FFA_YIELD invocation is essentially a no-op.
 */
struct ffa_value plat_ffa_yield_prepare(struct vcpu_locked current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high)
{
	struct ffa_value ret_args = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
		.arg2 = timeout_low,
		.arg3 = timeout_high,
	};

	switch (current->rt_model) {
	case RTM_FFA_DIR_REQ:
		assert(current->direct_request_origin.vm_id !=
		       HF_INVALID_VM_ID);
		if (current->call_chain.prev_node == NULL) {
			/*
			 * Relinquish cycles to the NWd VM that sent direct
			 * request message to the current SP.
			 */
			*next = api_switch_to_other_world(current_locked, ret,
							  VCPU_STATE_BLOCKED);
		} else {
			/*
			 * Relinquish cycles to the SP that sent direct request
			 * message to the current SP.
			 */
			*next = api_switch_to_vm(
				current_locked, ret, VCPU_STATE_BLOCKED,
				current->direct_request_origin.vm_id);
		}
		break;
	case RTM_SEC_INTERRUPT: {
		/*
		 * SPMC does not implement a scheduler needed to resume the
		 * current vCPU upon timeout expiration. Hence, SPMC makes the
		 * implementation defined choice to treat FFA_YIELD invocation
		 * as a no-op if the SP execution context is in the secure
		 * interrupt runtime model. This does not violate FF-A spec as
		 * the spec does not mandate timeout to be honored. Moreover,
		 * timeout specified by an endpoint is just a hint to the
		 * partition manager which allocated CPU cycles.
		 * Resume the current vCPU.
		 */
		*next = NULL;
		break;
	}
	default:
		CHECK(current->rt_model == RTM_FFA_RUN);
		*next = api_switch_to_primary(current_locked, ret,
					      VCPU_STATE_BLOCKED);
		break;
	}

	/*
	 * Before yielding CPU cycles, allow the interrupts(if they were
	 * masked earlier).
	 */
	if (*next != NULL) {
		plat_ffa_vcpu_allow_interrupts(current);
	}

	return ret_args;
}

/*
 * Handle FFA_ERROR_32 call according to the given error code.
 *
 * Error codes other than FFA_ABORTED, and cases of FFA_ABORTED not
 * in RTM_SP_INIT runtime model, not implemented. Refer to section 8.5
 * of FF-A 1.2 spec.
 */
struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code)
{
	struct vcpu_locked current_locked;
	struct vm_locked vm_locked;
	enum partition_runtime_model rt_model;
	struct ffa_value ret = api_ffa_interrupt_return(0);

	vm_locked = vm_lock(current->vm);
	current_locked = vcpu_lock(current);
	rt_model = current_locked.vcpu->rt_model;

	if (error_code == FFA_ABORTED && rt_model == RTM_SP_INIT) {
		dlog_error("Aborting SP %#x from vCPU %u\n", current->vm->id,
			   vcpu_index(current));

		atomic_store_explicit(&current->vm->aborting, true,
				      memory_order_relaxed);

		plat_ffa_free_vm_resources(vm_locked);

		if (sp_boot_next(current_locked, next)) {
			goto out;
		}

		/*
		 * Relinquish control back to the NWd. Return
		 * FFA_MSG_WAIT_32 to indicate to SPMD that SPMC
		 * has successfully finished initialization.
		 */
		*next = api_switch_to_other_world(
			current_locked,
			(struct ffa_value){.func = FFA_MSG_WAIT_32},
			VCPU_STATE_ABORTED);

		goto out;
	}
	ret = ffa_error(FFA_NOT_SUPPORTED);
out:
	vcpu_unlock(&current_locked);
	vm_unlock(&vm_locked);
	return ret;
}

/**
 * Check that the arguments to a VM availability message are correct.
 * Returns `FFA_SUCCESS_32` if the arguments are correct.
 * Returns `FFA_INVALID_PARAMETERS` if:
 * - the receiver is not a valid VM
 * - the receiver has not subscribed to the message type
 */
static struct ffa_value check_vm_availability_message(struct ffa_value args)
{
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);
	enum ffa_framework_msg_func func = ffa_framework_msg_func(args);
	ffa_id_t receiver_id = ffa_receiver(args);
	struct vm_locked receiver = vm_find_locked(receiver_id);

	if (receiver.vm == NULL) {
		dlog_verbose(
			"VM availability messaging: could not find SP %#x\n",
			receiver_id);
		return ret;
	}

	/* only valid if receiver has subscribed */
	if (func == FFA_FRAMEWORK_MSG_VM_CREATION_REQ &&
	    !receiver.vm->vm_availability_messages.vm_created) {
		dlog_verbose(
			"VM availability messaging: SP %#x is not subscribed "
			"to VM creation messages\n",
			receiver_id);
		goto out;
	}

	if (func == FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ &&
	    !receiver.vm->vm_availability_messages.vm_destroyed) {
		dlog_verbose(
			"VM availability messaging: SP %#x is not subscribed "
			"to VM destruction messages\n",
			receiver_id);
		goto out;
	}

	if (ANY_BITS_SET(args.arg5, FFA_VM_AVAILABILITY_MESSAGE_SBZ_HI,
			 FFA_VM_AVAILABILITY_MESSAGE_SBZ_LO)) {
		dlog_warning(
			"VM availability messaging: bits[%u:%u] of w5 are "
			"reserved and should be zero (w5=%#lx)\n",
			FFA_VM_AVAILABILITY_MESSAGE_SBZ_HI,
			FFA_VM_AVAILABILITY_MESSAGE_SBZ_LO, args.arg5);
	}

	if (args.arg6 != 0) {
		dlog_warning(
			"VM availability messaging: w6 is reserved and should "
			"be zero (w6=%#lx)\n",
			args.arg6);
	}

	if (args.arg7 != 0) {
		dlog_warning(
			"VM availability messaging: w7 is reserved and should "
			"be zero (w7=%#lx)\n",
			args.arg7);
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:

	vm_unlock(&receiver);
	return ret;
}

/**
 * Handle framework messages: in particular, check VM availability messages are
 * valid.
 */
bool plat_ffa_handle_framework_msg(struct ffa_value args, struct ffa_value *ret)
{
	enum ffa_framework_msg_func func = ffa_framework_msg_func(args);

	switch (func) {
	case FFA_FRAMEWORK_MSG_VM_CREATION_REQ:
	case FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ:
		*ret = check_vm_availability_message(args);
		if (ret->func != FFA_SUCCESS_32) {
			return true;
		}
		break;
	default:
		break;
	}

	return false;
}
