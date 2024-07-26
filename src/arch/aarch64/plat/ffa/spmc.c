/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/gicv3.h"
#include "hf/arch/host_timer.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/plat/ffa/vm.h"
#include "hf/arch/sve.h"
#include "hf/arch/vmid_base.h"

#include "hf/api.h"
#include "hf/bits.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/hf_ipi.h"
#include "hf/interrupt_desc.h"
#include "hf/plat/interrupts.h"
#include "hf/timer_mgmt.h"
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
 * Drops the current interrupt priority and deactivate the given interrupt ID
 * for the calling vCPU.
 *
 * Returns 0 on success, or -1 otherwise.
 */
int64_t plat_ffa_interrupt_deactivate(uint32_t pint_id, uint32_t vint_id,
				      struct vcpu *current)
{
	struct vcpu_locked current_locked;
	uint32_t int_id;
	int ret = 0;

	current_locked = vcpu_lock(current);
	if (vint_id >= HF_NUM_INTIDS) {
		ret = -1;
		goto out;
	}

	/*
	 * Current implementation maps virtual interrupt to physical interrupt.
	 */
	if (pint_id != vint_id) {
		ret = -1;
		goto out;
	}

	/*
	 * A malicious SP could de-activate an interrupt that does not belong to
	 * it. Return error to indicate failure.
	 */
	if (!vcpu_interrupt_queue_peek(current_locked, &int_id)) {
		dlog_error("No virtual interrupt to be deactivated\n");
		ret = -1;
		goto out;
	}

	if (int_id != vint_id) {
		dlog_error("Unknown interrupt being deactivated %u\n", vint_id);
		ret = -1;
		goto out;
	}

	if (current->requires_deactivate_call) {
		/* There is no preempted vCPU to resume. */
		assert(current->preempted_vcpu == NULL);

		vcpu_secure_interrupt_complete(current_locked);
	}

	/*
	 * Now that the virtual interrupt has been serviced and deactivated,
	 * remove it from the queue, if it was pending.
	 */
	vcpu_interrupt_queue_pop(current_locked, &int_id);
	assert(vint_id == int_id);
out:
	vcpu_unlock(&current_locked);
	return ret;
}

static struct vcpu *plat_ffa_find_target_vcpu_secure_interrupt(
	struct vcpu *current, uint32_t interrupt_id)
{
	/*
	 * Find which VM/SP owns this interrupt. We then find the
	 * corresponding vCPU context for this CPU.
	 */
	for (ffa_vm_count_t index = 0; index < vm_get_count(); ++index) {
		struct vm *vm = vm_find_index(index);

		for (uint32_t j = 0; j < HF_NUM_INTIDS; j++) {
			struct interrupt_descriptor int_desc =
				vm->interrupt_desc[j];

			/*
			 * Interrupt descriptors are populated
			 * contiguously.
			 */
			if (!int_desc.valid) {
				break;
			}
			if (int_desc.interrupt_id == interrupt_id) {
				return api_ffa_get_vm_vcpu(vm, current);
			}
		}
	}

	return NULL;
}

static struct vcpu *plat_ffa_find_target_vcpu(struct vcpu *current,
					      uint32_t interrupt_id)
{
	struct vcpu *target_vcpu;

	switch (interrupt_id) {
	case HF_IPI_INTID:
		target_vcpu = hf_ipi_get_pending_target_vcpu(current->cpu);
		break;
	case ARM_EL1_VIRT_TIMER_PHYS_INT:
		/* Fall through */
	case ARM_EL1_PHYS_TIMER_PHYS_INT:
		panic("Timer interrupt not expected to fire: %u\n",
		      interrupt_id);
	default:
		target_vcpu = plat_ffa_find_target_vcpu_secure_interrupt(
			current, interrupt_id);
	}

	/* The target vCPU for a secure interrupt cannot be NULL. */
	CHECK(target_vcpu != NULL);

	return target_vcpu;
}

/*
 * Queue the pending virtual interrupt for target vcpu. Necessary fields
 * tracking the secure interrupt processing are set accordingly.
 */
static void plat_ffa_queue_vint(struct vcpu_locked target_vcpu_locked,
				uint32_t vint_id,
				struct vcpu_locked current_locked)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *preempted_vcpu = current_locked.vcpu;

	if (preempted_vcpu != NULL) {
		target_vcpu->preempted_vcpu = preempted_vcpu;
		preempted_vcpu->state = VCPU_STATE_PREEMPTED;
	}

	/* Queue the pending virtual interrupt for target vcpu. */
	if (!vcpu_interrupt_queue_push(target_vcpu_locked, vint_id)) {
		panic("Exhausted interrupt queue for vcpu of SP: %x\n",
		      target_vcpu->vm->id);
	}
}

/**
 * Handles the secure interrupt according to the target vCPU's state
 * in the case the owner of the interrupt is an S-EL0 partition.
 */
static struct vcpu *plat_ffa_signal_secure_interrupt_sel0(
	struct vcpu_locked current_locked,
	struct vcpu_locked target_vcpu_locked, uint32_t v_intid)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *next;

	/* Secure interrupt signaling and queuing for S-EL0 SP. */
	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING:
		if (target_vcpu->cpu == current_locked.vcpu->cpu) {
			struct ffa_value ret_interrupt =
				api_ffa_interrupt_return(v_intid);

			/* FF-A v1.1 EAC0 Table 8.1 case 1 and Table 12.10. */
			dlog_verbose("S-EL0: Secure interrupt signaled: %x\n",
				     target_vcpu->vm->id);

			vcpu_enter_secure_interrupt_rtm(target_vcpu_locked);
			plat_ffa_vcpu_queue_interrupts(target_vcpu_locked);

			vcpu_set_running(target_vcpu_locked, &ret_interrupt);

			/*
			 * If the execution was in NWd as well, set the vCPU
			 * in preempted state as well.
			 */
			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    current_locked);

			/* Switch to target vCPU responsible for this interrupt.
			 */
			next = target_vcpu;
		} else {
			dlog_verbose("S-EL0: Secure interrupt queued: %x\n",
				     target_vcpu->vm->id);
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			next = NULL;
			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    (struct vcpu_locked){.vcpu = NULL});
		}
		break;
	case VCPU_STATE_BLOCKED:
	case VCPU_STATE_PREEMPTED:
	case VCPU_STATE_RUNNING:
		dlog_verbose("S-EL0: Secure interrupt queued: %x\n",
			     target_vcpu->vm->id);
		/*
		 * The target vCPU cannot be resumed, SPMC resumes current
		 * vCPU.
		 */
		next = NULL;
		plat_ffa_queue_vint(target_vcpu_locked, v_intid,
				    (struct vcpu_locked){.vcpu = NULL});
		break;
	default:
		panic("Secure interrupt cannot be signaled to target SP\n");
		break;
	}

	return next;
}

/**
 * Handles the secure interrupt according to the target vCPU's state
 * in the case the owner of the interrupt is an S-EL1 partition.
 */
static struct vcpu *plat_ffa_signal_secure_interrupt_sel1(
	struct vcpu_locked current_locked,
	struct vcpu_locked target_vcpu_locked, uint32_t v_intid)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *next = NULL;

	/* Secure interrupt signaling and queuing for S-EL1 SP. */
	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING:
		if (target_vcpu->cpu == current_locked.vcpu->cpu) {
			struct ffa_value ret_interrupt =
				api_ffa_interrupt_return(v_intid);

			/* FF-A v1.1 EAC0 Table 8.2 case 1 and Table 12.10. */
			vcpu_enter_secure_interrupt_rtm(target_vcpu_locked);
			plat_ffa_vcpu_queue_interrupts(target_vcpu_locked);

			/*
			 * Ideally, we have to mask non-secure interrupts here
			 * since the spec mandates that SPMC should make sure
			 * SPMC scheduled call chain cannot be preempted by a
			 * non-secure interrupt. However, our current design
			 * takes care of it implicitly.
			 */
			vcpu_set_running(target_vcpu_locked, &ret_interrupt);

			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    current_locked);
			next = target_vcpu;
		} else {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
			dlog_verbose("S-EL1: Secure interrupt queued: %x\n",
				     target_vcpu->vm->id);
			next = NULL;
			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    (struct vcpu_locked){.vcpu = NULL});
		}
		break;
	case VCPU_STATE_BLOCKED:
		if (target_vcpu->cpu != current_locked.vcpu->cpu) {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
			next = NULL;
			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    (struct vcpu_locked){.vcpu = NULL});
		} else if (is_predecessor_in_call_chain(current_locked,
							target_vcpu_locked)) {
			struct ffa_value ret_interrupt =
				api_ffa_interrupt_return(0);

			/*
			 * If the target vCPU ran earlier in the same call
			 * chain as the current vCPU, SPMC leaves all
			 * intermediate execution contexts in blocked state and
			 * resumes the target vCPU for handling secure
			 * interrupt.
			 * Under the current design, there is only one possible
			 * scenario in which this could happen: both the
			 * preempted (i.e. current) and target vCPU are in the
			 * same NWd scheduled call chain and is described in the
			 * Scenario 1 of Table 8.4 in EAC0 spec.
			 */
			assert(current_locked.vcpu->scheduling_mode ==
			       NWD_MODE);
			assert(target_vcpu->scheduling_mode == NWD_MODE);

			/*
			 * The execution preempted the call chain that involved
			 * the targeted and the current SPs.
			 * The targetted SP is set running, whilst the
			 * preempted SP is set PREEMPTED.
			 */
			vcpu_set_running(target_vcpu_locked, &ret_interrupt);

			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    current_locked);

			next = target_vcpu;
		} else {
			/*
			 * The target vCPU cannot be resumed now because it is
			 * in BLOCKED state (it yielded CPU cycles using
			 * FFA_YIELD). SPMC queues the virtual interrupt and
			 * resumes the current vCPU which could belong to either
			 * a VM or a SP.
			 */
			next = NULL;
			plat_ffa_queue_vint(target_vcpu_locked, v_intid,
					    (struct vcpu_locked){.vcpu = NULL});
		}
		break;
	case VCPU_STATE_PREEMPTED:
		if (target_vcpu->cpu == current_locked.vcpu->cpu) {
			/*
			 * We do not resume a target vCPU that has been already
			 * pre-empted by an interrupt. Make the vIRQ pending for
			 * target SP(i.e., queue the interrupt) and continue to
			 * resume current vCPU. Refer to section 8.3.2.1 bullet
			 * 3 in the FF-A v1.1 EAC0 spec.
			 */

			if (current->vm->id == HF_OTHER_WORLD_ID) {
				/*
				 * The target vCPU must have been preempted by a
				 * non secure interrupt. It could not have been
				 * preempted by a secure interrupt as current
				 * SPMC implementation does not allow secure
				 * interrupt prioritization. Moreover, the
				 * target vCPU should have been in Normal World
				 * scheduled mode as SPMC scheduled mode call
				 * chain cannot be preempted by a non secure
				 * interrupt.
				 */
				CHECK(target_vcpu->scheduling_mode == NWD_MODE);
			}
		} else {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
		}

		next = NULL;
		plat_ffa_queue_vint(target_vcpu_locked, v_intid,
				    (struct vcpu_locked){.vcpu = NULL});

		break;
	case VCPU_STATE_RUNNING:
		if (current == target_vcpu) {
			/*
			 * This is the special scenario where the current
			 * running execution context also happens to be the
			 * target of the secure interrupt. In this case, it
			 * needs to signal completion of secure interrupt
			 * implicitly. Refer to the embedded comment in vcpu.h
			 * file for the description of this variable.
			 */

			current->requires_deactivate_call = true;
		} else {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
		}
		next = NULL;
		plat_ffa_queue_vint(target_vcpu_locked, v_intid,
				    (struct vcpu_locked){.vcpu = NULL});
		break;
	case VCPU_STATE_BLOCKED_INTERRUPT:
		/* WFI is no-op for SP. Fall through. */
	default:
		/*
		 * vCPU of Target SP cannot be in OFF/ABORTED state if it has
		 * to handle secure interrupt.
		 */
		panic("Secure interrupt cannot be signaled to target SP\n");
		break;
	}

	return next;
}

/**
 * Obtain the physical interrupt that triggered from the interrupt controller,
 * and inject the corresponding virtual interrupt to the target vCPU.
 * When PEs executing in the Normal World, and secure interrupts trigger,
 * execution is trapped into EL3. SPMD then routes the interrupt to SPMC
 * through FFA_INTERRUPT_32 ABI synchronously using eret conduit.
 */
void plat_ffa_handle_secure_interrupt(struct vcpu *current, struct vcpu **next)
{
	struct vcpu *target_vcpu;
	struct vcpu_locked target_vcpu_locked =
		(struct vcpu_locked){.vcpu = NULL};
	struct vcpu_locked current_locked;
	uint32_t intid;
	struct vm_locked target_vm_locked;
	uint32_t v_intid;

	/* Find pending interrupt id. This also activates the interrupt. */
	intid = plat_interrupts_get_pending_interrupt_id();
	v_intid = intid;

	switch (intid) {
	case ARM_SEL2_TIMER_PHYS_INT:
		/* Disable the S-EL2 physical timer */
		host_timer_disable();
		target_vcpu = timer_find_target_vcpu(current);

		if (target_vcpu != NULL) {
			v_intid = HF_VIRTUAL_TIMER_INTID;
			break;
		}
		/*
		 * It is possible for target_vcpu to be NULL in case of spurious
		 * timer interrupt. Fall through.
		 */
	case SPURIOUS_INTID_OTHER_WORLD:
		/*
		 * Spurious interrupt ID indicating that there are no pending
		 * interrupts to acknowledge. For such scenarios, resume the
		 * current vCPU.
		 */
		*next = NULL;
		return;
	default:
		target_vcpu = plat_ffa_find_target_vcpu(current, intid);
		break;
	}

	/*
	 * End the interrupt to drop the running priority. It also deactivates
	 * the physical interrupt. If not, the interrupt could trigger again
	 * after resuming current vCPU.
	 */
	plat_interrupts_end_of_interrupt(intid);

	target_vm_locked = vm_lock(target_vcpu->vm);

	if (target_vcpu == current) {
		current_locked = vcpu_lock(current);
		target_vcpu_locked = current_locked;
	} else {
		struct two_vcpu_locked vcpus_locked;
		/* Lock both vCPUs at once to avoid deadlock. */
		vcpus_locked = vcpu_lock_both(current, target_vcpu);
		current_locked = vcpus_locked.vcpu1;
		target_vcpu_locked = vcpus_locked.vcpu2;
	}

	/*
	 * A race condition can occur with the execution contexts belonging to
	 * an MP SP. An interrupt targeting the execution context on present
	 * core can trigger while the execution context of this SP on a
	 * different core is being aborted. In such scenario, the physical
	 * interrupts beloning to the aborted SP are disabled and the current
	 * execution context is resumed.
	 */
	if (target_vcpu->state == VCPU_STATE_ABORTED ||
	    atomic_load_explicit(&target_vcpu->vm->aborting,
				 memory_order_relaxed)) {
		/* Clear fields corresponding to secure interrupt handling. */
		vcpu_secure_interrupt_complete(target_vcpu_locked);
		plat_ffa_disable_vm_interrupts(target_vm_locked);

		/* Resume current vCPU. */
		*next = NULL;
	} else {
		/*
		 * SPMC has started handling a secure interrupt with a clean
		 * slate. This signal should be false unless there was a bug in
		 * source code. Hence, use assert rather than CHECK.
		 */
		assert(!target_vcpu->requires_deactivate_call);

		/* Set the interrupt pending in the target vCPU. */
		vcpu_interrupt_inject(target_vcpu_locked, v_intid);

		switch (intid) {
		case HF_IPI_INTID:
			if (hf_ipi_handle(target_vcpu_locked)) {
				*next = NULL;
				break;
			}
			/*
			 * Fall through in the case handling has not been fully
			 * completed.
			 */
		default:
			/*
			 * Either invoke the handler related to partitions from
			 * S-EL0 or from S-EL1.
			 */
			*next = target_vcpu_locked.vcpu->vm->el0_partition
					? plat_ffa_signal_secure_interrupt_sel0(
						  current_locked,
						  target_vcpu_locked, v_intid)
					: plat_ffa_signal_secure_interrupt_sel1(
						  current_locked,
						  target_vcpu_locked, v_intid);
		}
	}

	if (target_vcpu_locked.vcpu != NULL) {
		vcpu_unlock(&target_vcpu_locked);
	}

	vcpu_unlock(&current_locked);
	vm_unlock(&target_vm_locked);
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

bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked)
{
	struct vm *next_vm = target_locked.vcpu->vm;
	bool ret = false;

	/*
	 * Inject the NPI if:
	 * - The targeted VM ID is from this world (i.e. if it is an SP).
	 * - The partition has global pending notifications and an NPI hasn't
	 * been injected yet.
	 * - There are pending per-vCPU notifications in the next vCPU.
	 */
	if (vm_id_is_current_world(next_vm->id) &&
	    (vm_are_per_vcpu_notifications_pending(
		     receiver_locked, vcpu_index(target_locked.vcpu)) ||
	     (vm_are_global_notifications_pending(receiver_locked) &&
	      !vm_notifications_is_npi_injected(receiver_locked)))) {
		api_interrupt_inject_locked(target_locked,
					    HF_NOTIFICATION_PENDING_INTID,
					    current_locked, NULL);
		vm_notifications_set_npi_injected(receiver_locked, true);
		ret = true;
	}

	return ret;
}

/**
 * Returns FFA_SUCCESS as FFA_SECONDARY_EP_REGISTER is supported at the
 * secure virtual FF-A instance.
 */
bool plat_ffa_is_secondary_ep_register_supported(void)
{
	return true;
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

struct vcpu *plat_ffa_unwind_nwd_call_chain_interrupt(struct vcpu *current_vcpu)
{
	struct vcpu *next;
	struct two_vcpu_locked both_vcpu_locked;

	/*
	 * The action specified by SP in its manifest is ``Non-secure interrupt
	 * is signaled``. Refer to section 8.2.4 rules and guidelines bullet 4.
	 * Hence, the call chain starts unwinding. The current vCPU must have
	 * been a part of NWd scheduled call chain. Therefore, it is pre-empted
	 * and execution is either handed back to the normal world or to the
	 * previous SP vCPU in the call chain through the FFA_INTERRUPT ABI.
	 * The api_preempt() call is equivalent to calling
	 * api_switch_to_other_world for current vCPU passing FFA_INTERRUPT. The
	 * SP can be resumed later by FFA_RUN.
	 */
	CHECK(current_vcpu->scheduling_mode == NWD_MODE);
	assert(current_vcpu->call_chain.next_node == NULL);

	if (current_vcpu->call_chain.prev_node == NULL) {
		/* End of NWd scheduled call chain */
		return api_preempt(current_vcpu);
	}

	next = current_vcpu->call_chain.prev_node;
	CHECK(next != NULL);

	/*
	 * Lock both vCPUs. Strictly speaking, it may not be necessary since
	 * next is guaranteed to be in BLOCKED state as it is the predecessor of
	 * the current vCPU in the present call chain.
	 */
	both_vcpu_locked = vcpu_lock_both(current_vcpu, next);

	/* Removing a node from an existing call chain. */
	current_vcpu->call_chain.prev_node = NULL;
	current_vcpu->state = VCPU_STATE_PREEMPTED;

	/*
	 * SPMC applies the runtime model till when the vCPU transitions from
	 * running to waiting state. Moreover, the SP continues to remain in
	 * its CPU cycle allocation mode. Hence, rt_model and scheduling_mode
	 * are not changed here.
	 */
	assert(next->state == VCPU_STATE_BLOCKED);
	assert(next->call_chain.next_node == current_vcpu);

	next->call_chain.next_node = NULL;

	vcpu_set_running(both_vcpu_locked.vcpu2,
			 &(struct ffa_value){
				 .func = FFA_INTERRUPT_32,
				 .arg1 = ffa_vm_vcpu(current_vcpu->vm->id,
						     vcpu_index(current_vcpu)),
			 });

	sl_unlock(&next->lock);
	sl_unlock(&current_vcpu->lock);

	return next;
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

static void plat_ffa_enable_virtual_maintenance_interrupts(
	struct vcpu_locked current_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;
	struct vm *vm;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;
	vm = current->vm;

	if (plat_ffa_vm_managed_exit_supported(vm)) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_MANAGED_EXIT_INTID);
		/*
		 * SPMC decides the interrupt type for Managed exit signal based
		 * on the partition manifest.
		 */
		if (vm->me_signal_virq) {
			vcpu_virt_interrupt_set_type(interrupts,
						     HF_MANAGED_EXIT_INTID,
						     INTERRUPT_TYPE_IRQ);
		} else {
			vcpu_virt_interrupt_set_type(interrupts,
						     HF_MANAGED_EXIT_INTID,
						     INTERRUPT_TYPE_FIQ);
		}
	}

	if (vm->notifications.enabled) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_NOTIFICATION_PENDING_INTID);
	}
}

/**
 * Enable relevant virtual interrupts for Secure Partitions.
 * For all SPs, any applicable virtual maintenance interrupts are enabled.
 * Additionally, for S-EL0 partitions, all the interrupts declared in the
 * partition manifest are enabled at the virtual interrupt controller
 * interface early during the boot stage as an S-EL0 SP need not call
 * HF_INTERRUPT_ENABLE hypervisor ABI explicitly.
 */
void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;
	struct vm *vm;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;
	vm = current->vm;
	assert(vm == vm_locked.vm);

	if (vm->el0_partition) {
		for (uint32_t k = 0; k < VM_MANIFEST_MAX_INTERRUPTS; k++) {
			struct interrupt_descriptor int_desc;

			int_desc = vm_locked.vm->interrupt_desc[k];

			/* Interrupt descriptors are populated contiguously. */
			if (!int_desc.valid) {
				break;
			}
			vcpu_virt_interrupt_set_enabled(interrupts,
							int_desc.interrupt_id);
		}
	}

	plat_ffa_enable_virtual_maintenance_interrupts(current_locked);
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
 * Reconfigure the interrupt belonging to the current partition at runtime.
 * At present, this paravirtualized interface only allows the following
 * commands which signify what change is being requested by the current
 * partition:
 * - Change the target CPU of the interrupt.
 * - Change the security state of the interrupt.
 * - Enable or disable the physical interrupt.
 */
int64_t plat_ffa_interrupt_reconfigure(uint32_t int_id, uint32_t command,
				       uint32_t value, struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	int64_t ret = -1;
	struct interrupt_descriptor *int_desc = NULL;

	/*
	 * Lock VM to protect interrupt descriptor from being modified
	 * concurrently.
	 */
	vm_locked = vm_lock(vm);

	switch (command) {
	case INT_RECONFIGURE_TARGET_PE:
		/* Here, value represents the target PE index. */
		if (value >= MAX_CPUS) {
			dlog_verbose(
				"Illegal target PE index specified while "
				"reconfiguring interrupt %x\n",
				int_id);
			goto out_unlock;
		}

		/*
		 * An UP SP cannot reconfigure an interrupt to be targetted to
		 * any other physical CPU except the one it is currently
		 * running on.
		 */
		if (vm_is_up(vm) && value != cpu_index(current->cpu)) {
			dlog_verbose(
				"Illegal target PE index specified by current "
				"UP SP\n");
			goto out_unlock;
		}

		/* Configure the interrupt to be routed to a specific CPU. */
		int_desc = vm_interrupt_set_target_mpidr(
			vm_locked, int_id, cpu_find_index(value)->id);
		break;
	case INT_RECONFIGURE_SEC_STATE:
		/* Specify the new security state of the interrupt. */
		if (value != INT_DESC_SEC_STATE_NS &&
		    value != INT_DESC_SEC_STATE_S) {
			dlog_verbose(
				"Illegal value %x specified while "
				"reconfiguring interrupt %x\n",
				value, int_id);
			goto out_unlock;
		}
		int_desc = vm_interrupt_set_sec_state(vm_locked, int_id, value);
		break;
	case INT_RECONFIGURE_ENABLE:
		/* Enable or disable the interrupt. */
		if (value != INT_DISABLE && value != INT_ENABLE) {
			dlog_verbose(
				"Illegal value %x specified while "
				"reconfiguring interrupt %x\n",
				value, int_id);
			goto out_unlock;
		} else {
			int_desc = vm_interrupt_set_enable(vm_locked, int_id,
							   value == INT_ENABLE);
		}
		break;
	default:
		dlog_verbose("Interrupt reconfigure: Unsupported command %x\n",
			     command);
		goto out_unlock;
	}

	/* Check if the interrupt belongs to the current SP. */
	if (int_desc == NULL) {
		dlog_verbose("Interrupt %x does not belong to current SP\n",
			     int_id);
		goto out_unlock;
	}

	ret = 0;
	plat_interrupts_reconfigure_interrupt(*int_desc);

out_unlock:
	vm_unlock(&vm_locked);

	return ret;
}

/* Returns the virtual interrupt id to be handled by SP. */
uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked)
{
	uint32_t int_id;

	/*
	 * If there are any virtual interrupts in the queue, return the first
	 * entry. Else, return the pending interrupt from the bitmap.
	 */
	if (vcpu_interrupt_queue_peek(current_locked, &int_id)) {
		struct interrupts *interrupts;

		/*
		 * Mark the virtual interrupt as no longer pending and decrement
		 * the count.
		 */
		interrupts = &current_locked.vcpu->interrupts;
		vcpu_virt_interrupt_clear_pending(interrupts, int_id);
		vcpu_interrupt_count_decrement(current_locked, interrupts,
					       int_id);

		return int_id;
	}

	return api_interrupt_get(current_locked);
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
