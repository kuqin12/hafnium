/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/ffa.h"
#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * TODO: Some of these tests are duplicated between 'primary_only' and
 * 'primary_with_secondaries'. Move them to a common place consider running
 * them inside secondary VMs too.
 */

/**
 * Confirms the primary VM has the primary ID.
 */
TEST(hf_vm_get_id, primary_has_primary_id)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);
}

/**
 * Confirm it is an error when running a vCPU from the primary VM.
 */
TEST(ffa_run, cannot_run_primary)
{
	struct ffa_value res = ffa_run(HF_PRIMARY_VM_ID, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Confirm it is an error when running a vCPU from a non-existent secondary VM.
 */
TEST(ffa_run, cannot_run_absent_secondary)
{
	struct ffa_value res = ffa_run(1, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Yielding from the primary is a noop.
 */
TEST(ffa_yield, yield_is_noop_for_primary)
{
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}

/**
 * Releases the lock passed in.
 */
static void vm_cpu_entry(uintptr_t arg)
{
	/*
	 * The function prototype must match the entry function so we permit the
	 * int to pointer conversion.
	 */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	struct spinlock *lock = (struct spinlock *)arg;

	dlog("Second CPU started.\n");
	sl_unlock(lock);
}

/**
 * Confirm a new CPU can be started to execute in parallel.
 */
TEST(cpus, start)
{
	struct spinlock lock = SPINLOCK_INIT;

	/* Start secondary while holding lock. */
	sl_lock(&lock);

	/**
	 * `hftest_get_cpu_id` function makes the assumption that cpus are
	 * specified in the FDT in reverse order and does the conversion
	 * MAX_CPUS - index internally. Since legacy VMs do not follow this
	 * convention, index 7 is passed into `hftest_cpu_get_id`.
	 */
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(7), vm_cpu_entry,
				   (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock. */
	sl_lock(&lock);
}

/**
 * Releases the lock passed in and then stops the CPU.
 */
static void vm_cpu_entry_stop(uintptr_t arg)
{
	/*
	 * The function prototype must match the entry function so we permit the
	 * int to pointer conversion.
	 */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	struct spinlock *lock = (struct spinlock *)arg;

	dlog("Second CPU started.\n");
	sl_unlock(lock);

	dlog("Second CPU stopping.\n");
	arch_cpu_stop();

	FAIL("arch_cpu_stop() returned.");
}

/**
 * Confirm a secondary CPU can be stopped again.
 */
TEST(cpus, stop)
{
	struct spinlock lock = SPINLOCK_INIT;

	/**
	 * `hftest_get_cpu_id` function makes the assumption that cpus are
	 * specified in the FDT in reverse order and does the conversion
	 * MAX_CPUS - index internally. Since legacy VMs do not follow this
	 * convention, index 7 is passed into `hftest_cpu_get_id`.
	 */
	size_t secondary_cpu_index = 7;

	/* Start secondary while holding lock. */
	sl_lock(&lock);
	dlog("Starting second CPU.\n");
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(secondary_cpu_index),
				   vm_cpu_entry_stop, (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock after starting. */
	sl_lock(&lock);

	dlog("Waiting for second CPU to stop.\n");
	/* Wait a while for CPU to stop. */
	while (arch_cpu_status(hftest_get_cpu_id(secondary_cpu_index)) !=
	       POWER_STATUS_OFF) {
	}
	dlog("Second CPU stopped.\n");

	dlog("Starting second CPU again.\n");
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(secondary_cpu_index),
				   vm_cpu_entry_stop, (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock after starting. */
	sl_lock(&lock);

	dlog("Waiting for second CPU to stop.\n");
	/* Wait a while for CPU to stop. */
	while (arch_cpu_status(hftest_get_cpu_id(secondary_cpu_index)) !=
	       POWER_STATUS_OFF) {
	}
	dlog("Second CPU stopped.\n");
}

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/** Ensures that the Hafnium FF-A version is reported as expected. */
TEST(ffa, ffa_version)
{
	const uint16_t major_revision = 1;
	const uint16_t minor_revision = 2;
	const uint32_t current_version =
		(int32_t)MAKE_FFA_VERSION(major_revision, minor_revision);
	const int32_t older_compatible_version_0 = MAKE_FFA_VERSION(1, 0);
	const int32_t older_compatible_version_1 = MAKE_FFA_VERSION(1, 1);

	EXPECT_EQ(ffa_version(current_version), current_version);
	EXPECT_EQ(ffa_version(older_compatible_version_0), current_version);
	EXPECT_EQ(ffa_version(older_compatible_version_1), current_version);
	EXPECT_EQ((int32_t)ffa_version(0x0), FFA_NOT_SUPPORTED);
	EXPECT_EQ((int32_t)ffa_version(0x1), FFA_NOT_SUPPORTED);
	EXPECT_EQ((int32_t)ffa_version(0x10003), FFA_NOT_SUPPORTED);
	EXPECT_EQ((int32_t)ffa_version(0xffff), FFA_NOT_SUPPORTED);
	EXPECT_EQ((int32_t)ffa_version(0xfffffff), FFA_NOT_SUPPORTED);
}

/** Ensures that an invalid call to FFA_VERSION gets an error back. */
TEST(ffa, ffa_version_invalid)
{
	int32_t ret = (int32_t)ffa_version(0x80000000);

	EXPECT_EQ(ret, FFA_NOT_SUPPORTED);
}

/** Ensures that FFA_FEATURES is reporting the expected interfaces. */
TEST(ffa, ffa_features)
{
	struct ffa_value ret;

	ret = ffa_features(FFA_ERROR_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_SUCCESS_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_INTERRUPT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_VERSION_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_FEATURES_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RX_RELEASE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_MAP_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_UNMAP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_PARTITION_INFO_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_ID_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_POLL_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_YIELD_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RUN_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_DONATE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_LEND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_SHARE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features_with_input_property(
		FFA_MEM_RETRIEVE_REQ_32,
		FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RETRIEVE_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RELINQUISH_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RECLAIM_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_FRAG_TX_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_FRAG_RX_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
TEST(ffa, ffa_v_1_1_features)
{
	struct ffa_value ret;
	ret = ffa_features(FFA_MEM_PERM_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_SET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_GET_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_SET_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND2_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}
#endif

#if (MAKE_FFA_VERSION(1, 2) <= FFA_VERSION_COMPILED)
TEST(ffa, ffa_v_1_2_features)
{
	struct ffa_value ret;

	ret = ffa_features(FFA_CONSOLE_LOG_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_CONSOLE_LOG_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_PARTITION_INFO_GET_REGS_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ2_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}
#endif

/**
 * Ensures that FFA_FEATURES returns not supported for a bogus FID or
 * currently non-implemented interfaces.
 */
TEST(ffa, ffa_features_not_supported)
{
	struct ffa_value ret;

	ret = ffa_features(0);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(0x84000000);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);
}

/**
 * Test that floating-point operations work in the primary VM.
 */
TEST(fp, fp)
{
	/*
	 * Get some numbers that the compiler can't tell are constants, so it
	 * can't optimise them away.
	 */
	ffa_id_t ai = hf_vm_get_id();
	ffa_id_t bi = hf_vm_get_id();
	double a = ai;
	double b = bi;
	double result = a * b * 8.0;
	dlog("a: %d\n", ai);
	dlog("b: %d\n", bi);
	dlog("a * b * 1.0: %d\n", (int)result);
	EXPECT_TRUE(a == 1.0);
	EXPECT_TRUE(b == 1.0);
	EXPECT_TRUE(result == 8.0);
}
