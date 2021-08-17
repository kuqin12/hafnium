/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/partition_services.h"

/**
 * Message loop to add tests to be controlled by the control partition(depends
 * on the test set-up).
 * TODO: Extend/refactor function below to cater for other tests, in addition to
 * the current simple 'echo' via direct message.
 */
noreturn void test_main_sp(void)
{
	struct ffa_value res;

	while (1) {
		res = ffa_msg_wait();

		HFTEST_LOG("Received direct message request");
		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);

		switch (res.arg3) {
		case SP_ECHO_CMD:
			ffa_msg_send_direct_resp(
				ffa_receiver(res), ffa_sender(res), res.arg3,
				res.arg4, res.arg5, res.arg6, res.arg7);
			break;
		default:
			HFTEST_LOG_FAILURE();
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "0x%x is not a valid command id\n");
			abort();
		}
	}
}
