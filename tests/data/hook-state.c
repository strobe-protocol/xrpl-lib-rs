#include "hookapi.h"

int64_t hook(uint32_t reserved) {
  TRACESTR("state_basic: Start.");

  // ACCOUNT: Hook Account
  uint8_t hook_acc[SFS_ACCOUNT];
  hook_account(SBUF(hook_acc));

  int64_t count[1];
  int64_t state_read_result = state(SBUF(count), hook_acc, SFS_ACCOUNT);
  if (state_read_result == DOESNT_EXIST) {
    count[0] = 12;
    if (state_set(SBUF(count), hook_acc, SFS_ACCOUNT) <= 0) {
      rollback(SBUF("state_basic: state_set failed"), -2);
    }
  } else {
    rollback(SBUF("state_basic: state failed"), -1);
  }

  TRACEVAR(count[0]) // <- count

  TRACESTR("state_basic: End.");
  accept(SBUF(count), 1);
  _g(1,
     1); // every hook needs to import guard function and use it at least once
  // unreachable
  return 0;
}
