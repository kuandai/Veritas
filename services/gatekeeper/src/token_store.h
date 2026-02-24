#pragma once

#include "veritas/shared/token_store.h"

namespace veritas::gatekeeper {

using TokenRecord = veritas::shared::TokenRecord;
using TokenState = veritas::shared::TokenState;
using TokenStatus = veritas::shared::TokenStatus;
using TokenStore = veritas::shared::TokenStore;
using TokenStoreError = veritas::shared::TokenStoreError;
using RedisConnectionConfig = veritas::shared::RedisConnectionConfig;
using InMemoryTokenStore = veritas::shared::InMemoryTokenStore;
using RedisTokenStore = veritas::shared::RedisTokenStore;
using veritas::shared::ParseRedisConnectionConfig;

}  // namespace veritas::gatekeeper
