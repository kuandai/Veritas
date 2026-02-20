#pragma once

#include <grpcpp/support/status.h>

#include <string_view>

namespace veritas::notary {

void LogNotaryEvent(std::string_view action,
                    const grpc::Status& status,
                    std::string_view detail);

}  // namespace veritas::notary
