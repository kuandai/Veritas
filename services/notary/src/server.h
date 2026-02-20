#pragma once

#include <memory>
#include <string>

#include <grpcpp/server.h>

#include "config.h"
#include "notary_service.h"

namespace veritas::notary {

struct NotaryRuntime {
  std::unique_ptr<grpc::Server> server;
  std::string bound_addr;
};

NotaryRuntime StartNotaryServer(const NotaryConfig& config,
                                NotaryServiceImpl* service);

}  // namespace veritas::notary
