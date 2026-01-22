#pragma once

#include <string>

namespace veritas::gatekeeper {

class FakeSaltGenerator {
 public:
  explicit FakeSaltGenerator(std::string secret);

  std::string Generate(const std::string& login_username) const;

 private:
  std::string secret_;
};

}  // namespace veritas::gatekeeper
