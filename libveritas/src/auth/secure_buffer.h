#pragma once

#include <string>
#include <string_view>

#include <sodium.h>

namespace veritas::auth {

class SecureString {
 public:
  explicit SecureString(std::string value) : value_(std::move(value)) {}
  ~SecureString() { Scrub(); }

  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;

  SecureString(SecureString&& other) noexcept : value_(std::move(other.value_)) {}
  SecureString& operator=(SecureString&& other) noexcept {
    if (this != &other) {
      Scrub();
      value_ = std::move(other.value_);
    }
    return *this;
  }

  std::string_view view() const { return value_; }
  void Scrub() {
    if (!value_.empty()) {
      sodium_memzero(value_.data(), value_.size());
    }
  }

 private:
  std::string value_;
};

}  // namespace veritas::auth
