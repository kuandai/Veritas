#pragma once

#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>

#include <sodium.h>

namespace veritas::auth {

struct SecureBufferOps {
  void* (*alloc)(std::size_t) = &sodium_malloc;
  void (*free_fn)(void*) = &sodium_free;
  int (*mlock_fn)(void*, std::size_t) = &sodium_mlock;
  int (*munlock_fn)(void*, std::size_t) = &sodium_munlock;
  void (*memzero_fn)(void*, std::size_t) = &sodium_memzero;
};

class SecureBuffer {
 public:
  explicit SecureBuffer(std::string_view value,
                        SecureBufferOps ops = SecureBufferOps{})
      : ops_(ops), size_(value.size()) {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium initialization failed");
    }
    const std::size_t alloc_size = size_ == 0 ? 1 : size_;
    if (!ops_.alloc) {
      throw std::runtime_error("secure allocator is not configured");
    }
    data_ = static_cast<unsigned char*>(ops_.alloc(alloc_size));
    if (!data_) {
      throw std::bad_alloc();
    }
    if (size_ > 0) {
      std::memcpy(data_, value.data(), size_);
      lock_attempted_ = true;
      if (ops_.mlock_fn && ops_.mlock_fn(data_, size_) == 0) {
        locked_ = true;
      }
    }
  }
  ~SecureBuffer() { Release(); }

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  SecureBuffer(SecureBuffer&& other) noexcept { *this = std::move(other); }
  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      Release();
      ops_ = other.ops_;
      data_ = other.data_;
      size_ = other.size_;
      locked_ = other.locked_;
      lock_attempted_ = other.lock_attempted_;
      other.data_ = nullptr;
      other.size_ = 0;
      other.locked_ = false;
      other.lock_attempted_ = false;
    }
    return *this;
  }

  std::string_view view() const {
    if (!data_ || size_ == 0) {
      return {};
    }
    return std::string_view(reinterpret_cast<const char*>(data_), size_);
  }

  bool is_locked() const { return locked_; }
  bool lock_attempted() const { return lock_attempted_; }

  void Scrub() {
    if (data_ && size_ > 0 && ops_.memzero_fn) {
      ops_.memzero_fn(data_, size_);
    }
  }

 private:
  void Release() {
    if (!data_) {
      return;
    }
    if (size_ > 0 && ops_.memzero_fn) {
      ops_.memzero_fn(data_, size_);
    }
    if (locked_ && size_ > 0 && ops_.munlock_fn) {
      ops_.munlock_fn(data_, size_);
    }
    if (ops_.free_fn) {
      ops_.free_fn(data_);
    }
    data_ = nullptr;
    size_ = 0;
    locked_ = false;
    lock_attempted_ = false;
  }

  SecureBufferOps ops_{};
  unsigned char* data_ = nullptr;
  std::size_t size_ = 0;
  bool locked_ = false;
  bool lock_attempted_ = false;
};

using SecureString = SecureBuffer;

}  // namespace veritas::auth
