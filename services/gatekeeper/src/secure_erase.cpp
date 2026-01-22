#include "secure_erase.h"

#include <openssl/crypto.h>

namespace veritas::gatekeeper {

void SecureErase(std::string* data) {
  if (!data || data->empty()) {
    return;
  }
  OPENSSL_cleanse(data->data(), data->size());
  data->clear();
}

}  // namespace veritas::gatekeeper
