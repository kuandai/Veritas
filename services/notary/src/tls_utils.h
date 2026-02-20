#pragma once

#include <string>

namespace veritas::notary {

void ValidateServerTlsCredentials(const std::string& cert_pem,
                                  const std::string& key_pem,
                                  const std::string& ca_bundle_pem);

}  // namespace veritas::notary
