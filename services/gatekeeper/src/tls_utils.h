#pragma once

#include <string>

namespace veritas::gatekeeper {

void ValidateTlsCredentials(const std::string& cert_chain_pem,
                            const std::string& key_pem,
                            const std::string& ca_bundle_pem);

}  // namespace veritas::gatekeeper
