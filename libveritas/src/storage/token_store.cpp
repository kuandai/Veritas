#include "veritas/storage/token_store.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <system_error>
#include <vector>

#include <sodium.h>

#if __has_include(<libsecret/secret.h>)
#include <libsecret/secret.h>
#define VERITAS_HAS_LIBSECRET 1
#else
#define VERITAS_HAS_LIBSECRET 0
#endif

namespace veritas::storage {

namespace {

constexpr std::uint32_t kLegacyTokenStoreMagic = 0x56545331;     // "VTS1"
constexpr std::uint32_t kEncryptedTokenStoreMagic = 0x56545332;  // "VTS2"
constexpr std::size_t kMaxFieldBytes = 1 * 1024 * 1024;

void EnsureSodiumInitialized() {
  static std::once_flag once;
  static int init_result = -1;
  std::call_once(once, []() { init_result = sodium_init(); });
  if (init_result < 0) {
    throw TokenStoreError("Failed to initialize libsodium");
  }
}

void AppendU32(std::vector<unsigned char>* out, std::uint32_t value) {
  out->push_back(static_cast<unsigned char>((value >> 24) & 0xff));
  out->push_back(static_cast<unsigned char>((value >> 16) & 0xff));
  out->push_back(static_cast<unsigned char>((value >> 8) & 0xff));
  out->push_back(static_cast<unsigned char>(value & 0xff));
}

void AppendI64(std::vector<unsigned char>* out, std::int64_t value) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
  }
}

std::uint32_t ReadU32(const std::vector<unsigned char>& data, std::size_t* off) {
  if (*off + 4 > data.size()) {
    throw TokenStoreError("Token store payload is truncated");
  }
  const std::uint32_t value =
      (static_cast<std::uint32_t>(data[*off]) << 24) |
      (static_cast<std::uint32_t>(data[*off + 1]) << 16) |
      (static_cast<std::uint32_t>(data[*off + 2]) << 8) |
      static_cast<std::uint32_t>(data[*off + 3]);
  *off += 4;
  return value;
}

std::int64_t ReadI64(const std::vector<unsigned char>& data, std::size_t* off) {
  if (*off + 8 > data.size()) {
    throw TokenStoreError("Token store payload is truncated");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | static_cast<std::uint64_t>(data[*off + i]);
  }
  *off += 8;
  return static_cast<std::int64_t>(value);
}

std::vector<unsigned char> SerializeIdentity(const StoredIdentity& identity) {
  if (identity.user_uuid.size() > kMaxFieldBytes ||
      identity.refresh_token.size() > kMaxFieldBytes) {
    throw TokenStoreError("Token store field exceeds maximum size");
  }

  std::vector<unsigned char> out;
  out.reserve(4 + 4 + 4 + 8 + identity.user_uuid.size() +
              identity.refresh_token.size());

  AppendU32(&out, kLegacyTokenStoreMagic);
  AppendU32(&out, static_cast<std::uint32_t>(identity.user_uuid.size()));
  AppendU32(&out, static_cast<std::uint32_t>(identity.refresh_token.size()));
  const auto expiry_seconds = std::chrono::duration_cast<std::chrono::seconds>(
      identity.expires_at.time_since_epoch());
  AppendI64(&out, static_cast<std::int64_t>(expiry_seconds.count()));

  out.insert(out.end(), identity.user_uuid.begin(), identity.user_uuid.end());
  out.insert(out.end(), identity.refresh_token.begin(),
             identity.refresh_token.end());
  return out;
}

StoredIdentity DeserializeIdentity(const std::vector<unsigned char>& data) {
  std::size_t off = 0;
  const std::uint32_t magic = ReadU32(data, &off);
  if (magic != kLegacyTokenStoreMagic) {
    throw TokenStoreError("Token store payload magic mismatch");
  }

  const std::uint32_t user_len = ReadU32(data, &off);
  const std::uint32_t token_len = ReadU32(data, &off);
  if (user_len > kMaxFieldBytes || token_len > kMaxFieldBytes) {
    throw TokenStoreError("Token store payload field too large");
  }
  const std::int64_t expiry_seconds = ReadI64(data, &off);

  if (off + user_len + token_len != data.size()) {
    throw TokenStoreError("Token store payload length mismatch");
  }

  StoredIdentity identity;
  identity.user_uuid.assign(
      reinterpret_cast<const char*>(data.data() + off), user_len);
  off += user_len;
  identity.refresh_token.assign(
      reinterpret_cast<const char*>(data.data() + off), token_len);
  off += token_len;
  identity.expires_at = std::chrono::system_clock::time_point(
      std::chrono::seconds(expiry_seconds));
  return identity;
}

std::string EncodeBase64(const std::vector<unsigned char>& data) {
  EnsureSodiumInitialized();
  const std::size_t out_size =
      sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
  std::string out(out_size, '\0');
  sodium_bin2base64(out.data(), out.size(), data.data(), data.size(),
                    sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

std::vector<unsigned char> DecodeBase64(const std::string& encoded) {
  EnsureSodiumInitialized();
  std::vector<unsigned char> out(encoded.size(), 0);
  std::size_t out_len = 0;
  if (sodium_base642bin(out.data(), out.size(), encoded.data(),
                        encoded.size(), nullptr, &out_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    throw TokenStoreError("Invalid base64 payload in token store");
  }
  out.resize(out_len);
  return out;
}

std::string TrimAsciiWhitespace(std::string value) {
  while (!value.empty() &&
         (value.back() == '\n' || value.back() == '\r' ||
          value.back() == ' ' || value.back() == '\t')) {
    value.pop_back();
  }
  std::size_t begin = 0;
  while (begin < value.size() &&
         (value[begin] == '\n' || value[begin] == '\r' || value[begin] == ' ' ||
          value[begin] == '\t')) {
    ++begin;
  }
  if (begin > 0) {
    value.erase(0, begin);
  }
  return value;
}

std::string ReadMachineIdentity(const TokenStoreConfig& config) {
  if (!config.machine_identity_override.empty()) {
    return config.machine_identity_override;
  }
  if (const char* env = std::getenv("VERITAS_MACHINE_ID_OVERRIDE")) {
    if (env[0] != '\0') {
      return std::string(env);
    }
  }

  std::ifstream file("/etc/machine-id", std::ios::binary);
  if (!file.good()) {
    throw TokenStoreError(
        "Failed to read /etc/machine-id for file token-store key derivation");
  }
  std::string machine_id((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
  machine_id = TrimAsciiWhitespace(std::move(machine_id));
  if (machine_id.empty()) {
    throw TokenStoreError("/etc/machine-id is empty");
  }
  return machine_id;
}

std::array<unsigned char, crypto_secretbox_KEYBYTES> DeriveFileKey(
    const TokenStoreConfig& config) {
  EnsureSodiumInitialized();
  const std::string machine_id = ReadMachineIdentity(config);
  const std::string service =
      config.service_name.empty() ? "veritas" : config.service_name;
  const std::string account =
      config.account_name.empty() ? "default" : config.account_name;
  const std::string domain = machine_id + "|" + service + "|" + account;

  std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
  if (crypto_generichash(key.data(), key.size(),
                         reinterpret_cast<const unsigned char*>(domain.data()),
                         domain.size(), nullptr, 0) != 0) {
    throw TokenStoreError("Failed to derive file token-store key");
  }
  return key;
}

std::vector<unsigned char> EncryptFilePayload(
    const std::vector<unsigned char>& plaintext,
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key) {
  EnsureSodiumInitialized();
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
  randombytes_buf(nonce.data(), nonce.size());

  std::vector<unsigned char> ciphertext(
      plaintext.size() + crypto_secretbox_MACBYTES);
  if (crypto_secretbox_easy(ciphertext.data(), plaintext.data(),
                            plaintext.size(), nonce.data(), key.data()) != 0) {
    throw TokenStoreError("Failed to encrypt file token-store payload");
  }

  std::vector<unsigned char> out;
  out.reserve(4 + 4 + 4 + nonce.size() + ciphertext.size());
  AppendU32(&out, kEncryptedTokenStoreMagic);
  AppendU32(&out, static_cast<std::uint32_t>(nonce.size()));
  AppendU32(&out, static_cast<std::uint32_t>(ciphertext.size()));
  out.insert(out.end(), nonce.begin(), nonce.end());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  return out;
}

std::vector<unsigned char> DecryptFilePayload(
    const std::vector<unsigned char>& encrypted,
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key) {
  EnsureSodiumInitialized();
  std::size_t off = 0;
  const std::uint32_t magic = ReadU32(encrypted, &off);
  if (magic != kEncryptedTokenStoreMagic) {
    throw TokenStoreError("Encrypted token-store payload magic mismatch");
  }
  const std::uint32_t nonce_len = ReadU32(encrypted, &off);
  const std::uint32_t cipher_len = ReadU32(encrypted, &off);
  if (nonce_len != crypto_secretbox_NONCEBYTES) {
    throw TokenStoreError("Encrypted token-store payload nonce length mismatch");
  }
  if (cipher_len < crypto_secretbox_MACBYTES) {
    throw TokenStoreError("Encrypted token-store payload ciphertext is invalid");
  }
  if (off + nonce_len + cipher_len != encrypted.size()) {
    throw TokenStoreError("Encrypted token-store payload length mismatch");
  }

  std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
  std::memcpy(nonce.data(), encrypted.data() + off, nonce.size());
  off += nonce.size();
  const unsigned char* ciphertext = encrypted.data() + off;
  const std::size_t plaintext_len = cipher_len - crypto_secretbox_MACBYTES;

  std::vector<unsigned char> plaintext(plaintext_len);
  if (crypto_secretbox_open_easy(plaintext.data(), ciphertext, cipher_len,
                                 nonce.data(), key.data()) != 0) {
    throw TokenStoreError(
        "Failed to decrypt file token-store payload (identity mismatch or corruption)");
  }
  return plaintext;
}

void EmitBreakGlassWarning() {
  static std::once_flag once;
  std::call_once(once, []() {
    std::cerr
        << "WARNING: Veritas file token-store break-glass plaintext mode is enabled."
        << "\n";
  });
}

class FileTokenStore final : public TokenStore {
 public:
  explicit FileTokenStore(TokenStoreConfig config)
      : path_(config.file_path), config_(std::move(config)) {}

  void Save(const StoredIdentity& identity) override {
    const std::vector<unsigned char> payload = SerializeIdentity(identity);
    std::vector<unsigned char> persisted_payload;
    if (config_.break_glass_plaintext_file) {
      EmitBreakGlassWarning();
      persisted_payload = payload;
    } else {
      const auto key = DeriveFileKey(config_);
      persisted_payload = EncryptFilePayload(payload, key);
    }
    const std::filesystem::path parent = path_.parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        throw TokenStoreError("Failed to create token store directory: " +
                              ec.message());
      }
    }

    const std::filesystem::path temp_path = path_.string() + ".tmp";
    {
      std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
      if (!out.good()) {
        throw TokenStoreError("Failed to open token store temp file");
      }
      out.write(reinterpret_cast<const char*>(persisted_payload.data()),
                static_cast<std::streamsize>(persisted_payload.size()));
      if (!out.good()) {
        throw TokenStoreError("Failed to write token store temp file");
      }
    }

    std::error_code perm_ec;
    std::filesystem::permissions(
        temp_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
      std::filesystem::remove(temp_path, perm_ec);
      throw TokenStoreError("Failed to set token store file permissions");
    }

    std::error_code rename_ec;
    std::filesystem::rename(temp_path, path_, rename_ec);
    if (rename_ec) {
      std::filesystem::remove(temp_path, rename_ec);
      throw TokenStoreError("Failed to move token store temp file");
    }
  }

  std::optional<StoredIdentity> Load() override {
    std::error_code exists_ec;
    if (!std::filesystem::exists(path_, exists_ec)) {
      return std::nullopt;
    }
    if (exists_ec) {
      throw TokenStoreError("Failed to read token store file path");
    }

    std::ifstream in(path_, std::ios::binary);
    if (!in.good()) {
      throw TokenStoreError("Failed to open token store file");
    }
    const std::vector<unsigned char> payload(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    if (payload.empty()) {
      return std::nullopt;
    }
    if (payload.size() < 4) {
      throw TokenStoreError("Token store payload is truncated");
    }

    std::size_t off = 0;
    const std::uint32_t magic = ReadU32(payload, &off);
    if (magic == kEncryptedTokenStoreMagic) {
      const auto key = DeriveFileKey(config_);
      return DeserializeIdentity(DecryptFilePayload(payload, key));
    }
    if (magic == kLegacyTokenStoreMagic) {
      const auto identity = DeserializeIdentity(payload);
      if (config_.break_glass_plaintext_file) {
        EmitBreakGlassWarning();
        return identity;
      }
      if (!config_.migrate_legacy_plaintext) {
        throw TokenStoreError(
            "Legacy plaintext token-store payload is present but migration is disabled");
      }
      Save(identity);
      return identity;
    }
    throw TokenStoreError("Unknown token-store payload format");
  }

  void Clear() override {
    std::error_code ec;
    std::filesystem::remove(path_, ec);
    if (ec && ec.value() != ENOENT) {
      throw TokenStoreError("Failed to delete token store file");
    }
  }

 private:
  std::filesystem::path path_;
  TokenStoreConfig config_;
};

class LibsecretTokenStore final : public TokenStore {
 public:
  LibsecretTokenStore(std::string service, std::string account)
      : service_(std::move(service)), account_(std::move(account)) {
    if (service_.empty()) {
      throw TokenStoreError("Libsecret token store requires service_name");
    }
    if (account_.empty()) {
      throw TokenStoreError("Libsecret token store requires account_name");
    }
  }

  void Save(const StoredIdentity& identity) override {
#if VERITAS_HAS_LIBSECRET
    static const SecretSchema kSchema = {
        "org.veritas.identity-token",
        SECRET_SCHEMA_NONE,
        {
            {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
            {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
        },
    };

    const std::string encoded = EncodeBase64(SerializeIdentity(identity));
    GError* error = nullptr;
    const gboolean ok = secret_password_store_sync(
        &kSchema, SECRET_COLLECTION_DEFAULT, "Veritas Identity Token",
        encoded.c_str(), nullptr, &error, "service", service_.c_str(), "account",
        account_.c_str(), nullptr);
    if (!ok) {
      const std::string msg =
          error && error->message ? error->message : "unknown libsecret error";
      if (error) {
        g_error_free(error);
      }
      throw TokenStoreError("Failed to save token in libsecret: " + msg);
    }
#else
    (void)identity;
    throw TokenStoreError("libsecret backend is not available");
#endif
  }

  std::optional<StoredIdentity> Load() override {
#if VERITAS_HAS_LIBSECRET
    static const SecretSchema kSchema = {
        "org.veritas.identity-token",
        SECRET_SCHEMA_NONE,
        {
            {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
            {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
        },
    };

    GError* error = nullptr;
    gchar* secret = secret_password_lookup_sync(
        &kSchema, nullptr, &error, "service", service_.c_str(), "account",
        account_.c_str(), nullptr);
    if (!secret) {
      if (error) {
        const std::string msg = error->message ? error->message : "lookup error";
        g_error_free(error);
        throw TokenStoreError("Failed to read token from libsecret: " + msg);
      }
      return std::nullopt;
    }
    const std::string encoded(secret);
    secret_password_free(secret);
    return DeserializeIdentity(DecodeBase64(encoded));
#else
    throw TokenStoreError("libsecret backend is not available");
#endif
  }

  void Clear() override {
#if VERITAS_HAS_LIBSECRET
    static const SecretSchema kSchema = {
        "org.veritas.identity-token",
        SECRET_SCHEMA_NONE,
        {
            {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
            {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
        },
    };

    GError* error = nullptr;
    const gboolean ok = secret_password_clear_sync(
        &kSchema, nullptr, &error, "service", service_.c_str(), "account",
        account_.c_str(), nullptr);
    if (!ok && error) {
      const std::string msg = error->message ? error->message : "clear error";
      g_error_free(error);
      throw TokenStoreError("Failed to clear token from libsecret: " + msg);
    }
#else
    throw TokenStoreError("libsecret backend is not available");
#endif
  }

 private:
  std::string service_;
  std::string account_;
};

}  // namespace

std::unique_ptr<TokenStore> CreateTokenStore(const TokenStoreConfig& config) {
  if (config.backend == TokenStoreBackend::Libsecret) {
    return std::make_unique<LibsecretTokenStore>(config.service_name,
                                                 config.account_name);
  }

  if (!config.allow_insecure_fallback) {
    throw TokenStoreError(
        "File token store fallback is disabled unless explicitly enabled");
  }
  if (config.file_path.empty()) {
    throw TokenStoreError("File token store requires file_path");
  }
  return std::make_unique<FileTokenStore>(config);
}

}  // namespace veritas::storage
