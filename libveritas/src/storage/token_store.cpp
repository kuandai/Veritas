#include "token_store.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
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

constexpr std::uint32_t kTokenStoreMagic = 0x56545331;  // "VTS1"
constexpr std::size_t kMaxFieldBytes = 1 * 1024 * 1024;

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

  AppendU32(&out, kTokenStoreMagic);
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
  if (magic != kTokenStoreMagic) {
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
  const std::size_t out_size =
      sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
  std::string out(out_size, '\0');
  sodium_bin2base64(out.data(), out.size(), data.data(), data.size(),
                    sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

std::vector<unsigned char> DecodeBase64(const std::string& encoded) {
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

class FileTokenStore final : public TokenStore {
 public:
  explicit FileTokenStore(std::filesystem::path path) : path_(std::move(path)) {}

  void Save(const StoredIdentity& identity) override {
    const std::vector<unsigned char> payload = SerializeIdentity(identity);
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
      out.write(reinterpret_cast<const char*>(payload.data()),
                static_cast<std::streamsize>(payload.size()));
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
    return DeserializeIdentity(payload);
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
  return std::make_unique<FileTokenStore>(config.file_path);
}

}  // namespace veritas::storage
