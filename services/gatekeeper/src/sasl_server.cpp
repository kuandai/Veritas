#include "sasl_server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <mutex>

#if !defined(VERITAS_DISABLE_SASL)
#include <sasl/sasl.h>
#endif

#include "secure_erase.h"
#include "token_utils.h"

namespace veritas::gatekeeper {

namespace {

std::once_flag g_sasl_init_once;
#if defined(VERITAS_DISABLE_SASL)
constexpr int kSaslOk = 0;
#else
constexpr int kSaslOk = SASL_OK;
#endif
std::atomic<int> g_sasl_init_result{kSaslOk};
std::string g_sasl_init_error;

#if !defined(VERITAS_DISABLE_SASL)
struct SaslCallbackContext {
  std::string conf_path;
  std::string plugin_path;
  std::string dbname;
  std::string mech_list;
};

int SaslGetopt(void* context,
               const char* /*plugin_name*/,
               const char* option,
               const char** result,
               unsigned* len) {
  if (!context || !option || !result) {
    return SASL_BADPARAM;
  }
  const auto* ctx = static_cast<SaslCallbackContext*>(context);
  const std::string_view option_view(option);
  const std::string* value = nullptr;
  if (option_view == "sasldb_path" && !ctx->dbname.empty()) {
    value = &ctx->dbname;
  } else if (option_view == "mech_list" && !ctx->mech_list.empty()) {
    value = &ctx->mech_list;
  }
  if (!value) {
    *result = nullptr;
    if (len) {
      *len = 0;
    }
    return SASL_OK;
  }
  *result = value->c_str();
  if (len) {
    *len = static_cast<unsigned>(value->size());
  }
  return SASL_OK;
}

bool IsDebugEnabled();

int SaslLog(void* /*context*/, int level, const char* message) {
  if (!message) {
    return SASL_OK;
  }
  if (!IsDebugEnabled()) {
    return SASL_OK;
  }
  std::cerr << "[sasl] level=" << level << " " << message << "\n";
  return SASL_OK;
}

void LogSaslDetail(sasl_conn_t* conn,
                   std::string_view context,
                   int code) {
  if (!conn) {
    return;
  }
  const char* detail = sasl_errdetail(conn);
  if (!detail || detail[0] == '\0') {
    return;
  }
  std::cerr << "[sasl] " << context << " rc=" << code
            << " detail=" << detail << "\n";
}

void LogSaslProp(sasl_conn_t* conn, int prop_id, std::string_view name) {
  if (!conn) {
    return;
  }
  const void* prop = nullptr;
  if (sasl_getprop(conn, prop_id, &prop) != SASL_OK || !prop) {
    return;
  }
  const char* value = static_cast<const char*>(prop);
  if (!value || value[0] == '\0') {
    return;
  }
  std::cerr << "[sasl] " << name << "=" << value << "\n";
}

int SaslGetpath(void* context, const char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  const auto* ctx = static_cast<SaslCallbackContext*>(context);
  if (ctx->plugin_path.empty()) {
    return SASL_FAIL;
  }
  *path = ctx->plugin_path.c_str();
  return SASL_OK;
}

int SaslGetconfpath(void* context, char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  const auto* ctx = static_cast<SaslCallbackContext*>(context);
  if (ctx->conf_path.empty()) {
    return SASL_FAIL;
  }
  const std::size_t size = ctx->conf_path.size() + 1;
  auto* buffer = static_cast<char*>(std::malloc(size));
  if (!buffer) {
    return SASL_NOMEM;
  }
  std::memcpy(buffer, ctx->conf_path.c_str(), size);
  *path = buffer;
  return SASL_OK;
}

int SaslCanonUser(sasl_conn_t* /*conn*/,
                  void* /*context*/,
                  const char* in,
                  unsigned inlen,
                  unsigned /*flags*/,
                  const char* user_realm,
                  char* out,
                  unsigned out_max,
                  unsigned* out_len) {
  if (!in || !out || out_max == 0) {
    return SASL_BADPARAM;
  }
  const std::size_t input_len =
      inlen > 0 ? static_cast<std::size_t>(inlen) : std::strlen(in);
  std::string value(in, input_len);
  if (user_realm && user_realm[0] != '\0' &&
      value.find('@') == std::string::npos) {
    value.push_back('@');
    value.append(user_realm);
  }
  if (value.size() + 1 > out_max) {
    return SASL_BUFOVER;
  }
  std::memcpy(out, value.data(), value.size());
  out[value.size()] = '\0';
  if (out_len) {
    *out_len = static_cast<unsigned>(value.size());
  }
  return SASL_OK;
}
#endif

std::string GenerateRandomBytes(std::size_t length) {
  return GenerateRefreshToken(length);
}

std::string GenerateSessionId() {
  return HexEncodeBytes(GenerateRandomBytes(16));
}

bool IsDebugEnabled() {
  const char* env = std::getenv("VERITAS_SASL_DEBUG");
  if (!env || env[0] == '\0') {
    return false;
  }
  return std::strcmp(env, "0") != 0 && std::strcmp(env, "false") != 0 &&
         std::strcmp(env, "no") != 0;
}

bool TestAuthBypassEnabled(const SaslServerOptions& options) {
#if defined(VERITAS_ENABLE_TEST_AUTH_BYPASS)
  return options.allow_test_auth_bypass;
#else
  (void)options;
  return false;
#endif
}

constexpr std::size_t kMinChallengeSize = 32;
constexpr std::size_t kMaxChallengeSize = 4096;

std::size_t ClampChallengeSize(std::size_t size) {
  return std::clamp(size, kMinChallengeSize, kMaxChallengeSize);
}

class BeginAuthLatencyPad {
 public:
  explicit BeginAuthLatencyPad(std::chrono::milliseconds min_duration)
      : min_duration_(min_duration),
        started_(std::chrono::steady_clock::now()) {}

  ~BeginAuthLatencyPad() {
    if (min_duration_.count() <= 0) {
      return;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_);
    if (elapsed < min_duration_) {
      std::this_thread::sleep_for(min_duration_ - elapsed);
    }
  }

 private:
  std::chrono::milliseconds min_duration_;
  std::chrono::steady_clock::time_point started_;
};

std::string SelectMechanism(const std::string& mech_list) {
  if (mech_list.empty()) {
    return "SRP";
  }
  std::size_t start = 0;
  while (start < mech_list.size()) {
    const char ch = mech_list[start];
    if (ch != ',' && !std::isspace(static_cast<unsigned char>(ch))) {
      break;
    }
    ++start;
  }
  if (start >= mech_list.size()) {
    return "SRP";
  }
  std::size_t end = start;
  while (end < mech_list.size()) {
    const char ch = mech_list[end];
    if (ch == ',' || std::isspace(static_cast<unsigned char>(ch))) {
      break;
    }
    ++end;
  }
  if (end <= start) {
    return "SRP";
  }
  return mech_list.substr(start, end - start);
}

#if !defined(VERITAS_DISABLE_SASL)
grpc::Status MapSaslError(int code, std::string_view context) {
  grpc::StatusCode grpc_code = grpc::StatusCode::UNAUTHENTICATED;
  switch (code) {
    case SASL_NOAUTHZ:
    case SASL_WRONGMECH:
      grpc_code = grpc::StatusCode::PERMISSION_DENIED;
      break;
    case SASL_PWLOCK:
    case SASL_TOOWEAK:
    case SASL_WEAKPASS:
      grpc_code = grpc::StatusCode::RESOURCE_EXHAUSTED;
      break;
    case SASL_UNAVAIL:
    case SASL_TRYAGAIN:
    case SASL_NOMEM:
    case SASL_NOMECH:
      grpc_code = grpc::StatusCode::UNAVAILABLE;
      break;
    case SASL_BADAUTH:
    case SASL_BADMAC:
    case SASL_BADPROT:
    case SASL_NOUSER:
    case SASL_NOVERIFY:
    default:
      grpc_code = grpc::StatusCode::UNAUTHENTICATED;
      break;
  }
  std::string message(context);
  const char* err = sasl_errstring(code, nullptr, nullptr);
  if (err) {
    message += ": ";
    message += err;
  }
  return grpc::Status(grpc_code, message);
}
#endif

}  // namespace

#if !defined(VERITAS_DISABLE_SASL)
struct SaslContext {
  SaslCallbackContext callback_ctx;
  std::vector<sasl_callback_t> callbacks;

  explicit SaslContext(const SaslServerOptions& options) {
    callback_ctx.conf_path = options.sasl_conf_path;
    callback_ctx.plugin_path = options.sasl_plugin_path;
    callback_ctx.dbname = options.sasl_dbname;
    callback_ctx.mech_list = options.sasl_mech_list;

    if (!callback_ctx.dbname.empty() || !callback_ctx.mech_list.empty()) {
      callbacks.push_back(
          {SASL_CB_GETOPT, reinterpret_cast<int (*)(void)>(&SaslGetopt),
           &callback_ctx});
    }
    if (!callback_ctx.plugin_path.empty()) {
      callbacks.push_back(
          {SASL_CB_GETPATH, reinterpret_cast<int (*)(void)>(&SaslGetpath),
           &callback_ctx});
    }
    if (!callback_ctx.conf_path.empty()) {
      callbacks.push_back(
          {SASL_CB_GETCONFPATH, reinterpret_cast<int (*)(void)>(&SaslGetconfpath),
           &callback_ctx});
    }
    callbacks.push_back(
        {SASL_CB_CANON_USER, reinterpret_cast<int (*)(void)>(&SaslCanonUser),
         &callback_ctx});
    callbacks.push_back(
        {SASL_CB_LOG, reinterpret_cast<int (*)(void)>(&SaslLog),
         &callback_ctx});
    callbacks.push_back({SASL_CB_LIST_END, nullptr, nullptr});
  }
};
#else
struct SaslContext {};
#endif

SaslServer::SaslServer(SaslServerOptions options)
    : options_(std::move(options)),
      session_cache_(options_.session_ttl),
      fake_salt_(options_.fake_salt_secret),
      observed_challenge_size_(ClampChallengeSize(options_.fake_challenge_size)) {
  if (options_.begin_auth_min_duration.count() < 0) {
    options_.begin_auth_min_duration = std::chrono::milliseconds(0);
  }
  const bool test_auth_bypass = TestAuthBypassEnabled(options_);
  if (!options_.enable_sasl && !test_auth_bypass) {
    throw std::runtime_error(
        "SASL_ENABLE=false is not permitted in this build");
  }
  if (options_.skip_sasl_init && !test_auth_bypass) {
    throw std::runtime_error(
        "skip_sasl_init is test-only and cannot be used in this build");
  }
#if defined(VERITAS_DISABLE_SASL)
  if (!test_auth_bypass) {
    throw std::runtime_error(
        "Gatekeeper was built without SASL support");
  }
#endif

  if (options_.token_store) {
    token_store_ = std::move(options_.token_store);
  } else {
    token_store_ = std::make_shared<InMemoryTokenStore>();
  }
#if !defined(VERITAS_DISABLE_SASL)
  if (options_.enable_sasl) {
    sasl_context_ = std::make_unique<SaslContext>(options_);
    if (!options_.skip_sasl_init) {
      EnsureInitialized();
    }
  }
#endif
}

SaslServer::~SaslServer() = default;

void SaslServer::EnsureInitialized() {
#if !defined(VERITAS_DISABLE_SASL)
  if (!sasl_context_) {
    sasl_context_ = std::make_unique<SaslContext>(options_);
  }
  std::call_once(g_sasl_init_once, [this]() {
    const auto* callbacks =
        sasl_context_ ? sasl_context_->callbacks.data() : nullptr;
    const int result =
        sasl_server_init(callbacks, options_.sasl_service.c_str());
    if (result != SASL_OK) {
      g_sasl_init_result.store(result);
      g_sasl_init_error = "SASL initialization failed";
#if !defined(VERITAS_DISABLE_SASL)
      const char* err = sasl_errstring(result, nullptr, nullptr);
      if (err) {
        g_sasl_init_error += ": ";
        g_sasl_init_error += err;
      }
#endif
      return;
    }
  });
#endif
}

bool SaslServer::UseSasl() const {
#if defined(VERITAS_DISABLE_SASL)
  return false;
#else
  return options_.enable_sasl && !options_.skip_sasl_init;
#endif
}

grpc::Status SaslServer::BeginAuth(
    const veritas::auth::v1::BeginAuthRequest& request,
    veritas::auth::v1::BeginAuthResponse* response) {
  if (request.login_username().empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "login_username is required");
  }

  BeginAuthLatencyPad latency_pad(options_.begin_auth_min_duration);

  try {
    session_cache_.CleanupExpired();
    const auto now = std::chrono::system_clock::now();
    const std::string session_id = GenerateSessionId();
    const std::string response_salt =
        fake_salt_.Generate(request.login_username());
    if (!UseSasl()) {
      if (!TestAuthBypassEnabled(options_)) {
        return grpc::Status(
            grpc::StatusCode::FAILED_PRECONDITION,
            "SASL authentication is required in this build");
      }
      SrpSession session{session_id, request.login_username(),
                         now + options_.session_ttl, nullptr, false};
      session_cache_.Insert(session);

      std::string server_public = GenerateRandomBytes(
          observed_challenge_size_.load(std::memory_order_relaxed));
      response->set_salt(response_salt);
      response->set_server_public(server_public);
      response->set_session_id(session_id);
      auto* params = response->mutable_params();
      params->set_group("rfc5054-4096");
      params->set_hash("sha256");
      SecureErase(&server_public);
      return grpc::Status::OK;
    }

#if !defined(VERITAS_DISABLE_SASL)
    EnsureInitialized();
    if (g_sasl_init_result.load() != kSaslOk) {
      return grpc::Status(grpc::StatusCode::INTERNAL, g_sasl_init_error);
    }

    const auto& client_start = request.client_start();
    if (client_start.empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "client_start is required");
    }
    if (IsDebugEnabled()) {
      std::cerr << "[sasl] client_start_len=" << client_start.size() << "\n";
    }

    sasl_conn_t* conn = nullptr;
    const std::string mech = SelectMechanism(options_.sasl_mech_list);
    const char* realm = options_.sasl_realm.empty()
                            ? nullptr
                            : options_.sasl_realm.c_str();
    const auto* callbacks =
        sasl_context_ ? sasl_context_->callbacks.data() : nullptr;
    int result = sasl_server_new(options_.sasl_service.c_str(), nullptr, realm,
                                 nullptr, nullptr, callbacks, 0, &conn);
    if (result != SASL_OK) {
      return MapSaslError(result, "SASL connection init failed");
    }

    const char* aux_props[] = {"cmusaslsecretSRP", "userPassword", nullptr};
    sasl_auxprop_request(conn, aux_props);

    const char* server_out = nullptr;
    unsigned server_out_len = 0;
    result = sasl_server_start(conn, mech.c_str(),
                               client_start.data(),
                               static_cast<unsigned>(client_start.size()),
                               &server_out, &server_out_len);
    if (IsDebugEnabled()) {
      std::cerr << "[sasl] sasl_server_start rc=" << result
                << " server_out_len=" << server_out_len << "\n";
    }
    if (result == SASL_NOUSER || result == SASL_NOVERIFY) {
      sasl_dispose(&conn);
      SrpSession session{session_id, request.login_username(),
                         now + options_.session_ttl, nullptr, true};
      session_cache_.Insert(session);
      std::string server_public = GenerateRandomBytes(
          observed_challenge_size_.load(std::memory_order_relaxed));
      response->set_salt(response_salt);
      response->set_server_public(server_public);
      response->set_session_id(session_id);
      auto* params = response->mutable_params();
      params->set_group("rfc5054-4096");
      params->set_hash("sha256");
      SecureErase(&server_public);
      return grpc::Status::OK;
    }
    if (result != SASL_CONTINUE) {
      LogSaslDetail(conn, "sasl_server_start", result);
      sasl_dispose(&conn);
      if (result == SASL_OK) {
        return grpc::Status(grpc::StatusCode::INTERNAL,
                            "SASL mechanism completed unexpectedly");
      }
      return MapSaslError(result, "SASL start failed");
    }

    auto handle = std::make_shared<SaslConnection>(conn);
    SrpSession session{session_id, request.login_username(),
                       now + options_.session_ttl, handle, false};
    session_cache_.Insert(session);
    if (server_out && server_out_len > 0) {
      observed_challenge_size_.store(
          ClampChallengeSize(static_cast<std::size_t>(server_out_len)),
          std::memory_order_relaxed);
      response->set_server_public(std::string(server_out, server_out_len));
    } else {
      response->set_server_public("");
    }
    LogSaslProp(conn, SASL_USERNAME, "username");
    LogSaslProp(conn, SASL_AUTHUSER, "authuser");
    response->set_salt(response_salt);
    response->set_session_id(session_id);
    auto* params = response->mutable_params();
    params->set_group("rfc5054-4096");
    params->set_hash("sha256");
    return grpc::Status::OK;
#endif
  } catch (const std::exception& ex) {
    return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }

  return grpc::Status::OK;
}

grpc::Status SaslServer::FinishAuth(
    const veritas::auth::v1::FinishAuthRequest& request,
    veritas::auth::v1::FinishAuthResponse* response) {
  if (request.session_id().empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "session_id is required");
  }
  if (request.client_proof().empty()) {
    return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                        "client_proof is required");
  }

  session_cache_.CleanupExpired();
  const auto session = session_cache_.Take(request.session_id());
  if (!session) {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "session not found");
  }
  if (session->is_fake) {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "invalid credentials");
  }

  try {
    const auto now = std::chrono::system_clock::now();
    const auto expires_at =
        now + std::chrono::hours(24 * options_.token_ttl_days);
    if (!UseSasl()) {
      if (!TestAuthBypassEnabled(options_)) {
        return grpc::Status(
            grpc::StatusCode::FAILED_PRECONDITION,
            "SASL authentication is required in this build");
      }
      std::string refresh_token = GenerateRefreshToken();
      const std::string token_hash = HashTokenSha256(refresh_token);
      const std::string user_uuid = "mock-" + session->session_id;

      TokenRecord record{token_hash, user_uuid, expires_at, false};
      token_store_->PutToken(record);

      std::string server_proof = GenerateRandomBytes(32);
      response->set_server_proof(server_proof);
      response->set_user_uuid(user_uuid);
      response->set_refresh_token(refresh_token);

      auto* ts = response->mutable_expires_at();
      const auto seconds =
          std::chrono::duration_cast<std::chrono::seconds>(
              expires_at.time_since_epoch())
              .count();
      ts->set_seconds(static_cast<int64_t>(seconds));
      ts->set_nanos(0);
      SecureErase(&refresh_token);
      SecureErase(&server_proof);
      return grpc::Status::OK;
    }

#if !defined(VERITAS_DISABLE_SASL)
    EnsureInitialized();
    if (g_sasl_init_result.load() != kSaslOk) {
      return grpc::Status(grpc::StatusCode::INTERNAL, g_sasl_init_error);
    }
    if (!session->sasl_conn) {
      return grpc::Status(grpc::StatusCode::INTERNAL,
                          "missing SASL session");
    }

    const std::string& client_proof = request.client_proof();
    if (IsDebugEnabled()) {
      std::cerr << "[sasl] client_proof_len=" << client_proof.size() << "\n";
    }
    const char* server_out = nullptr;
    unsigned server_out_len = 0;
    const int result =
        sasl_server_step(session->sasl_conn->get(), client_proof.data(),
                         static_cast<unsigned>(client_proof.size()),
                         &server_out, &server_out_len);
    bool treat_continue_as_ok = false;
    if (result == SASL_CONTINUE && server_out && server_out_len > 0) {
      treat_continue_as_ok = true;
    }
    if (result != SASL_OK && !treat_continue_as_ok) {
      LogSaslDetail(session->sasl_conn->get(), "sasl_server_step", result);
      LogSaslProp(session->sasl_conn->get(), SASL_USERNAME, "username");
      LogSaslProp(session->sasl_conn->get(), SASL_AUTHUSER, "authuser");
      if (result == SASL_CONTINUE) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                            "SASL requires additional steps");
      }
      return MapSaslError(result, "SASL step failed");
    }

    const void* prop = nullptr;
    std::string user_uuid = session->login_username;
    if (sasl_getprop(session->sasl_conn->get(), SASL_USERNAME, &prop) ==
            SASL_OK &&
        prop) {
      const char* sasl_user = static_cast<const char*>(prop);
      if (sasl_user && sasl_user[0] != '\0') {
        user_uuid = sasl_user;
      }
    }

    std::string refresh_token = GenerateRefreshToken();
    const std::string token_hash = HashTokenSha256(refresh_token);
    TokenRecord record{token_hash, user_uuid, expires_at, false};
    token_store_->PutToken(record);

    std::string server_proof;
    if (server_out && server_out_len > 0) {
      server_proof.assign(server_out, server_out_len);
    }
    response->set_server_proof(server_proof);
    response->set_user_uuid(user_uuid);
    response->set_refresh_token(refresh_token);

    auto* ts = response->mutable_expires_at();
    const auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            expires_at.time_since_epoch())
            .count();
    ts->set_seconds(static_cast<int64_t>(seconds));
    ts->set_nanos(0);
    SecureErase(&refresh_token);
    SecureErase(&server_proof);
    return grpc::Status::OK;
#endif
  } catch (const TokenStoreError& ex) {
    if (ex.kind() == TokenStoreError::Kind::Unavailable) {
      return grpc::Status(grpc::StatusCode::UNAVAILABLE, ex.what());
    }
    return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  } catch (const std::exception& ex) {
    return grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }

  return grpc::Status::OK;
}

}  // namespace veritas::gatekeeper
