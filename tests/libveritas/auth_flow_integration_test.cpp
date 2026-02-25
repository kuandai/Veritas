#include "auth/auth_flow.h"
#include "auth/gatekeeper_client.h"
#include "auth/sasl_client.h"

#include <chrono>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>
#include <grpcpp/server_builder.h>
#include <sasl/sasl.h>

#include "gatekeeper_service.h"
#include "notary.grpc.pb.h"
#include "sasl_server.h"

namespace veritas::auth {
namespace {

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

std::string RandomSuffix() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  return std::to_string(dist(gen));
}

std::string TempPath(const std::string& prefix) {
  const auto base = std::filesystem::temp_directory_path();
  return (base / (prefix + "_" + RandomSuffix())).string();
}

std::string QualifyUser(std::string username, const std::string& realm) {
  if (!realm.empty() && username.find('@') == std::string::npos) {
    username.push_back('@');
    username.append(realm);
  }
  return username;
}

std::string FindSaslPluginPath() {
  if (const char* env = std::getenv("SASL_PATH")) {
    return env;
  }
  if (const char* env = std::getenv("SASL_PLUGIN_PATH")) {
    return env;
  }

  std::vector<std::filesystem::path> roots;
  if (const char* env = std::getenv("CONAN_HOME")) {
    roots.emplace_back(env);
  }
  if (const char* home = std::getenv("HOME")) {
    std::filesystem::path conan2 = std::filesystem::path(home) / ".conan2";
    if (std::filesystem::exists(conan2)) {
      roots.push_back(conan2);
    }
  }

  std::filesystem::path cwd = std::filesystem::current_path();
  for (int i = 0; i < 4; ++i) {
    std::filesystem::path candidate = cwd / ".conan";
    if (std::filesystem::exists(candidate)) {
      roots.push_back(candidate);
      break;
    }
    if (!cwd.has_parent_path()) {
      break;
    }
    cwd = cwd.parent_path();
  }

  for (const auto& root : roots) {
    std::filesystem::path search_root = root / "p" / "b";
    if (!std::filesystem::exists(search_root)) {
      continue;
    }
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(search_root, ec);
         it != std::filesystem::recursive_directory_iterator();
         it.increment(ec)) {
      if (ec || !it->is_directory(ec)) {
        continue;
      }
      if (it->path().filename() != "sasl2") {
        continue;
      }
      for (const auto& entry :
           std::filesystem::directory_iterator(it->path(), ec)) {
        if (ec) {
          break;
        }
        const std::string filename = entry.path().filename().string();
        if (filename.rfind("libsrp.so", 0) == 0) {
          return it->path().string();
        }
      }
    }
  }

  return "";
}

struct SaslTestEnv {
  std::string plugin_path;
  std::string conf_dir;
  std::string realm;
};

const SaslTestEnv& GetSaslTestEnv() {
  static SaslTestEnv env = []() {
    SaslTestEnv value;
    value.realm = "veritas-test";
    value.plugin_path = FindSaslPluginPath();

    if (!value.plugin_path.empty()) {
      setenv("SASL_PATH", value.plugin_path.c_str(), 1);
    }
    setenv("SASL_REALM", value.realm.c_str(), 1);

    value.conf_dir = TempPath("veritas_sasl_conf");
    std::filesystem::create_directories(value.conf_dir);
    const std::filesystem::path conf_path =
        std::filesystem::path(value.conf_dir) / "veritas_gatekeeper.conf";
    std::ofstream conf(conf_path);
    conf << "pwcheck_method: auxprop\n"
         << "auxprop_plugin: sasldb\n"
         << "mech_list: SRP\n"
         << "srp_mda: SHA-1\n";
    setenv("SASL_CONF_PATH", value.conf_dir.c_str(), 1);
    return value;
  }();
  return env;
}

bool IsSrpUnavailable(const grpc::Status& status) {
  if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
    const std::string message = status.error_message();
    if (message.find("no mechanism") != std::string::npos ||
        message.find("NOMECH") != std::string::npos) {
      return true;
    }
  }
  return false;
}

struct SaslSetupResult {
  enum class Kind { Ok, Skip, Fail } kind = Kind::Fail;
  std::string message;
};

SaslSetupResult EnsureUserExists(
    const veritas::gatekeeper::SaslServerOptions& options,
    const std::string& username,
    const std::string& password) {
  veritas::gatekeeper::SaslServer server(options);
  SaslCallbackContext cb_ctx;
  cb_ctx.dbname = options.sasl_dbname;
  cb_ctx.mech_list = options.sasl_mech_list;
  cb_ctx.plugin_path = options.sasl_plugin_path;
  cb_ctx.conf_path = options.sasl_conf_path;

  std::vector<sasl_callback_t> callbacks;
  auto add_callback = [&callbacks](unsigned long id,
                                   int (*proc)(void),
                                   void* ctx) {
    sasl_callback_t cb{};
    cb.id = id;
    cb.proc = reinterpret_cast<int (*)(void)>(proc);
    cb.context = ctx;
    callbacks.push_back(cb);
  };

  add_callback(SASL_CB_GETOPT,
               reinterpret_cast<int (*)(void)>(&SaslGetopt),
               &cb_ctx);
  if (!cb_ctx.plugin_path.empty()) {
    add_callback(SASL_CB_GETPATH,
                 reinterpret_cast<int (*)(void)>(&SaslGetpath),
                 &cb_ctx);
  }
  if (!cb_ctx.conf_path.empty()) {
    add_callback(SASL_CB_GETCONFPATH,
                 reinterpret_cast<int (*)(void)>(&SaslGetconfpath),
                 &cb_ctx);
  }
  sasl_callback_t end_cb{};
  end_cb.id = SASL_CB_LIST_END;
  callbacks.push_back(end_cb);

  sasl_conn_t* conn = nullptr;
  const char* realm = options.sasl_realm.empty()
                           ? nullptr
                           : options.sasl_realm.c_str();
  int rc = sasl_server_new(options.sasl_service.c_str(), nullptr, realm, nullptr,
                           nullptr, callbacks.data(), 0, &conn);
  if (rc != SASL_OK) {
    return {SaslSetupResult::Kind::Skip,
            "SASL server init unavailable for setpass"};
  }

  rc = sasl_setpass(conn, username.c_str(), password.c_str(),
                    static_cast<unsigned>(password.size()), nullptr, 0,
                    SASL_SET_CREATE | SASL_SET_NOPLAIN);
  sasl_dispose(&conn);
  if (rc == SASL_NOMECH || rc == SASL_NOUSERPASS) {
    return {SaslSetupResult::Kind::Skip,
            "SASL SRP setpass not supported in this build"};
  }
  if (rc != SASL_OK && rc != SASL_NOCHANGE) {
    return {SaslSetupResult::Kind::Fail,
            std::string("sasl_setpass failed: ") +
                sasl_errstring(rc, nullptr, nullptr)};
  }

  veritas::auth::v1::BeginAuthRequest warmup_request;
  veritas::auth::v1::BeginAuthResponse warmup_response;
  const std::string warmup_user =
      QualifyUser("warmup_" + RandomSuffix(), options.sasl_realm);
  warmup_request.set_login_username(warmup_user);
  try {
    SaslClient warmup_client(options.sasl_service, warmup_user, "warmup-pass");
    const std::string warmup_start = warmup_client.Start();
    if (warmup_start.empty()) {
      return {SaslSetupResult::Kind::Skip,
              "SASL client did not emit initial response"};
    }
    warmup_request.set_client_start(warmup_start);
  } catch (const std::exception& ex) {
    return {SaslSetupResult::Kind::Skip,
            std::string("SASL client start failed: ") + ex.what()};
  }
  const grpc::Status warmup_status =
      server.BeginAuth(warmup_request, &warmup_response);
  if (!warmup_status.ok()) {
    if (IsSrpUnavailable(warmup_status)) {
      return {SaslSetupResult::Kind::Skip,
              "SRP mechanism not available in SASL build"};
    }
    return {SaslSetupResult::Kind::Fail, warmup_status.error_message()};
  }

  return {SaslSetupResult::Kind::Ok, ""};
}

struct GatekeeperHarness {
  veritas::gatekeeper::SaslServerOptions sasl_options;
  std::unique_ptr<veritas::auth::v1::GatekeeperServiceImpl> service;
  std::unique_ptr<grpc::Server> server;
  std::string target;
  std::string username;
  std::string password;
};

SaslSetupResult StartGatekeeper(GatekeeperHarness* harness) {
  const auto& env = GetSaslTestEnv();
  harness->sasl_options.fake_salt_secret = "test-secret";
  harness->sasl_options.sasl_mech_list = "SRP";
  harness->sasl_options.sasl_service = "veritas_gatekeeper";
  harness->sasl_options.sasl_dbname = TempPath("veritas_sasldb");
  harness->sasl_options.sasl_plugin_path = env.plugin_path;
  harness->sasl_options.sasl_conf_path = env.conf_dir;
  harness->sasl_options.sasl_realm = env.realm;

  harness->username =
      QualifyUser("user_" + RandomSuffix(), harness->sasl_options.sasl_realm);
  harness->password = "pass_" + RandomSuffix();

  const auto setup = EnsureUserExists(harness->sasl_options, harness->username,
                                      harness->password);
  if (setup.kind != SaslSetupResult::Kind::Ok) {
    return setup;
  }

  harness->service = std::make_unique<veritas::auth::v1::GatekeeperServiceImpl>(
      1000, harness->sasl_options);

  grpc::ServerBuilder builder;
  int selected_port = 0;
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(),
                           &selected_port);
  builder.RegisterService(harness->service.get());
  harness->server = builder.BuildAndStart();
  if (!harness->server) {
    return {SaslSetupResult::Kind::Fail, "Failed to start test server"};
  }
  if (selected_port == 0) {
    return {SaslSetupResult::Kind::Fail, "Failed to acquire test port"};
  }
  harness->target = "127.0.0.1:" + std::to_string(selected_port);
  return setup;
}

struct NotaryRecord {
  bool revoked = false;
  std::string reason;
  std::chrono::system_clock::time_point not_before;
  std::chrono::system_clock::time_point not_after;
};

class FakeNotaryService final : public veritas::notary::v1::Notary::Service {
 public:
  explicit FakeNotaryService(std::string expected_refresh_token)
      : expected_refresh_token_(std::move(expected_refresh_token)) {}

  grpc::Status IssueCertificate(
      grpc::ServerContext* /*context*/,
      const veritas::notary::v1::IssueCertificateRequest* request,
      veritas::notary::v1::IssueCertificateResponse* response) override {
    if (!Authorize(request->refresh_token(), response->mutable_error())) {
      return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                          "refresh token rejected");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const std::string serial = "SERIAL-" + std::to_string(++serial_counter_);
    const auto now = std::chrono::system_clock::now();
    const auto ttl = std::chrono::seconds(request->requested_ttl_seconds());
    records_[serial] = NotaryRecord{false, "", now, now + ttl};

    response->set_issued(true);
    response->set_certificate_serial(serial);
    response->set_certificate_pem("leaf-" + serial);
    response->set_certificate_chain_pem("chain-" + serial);
    response->mutable_not_before()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch())
            .count());
    response->mutable_not_after()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            (now + ttl).time_since_epoch())
            .count());
    return grpc::Status::OK;
  }

  grpc::Status RenewCertificate(
      grpc::ServerContext* /*context*/,
      const veritas::notary::v1::RenewCertificateRequest* request,
      veritas::notary::v1::RenewCertificateResponse* response) override {
    if (!Authorize(request->refresh_token(), response->mutable_error())) {
      return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                          "refresh token rejected");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_.find(request->certificate_serial());
    if (it == records_.end()) {
      response->mutable_error()->set_code(
          veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST);
      response->mutable_error()->set_detail("certificate not found");
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "certificate not found");
    }
    const auto now = std::chrono::system_clock::now();
    const auto ttl = std::chrono::seconds(request->requested_ttl_seconds());
    it->second.not_before = now;
    it->second.not_after = now + ttl;

    response->set_renewed(true);
    response->set_certificate_serial(request->certificate_serial());
    response->set_certificate_pem("renewed-" + request->certificate_serial());
    response->set_certificate_chain_pem("chain-" + request->certificate_serial());
    response->mutable_not_before()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch())
            .count());
    response->mutable_not_after()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            (now + ttl).time_since_epoch())
            .count());
    return grpc::Status::OK;
  }

  grpc::Status RevokeCertificate(
      grpc::ServerContext* /*context*/,
      const veritas::notary::v1::RevokeCertificateRequest* request,
      veritas::notary::v1::RevokeCertificateResponse* response) override {
    if (!Authorize(request->refresh_token(), response->mutable_error())) {
      return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                          "refresh token rejected");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_.find(request->certificate_serial());
    if (it == records_.end()) {
      response->mutable_error()->set_code(
          veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST);
      response->mutable_error()->set_detail("certificate not found");
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "certificate not found");
    }
    it->second.revoked = true;
    it->second.reason = request->reason();
    const auto now = std::chrono::system_clock::now();
    response->set_revoked(true);
    response->mutable_revoked_at()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch())
            .count());
    return grpc::Status::OK;
  }

  grpc::Status GetCertificateStatus(
      grpc::ServerContext* /*context*/,
      const veritas::notary::v1::GetCertificateStatusRequest* request,
      veritas::notary::v1::GetCertificateStatusResponse* response) override {
    if (!Authorize(request->refresh_token(), response->mutable_error())) {
      return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                          "refresh token rejected");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_.find(request->certificate_serial());
    if (it == records_.end()) {
      response->set_state(veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNKNOWN);
      return grpc::Status::OK;
    }
    response->mutable_not_before()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            it->second.not_before.time_since_epoch())
            .count());
    response->mutable_not_after()->set_seconds(
        std::chrono::duration_cast<std::chrono::seconds>(
            it->second.not_after.time_since_epoch())
            .count());
    if (it->second.revoked) {
      response->set_state(veritas::notary::v1::CERTIFICATE_STATUS_STATE_REVOKED);
      response->set_reason(it->second.reason);
      response->mutable_revoked_at()->set_seconds(
          std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count());
    } else {
      response->set_state(veritas::notary::v1::CERTIFICATE_STATUS_STATE_ACTIVE);
    }
    return grpc::Status::OK;
  }

 private:
  template <typename ErrorType>
  bool Authorize(std::string_view refresh_token, ErrorType* error) const {
    if (refresh_token != expected_refresh_token_) {
      if (error) {
        error->set_code(veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_INVALID);
        error->set_detail("refresh token does not match authenticated identity");
      }
      return false;
    }
    return true;
  }

  std::string expected_refresh_token_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, NotaryRecord> records_;
  int serial_counter_ = 0;
};

struct NotaryHarness {
  std::unique_ptr<FakeNotaryService> service;
  std::unique_ptr<grpc::Server> server;
  std::string target;
};

bool StartNotary(const std::string& expected_refresh_token, NotaryHarness* harness) {
  if (!harness) {
    return false;
  }
  harness->service =
      std::make_unique<FakeNotaryService>(expected_refresh_token);
  grpc::ServerBuilder builder;
  int selected_port = 0;
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(),
                           &selected_port);
  builder.RegisterService(harness->service.get());
  harness->server = builder.BuildAndStart();
  if (!harness->server || selected_port == 0) {
    return false;
  }
  harness->target = "127.0.0.1:" + std::to_string(selected_port);
  return true;
}

}  // namespace

TEST(AuthFlowIntegrationTest, SrpHappyPath) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;

  AuthFlow flow(config);
  const auto result = flow.Authenticate(harness.username, harness.password);
  EXPECT_FALSE(result.user_uuid.empty());
  EXPECT_FALSE(result.refresh_token.empty());
}

TEST(AuthFlowIntegrationTest, ProtocolNegotiationRejectsUnsupportedMajor) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;
  config.protocol_major = 9;
  config.protocol_minor = 0;

  AuthFlow flow(config);
  try {
    (void)flow.Authenticate(harness.username, harness.password);
    FAIL() << "Expected protocol major version rejection";
  } catch (const GatekeeperError& ex) {
    EXPECT_EQ(ex.code(), grpc::StatusCode::FAILED_PRECONDITION);
  }
}

TEST(AuthFlowIntegrationTest, ProtocolNegotiationAllowsMinorDowngrade) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;
  config.protocol_major = 1;
  config.protocol_minor = 7;

  AuthFlow flow(config);
  const auto result = flow.Authenticate(harness.username, harness.password);
  EXPECT_FALSE(result.user_uuid.empty());
  EXPECT_FALSE(result.refresh_token.empty());
}

TEST(IdentityManagerIntegrationTest, AuthenticatePersistsIdentity) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;

  ::veritas::storage::TokenStoreConfig store_config;
  store_config.backend = ::veritas::storage::TokenStoreBackend::File;
  store_config.allow_insecure_fallback = true;
  store_config.machine_identity_override = "test-machine";
  store_config.file_path = TempPath("veritas_identity_store");

  ::veritas::IdentityManager manager([] { return std::string("unused"); },
                                     store_config);
  const auto result =
      manager.Authenticate(config, harness.username, harness.password);
  const auto persisted = manager.GetPersistedIdentity();
  ASSERT_TRUE(persisted.has_value());
  EXPECT_EQ(persisted->user_uuid, result.user_uuid);
  EXPECT_EQ(persisted->refresh_token, result.refresh_token);

  ::veritas::IdentityManager restored([] { return std::string("unused"); },
                                      store_config);
  const auto reloaded = restored.GetPersistedIdentity();
  ASSERT_TRUE(reloaded.has_value());
  EXPECT_EQ(reloaded->user_uuid, result.user_uuid);
  EXPECT_EQ(reloaded->refresh_token, result.refresh_token);

  restored.ClearPersistedIdentity();
  EXPECT_FALSE(restored.GetPersistedIdentity().has_value());
}

TEST(GatekeeperClientIntegrationTest, InvalidProofIsUnauthenticated) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;

  GatekeeperClient client(config);
  SaslClient sasl_client("veritas_gatekeeper", harness.username,
                         harness.password);
  const std::string client_start = sasl_client.Start();
  if (client_start.empty()) {
    GTEST_SKIP() << "SASL client did not emit initial response";
  }
  const auto begin = client.BeginAuth(harness.username, client_start);

  try {
    client.FinishAuth(begin.session_id, "invalid-proof");
    FAIL() << "FinishAuth should have thrown";
  } catch (const GatekeeperError& ex) {
    EXPECT_EQ(ex.code(), grpc::StatusCode::UNAUTHENTICATED);
  }
}

TEST(GatekeeperClientIntegrationTest, GetTokenStatusRejectsEmptyToken) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;

  GatekeeperClient client(config);
  try {
    static_cast<void>(client.GetTokenStatus(""));
    FAIL() << "GetTokenStatus should reject empty token payload";
  } catch (const GatekeeperError& ex) {
    EXPECT_EQ(ex.code(), grpc::StatusCode::INVALID_ARGUMENT);
  }
}

TEST(IdentityManagerIntegrationTest, RevocationTransitionsToLocked) {
  GatekeeperHarness harness;
  const auto setup = StartGatekeeper(&harness);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig config;
  config.target = harness.target;
  config.allow_insecure = true;

  ::veritas::IdentityManager manager([] { return std::string("unused"); });
  const auto result =
      manager.Authenticate(config, harness.username, harness.password);
  ASSERT_FALSE(result.refresh_token.empty());

  std::atomic<bool> saw_revoked_alert{false};
  manager.on_security_alert([&](::veritas::AlertType alert) {
    if (alert == ::veritas::AlertType::TokenRevoked) {
      saw_revoked_alert.store(true);
    }
  });

  ::veritas::RevocationPolicy policy;
  policy.poll_interval = std::chrono::milliseconds(100);
  policy.lock_deadline = std::chrono::seconds(60);
  manager.StartRevocationMonitor(config, policy);

  GatekeeperClient client(config);
  const auto revoked_at = std::chrono::steady_clock::now();
  client.RevokeToken(result.refresh_token, "integration-revoke");

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  std::optional<std::chrono::steady_clock::time_point> locked_at;
  while (std::chrono::steady_clock::now() < deadline) {
    if (manager.GetState() == ::veritas::IdentityState::Locked) {
      locked_at = std::chrono::steady_clock::now();
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }

  manager.StopRevocationMonitor();
  EXPECT_EQ(manager.GetState(), ::veritas::IdentityState::Locked);
  EXPECT_TRUE(saw_revoked_alert.load());
  ASSERT_TRUE(locked_at.has_value());
  const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      *locked_at - revoked_at);
  EXPECT_LE(elapsed.count(), 60);
}

TEST(IdentityManagerIntegrationTest, NotaryLifecycleUsesAuthenticatedToken) {
  GatekeeperHarness gatekeeper;
  const auto setup = StartGatekeeper(&gatekeeper);
  if (setup.kind == SaslSetupResult::Kind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResult::Kind::Ok) << setup.message;

  GatekeeperClientConfig gatekeeper_config;
  gatekeeper_config.target = gatekeeper.target;
  gatekeeper_config.allow_insecure = true;

  ::veritas::IdentityManager manager([] { return std::string("unused"); });
  const auto auth_result = manager.Authenticate(
      gatekeeper_config, gatekeeper.username, gatekeeper.password);
  ASSERT_FALSE(auth_result.refresh_token.empty());

  NotaryHarness notary;
  ASSERT_TRUE(StartNotary(auth_result.refresh_token, &notary));

  ::veritas::NotaryClientConfig notary_config;
  notary_config.target = notary.target;
  notary_config.allow_insecure = true;

  const auto issued = manager.IssueCertificate(
      notary_config, "csr-der", 600, "idem-issue");
  EXPECT_FALSE(issued.certificate_serial.empty());
  EXPECT_FALSE(issued.certificate_pem.empty());

  const auto renewed = manager.RenewCertificate(
      notary_config, issued.certificate_serial, 600, "idem-renew");
  EXPECT_EQ(renewed.certificate_serial, issued.certificate_serial);
  EXPECT_FALSE(renewed.certificate_pem.empty());

  EXPECT_NO_THROW(manager.RevokeCertificate(notary_config,
                                            issued.certificate_serial,
                                            "TOKEN_REVOKED",
                                            "integration-test"));

  const auto status = manager.GetCertificateStatus(
      notary_config, issued.certificate_serial);
  EXPECT_EQ(status.state, ::veritas::CertificateStatusState::Revoked);
  EXPECT_EQ(status.reason, "TOKEN_REVOKED");
}

}  // namespace veritas::auth
