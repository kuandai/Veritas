#include "auth/auth_flow.h"
#include "auth/gatekeeper_client.h"

#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <sasl/sasl.h>

#include "gatekeeper_service.h"
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
  veritas::auth::v1::BeginAuthRequest warmup_request;
  veritas::auth::v1::BeginAuthResponse warmup_response;
  warmup_request.set_login_username("warmup_" + RandomSuffix());
  const grpc::Status warmup_status =
      server.BeginAuth(warmup_request, &warmup_response);
  if (!warmup_status.ok()) {
    if (IsSrpUnavailable(warmup_status)) {
      return {SaslSetupResult::Kind::Skip,
              "SRP mechanism not available in SASL build"};
    }
    return {SaslSetupResult::Kind::Fail, warmup_status.error_message()};
  }

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
  if (rc == SASL_OK || rc == SASL_NOCHANGE) {
    return {SaslSetupResult::Kind::Ok, ""};
  }
  if (rc == SASL_NOMECH || rc == SASL_NOUSERPASS) {
    return {SaslSetupResult::Kind::Skip,
            "SASL SRP setpass not supported in this build"};
  }
  return {SaslSetupResult::Kind::Fail,
          std::string("sasl_setpass failed: ") +
              sasl_errstring(rc, nullptr, nullptr)};
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
  harness->sasl_options.fake_salt_secret = "test-secret";
  harness->sasl_options.sasl_mech_list = "SRP";
  harness->sasl_options.sasl_service = "veritas_gatekeeper";
  harness->sasl_options.sasl_dbname = TempPath("veritas_sasldb");

  harness->username = "user_" + RandomSuffix();
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
  const auto begin = client.BeginAuth(harness.username);

  try {
    client.FinishAuth(begin.session_id, "invalid-proof");
    FAIL() << "FinishAuth should have thrown";
  } catch (const GatekeeperError& ex) {
    EXPECT_EQ(ex.code(), grpc::StatusCode::UNAUTHENTICATED);
  }
}

}  // namespace veritas::auth
