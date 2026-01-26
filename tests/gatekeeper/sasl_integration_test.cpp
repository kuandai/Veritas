#include "sasl_server.h"

#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <sasl/sasl.h>

namespace veritas::gatekeeper {
namespace {

struct SaslSecretDeleter {
  void operator()(sasl_secret_t* secret) const { free(secret); }
};

struct ClientCreds {
  std::string username;
  std::string password;
  std::unique_ptr<sasl_secret_t, SaslSecretDeleter> secret;
};

int SaslGetSimple(void* context, int id, const char** result, unsigned* len) {
  if (!context || !result) {
    return SASL_BADPARAM;
  }
  auto* creds = static_cast<ClientCreds*>(context);
  if (id == SASL_CB_AUTHNAME || id == SASL_CB_USER) {
    *result = creds->username.c_str();
    if (len) {
      *len = static_cast<unsigned>(creds->username.size());
    }
    return SASL_OK;
  }
  return SASL_FAIL;
}

int SaslGetSecret(sasl_conn_t* /*conn*/, void* context, int id,
                  sasl_secret_t** psecret) {
  if (!context || !psecret || id != SASL_CB_PASS) {
    return SASL_BADPARAM;
  }
  auto* creds = static_cast<ClientCreds*>(context);
  if (!creds->secret) {
    const std::size_t size = sizeof(sasl_secret_t) + creds->password.size();
    auto* raw = static_cast<sasl_secret_t*>(std::malloc(size));
    if (!raw) {
      return SASL_NOMEM;
    }
    raw->len = static_cast<unsigned>(creds->password.size());
    std::memcpy(raw->data, creds->password.data(), creds->password.size());
    creds->secret.reset(raw);
  }
  *psecret = creds->secret.get();
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

struct SaslFixture {
  SaslServerOptions options;
  std::string db_path;
  std::string username;
  std::string password;
  std::optional<SaslServer> server;

  SaslFixture() {
    db_path = TempPath("veritas_sasldb");
    username = "user_" + RandomSuffix();
    password = "pass_" + RandomSuffix();

    options.fake_salt_secret = "test-secret";
    options.sasl_service = "veritas_gatekeeper";
    options.sasl_mech_list = "SRP";
    options.sasl_dbname = db_path;

    server.emplace(options);
  }
};

bool MechanismAvailable(sasl_conn_t* conn, const std::string& mech) {
  const char* list = nullptr;
  unsigned list_len = 0;
  int count = 0;
  if (sasl_listmech(conn, nullptr, "", " ", "", &list, &list_len, &count) !=
      SASL_OK) {
    return false;
  }
  if (!list || list_len == 0) {
    return false;
  }
  std::string_view mechs(list, list_len);
  return mechs.find(mech) != std::string_view::npos;
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

enum class SaslSetupResultKind {
  Ok,
  Skip,
  Fail,
};

struct SaslSetupResult {
  SaslSetupResultKind kind = SaslSetupResultKind::Fail;
  std::string message;
};

SaslSetupResult EnsureUserExists(SaslFixture& fixture) {
  veritas::auth::v1::BeginAuthRequest warmup_request;
  veritas::auth::v1::BeginAuthResponse warmup_response;
  warmup_request.set_login_username("warmup_" + RandomSuffix());
  const grpc::Status warmup_status =
      fixture.server->BeginAuth(warmup_request, &warmup_response);
  if (!warmup_status.ok()) {
    if (IsSrpUnavailable(warmup_status)) {
      return {SaslSetupResultKind::Skip,
              "SRP mechanism not available in SASL build"};
    }
    return {SaslSetupResultKind::Fail, warmup_status.error_message()};
  }

  sasl_conn_t* conn = nullptr;
  const char* realm = fixture.options.sasl_realm.empty()
                           ? nullptr
                           : fixture.options.sasl_realm.c_str();
  int rc = sasl_server_new(fixture.options.sasl_service.c_str(), nullptr, realm,
                           nullptr, nullptr, nullptr, 0, &conn);
  if (rc != SASL_OK) {
    return {SaslSetupResultKind::Skip,
            "SASL server init unavailable for setpass"};
  }

  if (!MechanismAvailable(conn, "SRP")) {
    sasl_dispose(&conn);
    return {SaslSetupResultKind::Skip,
            "SRP mechanism not available in SASL build"};
  }

  rc = sasl_setpass(conn, fixture.username.c_str(), fixture.password.c_str(),
                    static_cast<unsigned>(fixture.password.size()), nullptr, 0,
                    SASL_SET_CREATE | SASL_SET_NOPLAIN);
  sasl_dispose(&conn);
  if (rc == SASL_OK || rc == SASL_NOCHANGE) {
    return {SaslSetupResultKind::Ok, ""};
  }
  if (rc == SASL_NOMECH || rc == SASL_NOUSERPASS) {
    return {SaslSetupResultKind::Skip,
            "SASL SRP setpass not supported in this build"};
  }
  return {SaslSetupResultKind::Fail,
          std::string("sasl_setpass failed: ") +
              sasl_errstring(rc, nullptr, nullptr)};
}

int EnsureClientInit() {
  static std::once_flag once;
  static int result = SASL_FAIL;
  std::call_once(once, []() { result = sasl_client_init(nullptr); });
  return result;
}

}  // namespace

TEST(SaslIntegrationTest, SrpHandshakeHappyPath) {
  SaslFixture fixture;
  const auto setup = EnsureUserExists(fixture);
  if (setup.kind == SaslSetupResultKind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResultKind::Ok) << setup.message;
  if (EnsureClientInit() != SASL_OK) {
    GTEST_SKIP() << "SASL client initialization failed";
  }

  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username(fixture.username);
  const grpc::Status begin_status =
      fixture.server->BeginAuth(begin_request, &begin_response);
  if (!begin_status.ok()) {
    if (IsSrpUnavailable(begin_status)) {
      GTEST_SKIP() << "SRP mechanism not available in SASL build";
    }
    ASSERT_TRUE(begin_status.ok());
  }

  ClientCreds creds{fixture.username, fixture.password};
  sasl_callback_t callbacks[] = {
      {SASL_CB_AUTHNAME, reinterpret_cast<int (*)(void)>(&SaslGetSimple), &creds},
      {SASL_CB_USER, reinterpret_cast<int (*)(void)>(&SaslGetSimple), &creds},
      {SASL_CB_PASS, reinterpret_cast<int (*)(void)>(&SaslGetSecret), &creds},
      {SASL_CB_LIST_END, nullptr, nullptr},
  };

  sasl_conn_t* client_conn = nullptr;
  int rc = sasl_client_new(fixture.options.sasl_service.c_str(), "localhost",
                           nullptr, nullptr, callbacks, 0, &client_conn);
  ASSERT_EQ(rc, SASL_OK);

  const char* client_out = nullptr;
  unsigned client_out_len = 0;
  const char* mech = nullptr;
  rc = sasl_client_start(client_conn, "SRP", nullptr, &client_out,
                         &client_out_len, &mech);
  if (rc == SASL_NOMECH) {
    sasl_dispose(&client_conn);
    GTEST_SKIP() << "SRP mechanism not available for client";
  }
  ASSERT_TRUE(rc == SASL_CONTINUE || rc == SASL_OK);

  rc = sasl_client_step(
      client_conn, begin_response.server_public().data(),
      static_cast<unsigned>(begin_response.server_public().size()), nullptr,
      &client_out, &client_out_len);
  ASSERT_TRUE(rc == SASL_CONTINUE || rc == SASL_OK);

  veritas::auth::v1::FinishAuthRequest finish_request;
  veritas::auth::v1::FinishAuthResponse finish_response;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof(
      std::string(client_out ? client_out : "", client_out_len));

  const grpc::Status finish_status =
      fixture.server->FinishAuth(finish_request, &finish_response);
  ASSERT_TRUE(finish_status.ok());
  EXPECT_FALSE(finish_response.refresh_token().empty());
  EXPECT_FALSE(finish_response.user_uuid().empty());
  EXPECT_FALSE(finish_response.server_proof().empty());

  rc = sasl_client_step(
      client_conn, finish_response.server_proof().data(),
      static_cast<unsigned>(finish_response.server_proof().size()), nullptr,
      &client_out, &client_out_len);
  EXPECT_EQ(rc, SASL_OK);

  sasl_dispose(&client_conn);
}

TEST(SaslIntegrationTest, InvalidProofIsUnauthenticated) {
  SaslFixture fixture;
  const auto setup = EnsureUserExists(fixture);
  if (setup.kind == SaslSetupResultKind::Skip) {
    GTEST_SKIP() << setup.message;
  }
  ASSERT_EQ(setup.kind, SaslSetupResultKind::Ok) << setup.message;

  veritas::auth::v1::BeginAuthRequest begin_request;
  veritas::auth::v1::BeginAuthResponse begin_response;
  begin_request.set_login_username(fixture.username);
  const grpc::Status begin_status =
      fixture.server->BeginAuth(begin_request, &begin_response);
  if (!begin_status.ok()) {
    if (IsSrpUnavailable(begin_status)) {
      GTEST_SKIP() << "SRP mechanism not available in SASL build";
    }
    ASSERT_TRUE(begin_status.ok());
  }

  veritas::auth::v1::FinishAuthRequest finish_request;
  veritas::auth::v1::FinishAuthResponse finish_response;
  finish_request.set_session_id(begin_response.session_id());
  finish_request.set_client_proof("invalid-proof");

  const grpc::Status finish_status =
      fixture.server->FinishAuth(finish_request, &finish_response);
  EXPECT_EQ(finish_status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

}  // namespace veritas::gatekeeper
