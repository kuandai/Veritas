#include <auth/auth_flow.h>
#include <auth/gatekeeper_client.h>

#include <sasl/sasl.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct DemoArgs {
  std::string target = "127.0.0.1:50051";
  std::string username;
  std::string password;
  std::string root_cert_path;
  bool allow_insecure = false;
  bool provision = false;
  std::string sasldb_path;
  std::string sasl_service = "veritas_gatekeeper";
  std::string sasl_mech_list = "SRP";
  std::string sasl_realm;
};

void PrintUsage(const char* name) {
  std::cout
      << "Usage: " << name << " --username USER --password PASS [options]\n"
      << "Options:\n"
      << "  --target ADDR            Gatekeeper address (default: 127.0.0.1:50051)\n"
      << "  --root-cert PATH         Root cert PEM for TLS verification\n"
      << "  --allow-insecure         Use insecure gRPC (dev only)\n"
      << "  --provision              Create/overwrite SASL user in sasldb\n"
      << "  --sasldb PATH            sasldb2 file path (or SASL_DBNAME env)\n"
      << "  --sasl-service NAME      SASL service name (default: veritas_gatekeeper)\n"
      << "  --sasl-realm REALM       SASL realm (or SASL_REALM env)\n"
      << "  --help                   Show this help\n";
}

bool ParseArgs(int argc, char** argv, DemoArgs* args) {
  if (!args) {
    return false;
  }
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    auto next = [&]() -> const char* {
      if (i + 1 >= argc) {
        return nullptr;
      }
      return argv[++i];
    };
    if (arg == "--help") {
      PrintUsage(argv[0]);
      return false;
    }
    if (arg == "--target") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->target = value;
      continue;
    }
    if (arg == "--username") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->username = value;
      continue;
    }
    if (arg == "--password") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->password = value;
      continue;
    }
    if (arg == "--root-cert") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->root_cert_path = value;
      continue;
    }
    if (arg == "--allow-insecure") {
      args->allow_insecure = true;
      continue;
    }
    if (arg == "--provision") {
      args->provision = true;
      continue;
    }
    if (arg == "--sasldb") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->sasldb_path = value;
      continue;
    }
    if (arg == "--sasl-service") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->sasl_service = value;
      continue;
    }
    if (arg == "--sasl-realm") {
      const char* value = next();
      if (!value) {
        return false;
      }
      args->sasl_realm = value;
      continue;
    }
    std::cerr << "Unknown argument: " << arg << "\n";
    return false;
  }

  if (args->username.empty() || args->password.empty()) {
    return false;
  }
  return true;
}

std::string ReadFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path);
  }
  std::string data;
  file.seekg(0, std::ios::end);
  const auto size = file.tellg();
  if (size > 0) {
    data.resize(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(data.data(), size);
  }
  return data;
}

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

int ProvisionUser(const DemoArgs& args) {
  SaslCallbackContext cb_ctx;
  if (const char* env = std::getenv("SASL_CONF_PATH")) {
    cb_ctx.conf_path = env;
  }
  if (const char* env = std::getenv("SASL_PATH")) {
    cb_ctx.plugin_path = env;
  }
  if (const char* env = std::getenv("SASL_PLUGIN_PATH")) {
    if (cb_ctx.plugin_path.empty()) {
      cb_ctx.plugin_path = env;
    }
  }
  if (const char* env = std::getenv("SASL_DBNAME")) {
    cb_ctx.dbname = env;
  }
  if (!args.sasldb_path.empty()) {
    cb_ctx.dbname = args.sasldb_path;
  }
  if (const char* env = std::getenv("SASL_MECH_LIST")) {
    cb_ctx.mech_list = env;
  } else {
    cb_ctx.mech_list = args.sasl_mech_list;
  }

  if (cb_ctx.dbname.empty()) {
    std::cerr << "Missing sasldb path. Set --sasldb or SASL_DBNAME.\n";
    return 1;
  }

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

  int rc = sasl_server_init(callbacks.data(), "veritas_auth_demo");
  if (rc != SASL_OK) {
    std::cerr << "sasl_server_init failed: "
              << sasl_errstring(rc, nullptr, nullptr) << "\n";
    return 1;
  }

  sasl_conn_t* conn = nullptr;
  std::string realm = args.sasl_realm;
  if (realm.empty()) {
    if (const char* env = std::getenv("SASL_REALM")) {
      realm = env;
    }
  }
  const char* realm_ptr = realm.empty() ? nullptr : realm.c_str();
  rc = sasl_server_new(args.sasl_service.c_str(), nullptr, realm_ptr, nullptr,
                       nullptr, callbacks.data(), 0, &conn);
  if (rc != SASL_OK) {
    std::cerr << "sasl_server_new failed: "
              << sasl_errstring(rc, nullptr, nullptr) << "\n";
    return 1;
  }

  rc = sasl_setpass(conn, args.username.c_str(), args.password.c_str(),
                    static_cast<unsigned>(args.password.size()), nullptr, 0,
                    SASL_SET_CREATE | SASL_SET_NOPLAIN);
  sasl_dispose(&conn);
  if (rc != SASL_OK && rc != SASL_NOCHANGE) {
    std::cerr << "sasl_setpass failed: "
              << sasl_errstring(rc, nullptr, nullptr) << "\n";
    return 1;
  }

  std::cout << "Provisioned SASL user " << args.username << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  DemoArgs args;
  if (!ParseArgs(argc, argv, &args)) {
    PrintUsage(argv[0]);
    return 1;
  }

  if (args.provision) {
    return ProvisionUser(args);
  }

  veritas::auth::GatekeeperClientConfig config;
  config.target = args.target;
  config.allow_insecure = args.allow_insecure;
  if (!args.root_cert_path.empty()) {
    config.root_cert_pem = ReadFile(args.root_cert_path);
  }

  try {
    veritas::auth::AuthFlow flow(config);
    const auto result = flow.Authenticate(args.username, args.password);
    std::cout << "Authenticated user_uuid=" << result.user_uuid << "\n"
              << "Refresh token: " << result.refresh_token << "\n";
  } catch (const std::exception& ex) {
    std::cerr << "Authentication failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
