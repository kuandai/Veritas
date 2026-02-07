#include "sasl_client.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>

#include <sodium.h>

namespace veritas::auth {

namespace {
std::once_flag g_sasl_init_once;
int g_sasl_init_result = SASL_OK;
std::string g_sasl_init_error;

struct GlobalCallbackContext {
  std::string plugin_path;
  std::string conf_path;
  std::string realm;
};

GlobalCallbackContext g_global_ctx;
std::vector<sasl_callback_t> g_global_callbacks;

bool IsDebugEnabled() {
  const char* env = std::getenv("VERITAS_SASL_DEBUG");
  if (!env || env[0] == '\0') {
    return false;
  }
  return std::strcmp(env, "0") != 0 && std::strcmp(env, "false") != 0 &&
         std::strcmp(env, "no") != 0;
}

int GlobalGetPath(void* context, const char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<GlobalCallbackContext*>(context);
  if (ctx->plugin_path.empty()) {
    return SASL_FAIL;
  }
  *path = ctx->plugin_path.c_str();
  return SASL_OK;
}

int GlobalGetConfPath(void* context, char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<GlobalCallbackContext*>(context);
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

int GlobalGetRealm(void* context,
                   int /*id*/,
                   const char** /*availrealms*/,
                   const char** result) {
  if (!context || !result) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<GlobalCallbackContext*>(context);
  if (ctx->realm.empty()) {
    return SASL_FAIL;
  }
  *result = ctx->realm.c_str();
  return SASL_OK;
}
}  // namespace

SaslClient::SecretBuffer::SecretBuffer(std::string_view password) {
  buffer_.resize(sizeof(sasl_secret_t) + password.size());
  auto* secret = reinterpret_cast<sasl_secret_t*>(buffer_.data());
  secret->len = static_cast<unsigned>(password.size());
  if (!password.empty()) {
    std::memcpy(secret->data, password.data(), password.size());
  }
}

SaslClient::SecretBuffer::~SecretBuffer() {
  if (!buffer_.empty()) {
    sodium_memzero(buffer_.data(), buffer_.size());
  }
}

sasl_secret_t* SaslClient::SecretBuffer::get() {
  return reinterpret_cast<sasl_secret_t*>(buffer_.data());
}

SaslClient::SaslClient(std::string service,
                       std::string username,
                       std::string_view password)
    : service_(std::move(service)) {
  EnsureInitialized();
  if (g_sasl_init_result != SASL_OK) {
    throw std::runtime_error(g_sasl_init_error);
  }

  context_ = std::make_unique<CallbackContext>(
      CallbackContext{std::move(username), SecretBuffer(password), "", "", ""});

  if (const char* env = std::getenv("SASL_PATH")) {
    context_->plugin_path = env;
  }
  if (const char* env = std::getenv("SASL_CONF_PATH")) {
    context_->conf_path = env;
  }
  if (const char* env = std::getenv("SASL_REALM")) {
    context_->realm = env;
  }

  auto add_callback = [this](unsigned long id,
                             int (*proc)(void),
                             void* ctx) {
    sasl_callback_t cb{};
    cb.id = id;
    cb.proc = reinterpret_cast<int (*)(void)>(proc);
    cb.context = ctx;
    callbacks_.push_back(cb);
  };

  add_callback(SASL_CB_AUTHNAME,
               reinterpret_cast<int (*)(void)>(&SaslClient::GetSimple),
               context_.get());
  add_callback(SASL_CB_USER,
               reinterpret_cast<int (*)(void)>(&SaslClient::GetSimple),
               context_.get());
  add_callback(SASL_CB_PASS,
               reinterpret_cast<int (*)(void)>(&SaslClient::GetSecret),
               context_.get());
  if (!context_->plugin_path.empty()) {
    add_callback(SASL_CB_GETPATH,
                 reinterpret_cast<int (*)(void)>(&SaslClient::GetPath),
                 context_.get());
  }
  if (!context_->conf_path.empty()) {
    add_callback(SASL_CB_GETCONFPATH,
                 reinterpret_cast<int (*)(void)>(&SaslClient::GetConfPath),
                 context_.get());
  }
  if (!context_->realm.empty()) {
    add_callback(SASL_CB_GETREALM,
                 reinterpret_cast<int (*)(void)>(&SaslClient::GetRealm),
                 context_.get());
  }

  sasl_callback_t end_cb{};
  end_cb.id = SASL_CB_LIST_END;
  callbacks_.push_back(end_cb);

  const int result = sasl_client_new(service_.c_str(), nullptr, nullptr, nullptr,
                                     callbacks_.data(), 0, &conn_);
  if (result != SASL_OK) {
    throw std::runtime_error("SASL client init failed");
  }
}

SaslClient::~SaslClient() {
  if (conn_) {
    sasl_dispose(&conn_);
    conn_ = nullptr;
  }
}

void SaslClient::EnsureInitialized() {
  std::call_once(g_sasl_init_once, []() {
    g_global_callbacks.clear();
    if (const char* env = std::getenv("SASL_PATH")) {
      g_global_ctx.plugin_path = env;
    }
    if (const char* env = std::getenv("SASL_CONF_PATH")) {
      g_global_ctx.conf_path = env;
    }
    if (const char* env = std::getenv("SASL_REALM")) {
      g_global_ctx.realm = env;
    }

    auto add_callback = [](unsigned long id, int (*proc)(void), void* ctx) {
      sasl_callback_t cb{};
      cb.id = id;
      cb.proc = reinterpret_cast<int (*)(void)>(proc);
      cb.context = ctx;
      g_global_callbacks.push_back(cb);
    };
    if (!g_global_ctx.plugin_path.empty()) {
      add_callback(SASL_CB_GETPATH,
                   reinterpret_cast<int (*)(void)>(&GlobalGetPath),
                   &g_global_ctx);
    }
    if (!g_global_ctx.conf_path.empty()) {
      add_callback(SASL_CB_GETCONFPATH,
                   reinterpret_cast<int (*)(void)>(&GlobalGetConfPath),
                   &g_global_ctx);
    }
    if (!g_global_ctx.realm.empty()) {
      add_callback(SASL_CB_GETREALM,
                   reinterpret_cast<int (*)(void)>(&GlobalGetRealm),
                   &g_global_ctx);
    }
    sasl_callback_t end_cb{};
    end_cb.id = SASL_CB_LIST_END;
    g_global_callbacks.push_back(end_cb);

    g_sasl_init_result = sasl_client_init(g_global_callbacks.data());
    if (g_sasl_init_result != SASL_OK) {
      const char* err = sasl_errstring(g_sasl_init_result, nullptr, nullptr);
      g_sasl_init_error = "SASL client initialization failed";
      if (err) {
        g_sasl_init_error += ": ";
        g_sasl_init_error += err;
      }
    }
  });
}

int SaslClient::GetSimple(void* context,
                          int id,
                          const char** result,
                          unsigned* len) {
  if (!context || !result) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<CallbackContext*>(context);
  if (id == SASL_CB_AUTHNAME || id == SASL_CB_USER) {
    *result = ctx->username.c_str();
    if (len) {
      *len = static_cast<unsigned>(ctx->username.size());
    }
    return SASL_OK;
  }
  return SASL_FAIL;
}

int SaslClient::GetSecret(sasl_conn_t* /*conn*/,
                          void* context,
                          int id,
                          sasl_secret_t** psecret) {
  if (!context || !psecret || id != SASL_CB_PASS) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<CallbackContext*>(context);
  *psecret = ctx->secret.get();
  return SASL_OK;
}

int SaslClient::GetPath(void* context, const char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<CallbackContext*>(context);
  if (ctx->plugin_path.empty()) {
    return SASL_FAIL;
  }
  *path = ctx->plugin_path.c_str();
  return SASL_OK;
}

int SaslClient::GetConfPath(void* context, char** path) {
  if (!context || !path) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<CallbackContext*>(context);
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

int SaslClient::GetRealm(void* context,
                         int /*id*/,
                         const char** /*availrealms*/,
                         const char** result) {
  if (!context || !result) {
    return SASL_BADPARAM;
  }
  auto* ctx = static_cast<CallbackContext*>(context);
  if (ctx->realm.empty()) {
    return SASL_FAIL;
  }
  *result = ctx->realm.c_str();
  return SASL_OK;
}

std::string SaslClient::Start() {
  if (started_) {
    return initial_response_;
  }
  const char* out = nullptr;
  unsigned out_len = 0;
  const char* mech = nullptr;
  const int result = sasl_client_start(conn_, "SRP", nullptr, &out, &out_len,
                                       &mech);
  if (result != SASL_CONTINUE && result != SASL_OK) {
    throw std::runtime_error("SASL client start failed");
  }
  if (IsDebugEnabled()) {
    std::cerr << "[sasl-client] initial_response_len=" << out_len << "\n";
  }
  if (IsDebugEnabled()) {
    const void* prop = nullptr;
    if (sasl_getprop(conn_, SASL_USERNAME, &prop) == SASL_OK && prop) {
      const char* value = static_cast<const char*>(prop);
      if (value && value[0] != '\0') {
        std::cerr << "[sasl-client] username=" << value << "\n";
      }
    }
  }
  if (out && out_len > 0) {
    initial_response_.assign(out, out_len);
  }
  started_ = true;
  return initial_response_;
}

std::string SaslClient::ComputeClientProof(std::string_view server_public) {
  Start();
  const char* out = nullptr;
  unsigned out_len = 0;
  const int result = sasl_client_step(conn_, server_public.data(),
                                      static_cast<unsigned>(server_public.size()),
                                      nullptr, &out, &out_len);
  if (result != SASL_CONTINUE && result != SASL_OK) {
    throw std::runtime_error("SASL client step failed");
  }
  if (!out || out_len == 0) {
    throw std::runtime_error("SASL client proof missing");
  }
  return std::string(out, out_len);
}

void SaslClient::VerifyServerProof(std::string_view server_proof) {
  const char* out = nullptr;
  unsigned out_len = 0;
  const int result = sasl_client_step(conn_, server_proof.data(),
                                      static_cast<unsigned>(server_proof.size()),
                                      nullptr, &out, &out_len);
  if (result != SASL_OK) {
    throw std::runtime_error("SASL server proof verification failed");
  }
}

}  // namespace veritas::auth
