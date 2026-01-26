#include "sasl_client.h"

#include <cstring>
#include <mutex>
#include <stdexcept>

#include <sodium.h>

namespace veritas::auth {

namespace {
std::once_flag g_sasl_init_once;
int g_sasl_init_result = SASL_OK;
std::string g_sasl_init_error;
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
      CallbackContext{std::move(username), SecretBuffer(password)});

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

  sasl_callback_t end_cb{};
  end_cb.id = SASL_CB_LIST_END;
  callbacks_.push_back(end_cb);

  const int result = sasl_client_new(service_.c_str(), "localhost", nullptr,
                                     nullptr, callbacks_.data(), 0, &conn_);
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
    g_sasl_init_result = sasl_client_init(nullptr);
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

void SaslClient::Start() {
  if (started_) {
    return;
  }
  const char* out = nullptr;
  unsigned out_len = 0;
  const char* mech = nullptr;
  const int result = sasl_client_start(conn_, "SRP", nullptr, &out, &out_len,
                                       &mech);
  if (result != SASL_CONTINUE && result != SASL_OK) {
    throw std::runtime_error("SASL client start failed");
  }
  if (out_len > 0) {
    throw std::runtime_error("Unexpected SASL initial response for SRP");
  }
  started_ = true;
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
