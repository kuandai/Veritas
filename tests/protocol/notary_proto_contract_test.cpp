#include <gtest/gtest.h>

#include <google/protobuf/descriptor.h>

#include "notary.pb.h"

namespace {

TEST(NotaryProtoContractTest, ServiceShapeIsFrozen) {
  const auto* service =
      google::protobuf::DescriptorPool::generated_pool()->FindServiceByName(
          "veritas.notary.v1.Notary");
  ASSERT_NE(service, nullptr);
  ASSERT_EQ(service->method_count(), 4);
  EXPECT_EQ(service->method(0)->name(), "IssueCertificate");
  EXPECT_EQ(service->method(1)->name(), "RenewCertificate");
  EXPECT_EQ(service->method(2)->name(), "RevokeCertificate");
  EXPECT_EQ(service->method(3)->name(), "GetCertificateStatus");
}

TEST(NotaryProtoContractTest, ErrorCodeValuesAreStable) {
  using veritas::notary::v1::NOTARY_ERROR_CODE_ALREADY_REVOKED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_INTERNAL;
  using veritas::notary::v1::NOTARY_ERROR_CODE_INVALID_REQUEST;
  using veritas::notary::v1::NOTARY_ERROR_CODE_POLICY_DENIED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_RATE_LIMITED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE;
  using veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_EXPIRED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_INVALID;
  using veritas::notary::v1::NOTARY_ERROR_CODE_TOKEN_REVOKED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_UNAUTHORIZED;
  using veritas::notary::v1::NOTARY_ERROR_CODE_UNSPECIFIED;

  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_UNSPECIFIED), 0);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_INVALID_REQUEST), 1);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_UNAUTHORIZED), 2);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_TOKEN_INVALID), 3);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_TOKEN_EXPIRED), 4);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_TOKEN_REVOKED), 5);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_POLICY_DENIED), 6);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_ALREADY_REVOKED), 7);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_RATE_LIMITED), 8);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_TEMPORARILY_UNAVAILABLE), 9);
  EXPECT_EQ(static_cast<int>(NOTARY_ERROR_CODE_INTERNAL), 10);
}

TEST(NotaryProtoContractTest, StatusEnumValuesAreStable) {
  using veritas::notary::v1::CERTIFICATE_STATUS_STATE_ACTIVE;
  using veritas::notary::v1::CERTIFICATE_STATUS_STATE_EXPIRED;
  using veritas::notary::v1::CERTIFICATE_STATUS_STATE_REVOKED;
  using veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNKNOWN;
  using veritas::notary::v1::CERTIFICATE_STATUS_STATE_UNSPECIFIED;

  EXPECT_EQ(static_cast<int>(CERTIFICATE_STATUS_STATE_UNSPECIFIED), 0);
  EXPECT_EQ(static_cast<int>(CERTIFICATE_STATUS_STATE_ACTIVE), 1);
  EXPECT_EQ(static_cast<int>(CERTIFICATE_STATUS_STATE_REVOKED), 2);
  EXPECT_EQ(static_cast<int>(CERTIFICATE_STATUS_STATE_EXPIRED), 3);
  EXPECT_EQ(static_cast<int>(CERTIFICATE_STATUS_STATE_UNKNOWN), 4);
}

TEST(NotaryProtoContractTest, IssueRequestContainsCoreFields) {
  const auto* descriptor =
      veritas::notary::v1::IssueCertificateRequest::descriptor();
  ASSERT_NE(descriptor, nullptr);
  EXPECT_NE(descriptor->FindFieldByName("refresh_token"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("csr_der"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("requested_ttl_seconds"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("idempotency_key"), nullptr);
}

TEST(NotaryProtoContractTest, StatusResponseContainsErrorAndStateFields) {
  const auto* descriptor =
      veritas::notary::v1::GetCertificateStatusResponse::descriptor();
  ASSERT_NE(descriptor, nullptr);
  EXPECT_NE(descriptor->FindFieldByName("state"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("reason"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("revoked_at"), nullptr);
  EXPECT_NE(descriptor->FindFieldByName("error"), nullptr);
}

}  // namespace
