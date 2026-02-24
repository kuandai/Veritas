#include <gtest/gtest.h>

#include <google/protobuf/descriptor.h>

#include "identity.pb.h"

namespace {

TEST(IdentityProtoContractTest, ServiceShapeIsFrozen) {
  const auto* service =
      google::protobuf::DescriptorPool::generated_pool()->FindServiceByName(
          "veritas.identity.v1.Identity");
  ASSERT_NE(service, nullptr);
  ASSERT_EQ(service->method_count(), 1);
  EXPECT_EQ(service->method(0)->name(), "Negotiate");
}

TEST(IdentityProtoContractTest, NegotiationResultValuesAreStable) {
  using veritas::identity::v1::NEGOTIATION_RESULT_ACCEPTED;
  using veritas::identity::v1::NEGOTIATION_RESULT_DOWNGRADED;
  using veritas::identity::v1::NEGOTIATION_RESULT_INVALID;
  using veritas::identity::v1::NEGOTIATION_RESULT_UNSUPPORTED;
  using veritas::identity::v1::NEGOTIATION_RESULT_UNSPECIFIED;

  EXPECT_EQ(static_cast<int>(NEGOTIATION_RESULT_UNSPECIFIED), 0);
  EXPECT_EQ(static_cast<int>(NEGOTIATION_RESULT_ACCEPTED), 1);
  EXPECT_EQ(static_cast<int>(NEGOTIATION_RESULT_DOWNGRADED), 2);
  EXPECT_EQ(static_cast<int>(NEGOTIATION_RESULT_UNSUPPORTED), 3);
  EXPECT_EQ(static_cast<int>(NEGOTIATION_RESULT_INVALID), 4);
}

TEST(IdentityProtoContractTest, NegotiationPayloadFieldsExist) {
  const auto* request_descriptor =
      veritas::identity::v1::NegotiateRequest::descriptor();
  ASSERT_NE(request_descriptor, nullptr);
  EXPECT_NE(request_descriptor->FindFieldByName("supported_versions"), nullptr);

  const auto* response_descriptor =
      veritas::identity::v1::NegotiateResponse::descriptor();
  ASSERT_NE(response_descriptor, nullptr);
  EXPECT_NE(response_descriptor->FindFieldByName("result"), nullptr);
  EXPECT_NE(response_descriptor->FindFieldByName("selected_version"), nullptr);
  EXPECT_NE(response_descriptor->FindFieldByName("detail"), nullptr);
}

}  // namespace
