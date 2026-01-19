#include <iostream>

#include "veritas/shared/shared.h"

int main() {
  std::cout << "veritas notary (shared "
            << veritas::shared::shared_build_id() << ")\n";
  return 0;
}
