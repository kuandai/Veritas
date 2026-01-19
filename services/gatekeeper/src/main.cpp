#include <iostream>

#include "veritas/shared/shared.h"

int main() {
  std::cout << "veritas gatekeeper (shared "
            << veritas::shared::shared_build_id() << ")\n";
  return 0;
}
