#include "loader.hpp"
#include <iostream>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <binary>" << std::endl;
    return 1;
  }

  auto bin = loader::BFDManager::initialize().load_binary(argv[1]);
  std::cout << bin.filename << std::endl;
}