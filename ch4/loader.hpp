#ifndef LOADER_LOADER_H
#define LOADER_LOADER_H

#include <bfd.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace loader {
template <class T> auto make_unique_with_malloc(std::size_t size) {
  return std::unique_ptr<T, decltype(&std::free)>(
      [&size] {
        auto p = malloc(size);
        if (!p)
          throw std::runtime_error("out of memory");
        return static_cast<T *>(p);
      }(),
      std::free);
}

struct Binary;
struct Section;
struct Symbol;

struct Symbol {
  enum class Type { UNK, FUNC };
  Type type;
  std::string name;
  uint64_t addr;
  Symbol(Type type, const std::string &name, uint64_t addr)
      : type(type), name(name), addr(addr) {}
};

struct Section {
  enum class Type { NONE, CODE, DATA };
  std::string name;
  Type type;
  uint64_t vma;
  uint64_t size;
  std::unique_ptr<uint8_t, decltype(&std::free)> bytes;
  Section(const std::string &name, Type type, uint64_t vma, uint64_t size,
          std::unique_ptr<uint8_t, decltype(&std::free)> &&bytes)
      : name(name), type(type), vma(vma), size(size), bytes(std::move(bytes)) {}
  auto contains(uint64_t addr) { return addr >= vma && addr - vma < size; }
};

struct Binary {
  enum class Type { AUTO, ELF, PE };
  enum class Arch { NONE, X86 };
  std::string filename;
  Type type;
  std::string type_str;
  Arch arch;
  std::string arch_str;
  unsigned int bits;
  uint64_t entry;
  std::vector<Section> sections;
  std::vector<Symbol> symbols;
  Binary(const std::string &filename, Type type, const std::string &type_str,
         Arch arch, const std::string &arch_str, unsigned int bits,
         uint64_t entry, std::vector<Section> &&sections,
         std::vector<Symbol> &&symbols)
      : filename(filename), type(type), type_str(type_str), arch(arch),
        arch_str(arch_str), bits(bits), entry(entry),
        sections(std::move(sections)), symbols(std::move(symbols)) {}
  /**
  std::optional<Section> get_text_section() {
    for (const auto &section : sections) {
      if (section.name == ".text")
        return section;
    }
    return std::nullopt;
  }
  */
};

class BFDManager {
  struct BFDWrapper {
    bfd *bfd_h;
    std::string filename;
    BFDWrapper(const std::string &filename) : filename(filename) {
      using namespace std::literals::string_literals;
      bfd_h = bfd_openr(filename.c_str(), NULL);
      if (!bfd_h) {
        throw std::runtime_error("failed to open binary "s + filename + ". "s +
                                 bfd_errmsg(bfd_get_error()));
      }
      if (!bfd_check_format(bfd_h, bfd_object)) {
        throw std::runtime_error("file "s + filename +
                                 " does not look like an executable. "s +
                                 bfd_errmsg(bfd_get_error()));
      }
      bfd_set_error(bfd_error_no_error);
      if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
        throw std::runtime_error("unrecognized format for binary "s + filename +
                                 ". "s + bfd_errmsg(bfd_get_error()));
      }
    }
    ~BFDWrapper() {
      if (bfd_h) {
        bfd_close(bfd_h);
      }
    }
    auto load_binary() {
      using namespace std::literals::string_literals;
      auto entry = bfd_get_start_address(bfd_h);
      auto type_str = bfd_h->xvec->name;

      const auto transform_flavour = [this](auto flavour) {
        switch (flavour) {
        case bfd_target_elf_flavour:
          return Binary::Type::ELF;
        case bfd_target_coff_flavour:
          return Binary::Type::PE;
        case bfd_target_unknown_flavour:
        default:
          throw std::runtime_error("unsupported binary type "s +
                                   this->bfd_h->xvec->name);
        }
      };

      auto type = transform_flavour(bfd_h->xvec->flavour);
      auto bfd_info = bfd_get_arch_info(bfd_h);
      auto arch_str = bfd_info->printable_name;

      const auto transform_mach =
          [&bfd_info](auto mach) -> std::tuple<Binary::Arch, unsigned int> {
        switch (mach) {
        case bfd_mach_i386_i386:
          return {Binary::Arch::X86, 32};
        case bfd_mach_x86_64:
          return {Binary::Arch::X86, 64};
        default:
          throw std::runtime_error("unsupported archtecture "s +
                                   bfd_info->printable_name);
        }
      };

      auto [arch, bits] = transform_mach(bfd_info->mach);

      auto n = bfd_get_symtab_upper_bound(bfd_h);
      const auto load_static_symbols = [this](auto n) {
        if (n <= 0)
          throw std::runtime_error("failed to read symtab "s +
                                   bfd_errmsg(bfd_get_error()));
        auto bfd_symtab = make_unique_with_malloc<asymbol *>(n);
        auto nsyms = bfd_canonicalize_symtab(this->bfd_h, bfd_symtab.get());
        if (nsyms < 0)
          throw std::runtime_error("failed to read symtab "s +
                                   bfd_errmsg(bfd_get_error()));
        std::vector<Symbol> symbols;
        for (std::size_t i = 0; i < nsyms; ++i) {
          if (bfd_symtab.get()[i]->flags & BSF_FUNCTION) {
            symbols.emplace_back(Symbol::Type::FUNC, bfd_symtab.get()[i]->name,
                                 bfd_asymbol_value(bfd_symtab.get()[i]));
          }
        }
        return symbols;
      };

      auto static_symbols = load_static_symbols(n);

      auto m = bfd_get_dynamic_symtab_upper_bound(bfd_h);
      const auto load_dynamic_symbols = [this](auto n) {
        if (n <= 0)
          throw std::runtime_error("failed to read dynamic symtab "s +
                                   bfd_errmsg(bfd_get_error()));
        auto bfd_dynsym = make_unique_with_malloc<asymbol *>(n);
        auto nsyms =
            bfd_canonicalize_dynamic_symtab(this->bfd_h, bfd_dynsym.get());
        if (nsyms < 0)
          throw std::runtime_error("failed to read dynamic symtab "s +
                                   bfd_errmsg(bfd_get_error()));
        std::vector<Symbol> symbols;
        for (std::size_t i = 0; i < nsyms; ++i) {
          if (bfd_dynsym.get()[i]->flags & BSF_FUNCTION) {
            symbols.emplace_back(Symbol::Type::FUNC, bfd_dynsym.get()[i]->name,
                                 bfd_asymbol_value(bfd_dynsym.get()[i]));
          }
        }
        return symbols;
      };

      auto dynamic_symbols = load_dynamic_symbols(m);

      const auto load_sections = [this]() {
        std::vector<Section> sections;
        for (auto bfd_sec = this->bfd_h->sections; bfd_sec;
             bfd_sec = bfd_sec->next) {
          auto bfd_flags = bfd_get_section_flags(this->bfd_h, bfd_sec);
          const auto get_sectype = [](auto flags) {
            if (flags & SEC_CODE)
              return Section::Type::CODE;
            if (flags & SEC_DATA)
              return Section::Type::DATA;
            return Section::Type::NONE;
          };
          auto vma = bfd_section_vma(this->bfd_h, bfd_sec);
          auto size = bfd_section_size(this->bfd_h, bfd_sec);
          auto secname = bfd_section_name(this->bfd_h, bfd_sec);
          if (!secname)
            secname = "<unnamed>";
          auto bytes = make_unique_with_malloc<uint8_t>(size);
          if (!bfd_get_section_contents(this->bfd_h, bfd_sec, bytes.get(), 0,
                                        size)) {
            throw std::runtime_error("failed to read section "s + secname +
                                     ". "s + bfd_errmsg(bfd_get_error()));
          }
          sections.emplace_back(secname, get_sectype(bfd_flags), vma, size,
                                std::move(bytes));
        }
        return sections;
      };
      static_symbols.insert(static_symbols.end(), dynamic_symbols.begin(),
                            dynamic_symbols.end());
      auto sections = load_sections();
      return Binary(filename, type, type_str, arch, arch_str, bits, entry,
                    std::move(sections), std::move(static_symbols));
    }
  };
  BFDManager() { bfd_init(); }

public:
  BFDManager(const BFDManager &) = delete;
  BFDManager &operator=(const BFDManager &) = delete;

public:
  static BFDManager &initialize() {
    static BFDManager bfd_manager;
    return bfd_manager;
  }
  auto load_binary(const std::string &filename) {
    return BFDWrapper(filename).load_binary();
  }
};
}; // namespace loader
#endif