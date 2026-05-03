from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import get, copy, replace_in_file
from conan.errors import ConanInvalidConfiguration
import os

class PcapPlusPlusConan(ConanFile):
    name = "pcapplusplus"
    version = "25.05"
    license = "Unlicense"
    description = "PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting network packets"
    topics = ("conan", "pcapplusplus", "pcap", "network", "security", "packet")
    homepage = "https://github.com/seladb/PcapPlusPlus"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "with_dpdk": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "with_dpdk": True,
    }
    generators = "CMakeDeps"

    def configure(self):
        if self.settings.os != "Linux":
            raise ConanInvalidConfiguration("This recipe supports Linux only")
        if self.options.shared:
            del self.options.fPIC

    def requirements(self):
        self.requires("libpcap/1.10.4")        

    def layout(self):
        cmake_layout(self, src_folder="src")

    def source(self):
        get(self, f"https://github.com/seladb/PcapPlusPlus/archive/refs/tags/v{self.version}.tar.gz",
            strip_root=True, destination=self.source_folder)        

    def generate(self):
        tc = CMakeToolchain(self)       
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        # Additional header copy (fallback)
        copy(self, "*.h", src=os.path.join(self.source_folder, "Dist", "header"),
             dst=os.path.join(self.package_folder, "include", "pcapplusplus"), keep_path=True)

    def package_info(self):
        self.cpp_info.libs = ["Pcap++", "Packet++", "Common++"]
        self.cpp_info.includedirs = ["include"]
        if self.settings.os == "Linux":
            self.cpp_info.system_libs = ["pthread"]