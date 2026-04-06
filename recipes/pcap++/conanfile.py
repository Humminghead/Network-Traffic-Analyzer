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
        if self.options.with_dpdk:
            self.requires("dpdk/21.11.9")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def source(self):
        get(self, f"https://github.com/seladb/PcapPlusPlus/archive/refs/tags/v{self.version}.tar.gz",
            strip_root=True, destination=self.source_folder)

        # Patch DPDK::DPDK → dpdk::dpdk (fix target name)
        replace_in_file(self, os.path.join(self.source_folder, "Pcap++", "CMakeLists.txt"),
                        "DPDK::DPDK", "dpdk::dpdk")

    def generate(self):
        tc = CMakeToolchain(self)
        # Add -mssse3 to C++ flags (required for DPDK intrinsics)
        tc.cache_variables["CMAKE_CXX_FLAGS"] = "${CMAKE_CXX_FLAGS} -mssse3"
        if self.options.with_dpdk:
            tc.cache_variables["PCAPPP_USE_DPDK"] = "ON"
            dpdk_root = self.dependencies["dpdk"].package_folder
            tc.cache_variables["DPDK_ROOT_DIR"] = dpdk_root
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