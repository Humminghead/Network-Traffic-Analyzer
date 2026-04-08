from conan import ConanFile
from conan.tools.files import copy, get
from conan.tools.layout import basic_layout

class ThriftPfrSerializerConan(ConanFile):
    name = "thrift_pfr_serializer"
    version = "1.0.6"
    package_type = "header-library"
    no_copy_source = True

    # Dependencies
    requires = "thrift/0.21.0", "pfr/2.2.0"    
    generators = "CMakeDeps", "CMakeToolchain"  
    settings = "os", "arch", "compiler", "build_type"

    def layout(self):
        basic_layout(self)

    def source(self):
        # Download the library from GitHub (use a specific commit or tag for reproducibility)
        get(self, "https://github.com/Humminghead/ThriftPfrSerializer/archive/refs/heads/main.zip",
            strip_root=True)

    def package(self):
        copy(self, "*.h",
             src=self.source_folder + "/include",
             dst=self.package_folder + "/include")

    def package_info(self):
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
        self.cpp_info.includedirs = ["include"]
        # Provide CMake target and file name "tpfr"
        self.cpp_info.set_property("cmake_file_name", "tpfr")
        self.cpp_info.set_property("cmake_target_name", "tpfr::tpfr")
        # Or for compatibility with older CMake:
        self.cpp_info.names["cmake_find_package"] = "tpfr"
        self.cpp_info.names["cmake_find_package_multi"] = "tpf"
