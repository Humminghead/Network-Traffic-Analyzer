from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import get, copy


class ExampleRecipe(ConanFile):
    name = "poco"
    version = "1.15.1"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps"

    def requirements(self):
        self.requires("pcre2/[>=10.42 <11]")
        self.requires("utf8proc/[>=2.8.0 <3]")
        self.requires("zlib/[>=1.2.11 <2]", transitive_headers=True)

    def layout(self):
        cmake_layout(self)

    def source(self):
        get(self, "https://github.com/pocoproject/poco/releases/download/poco-1.15.1-release/poco-1.15.1.zip",
            strip_root=True)

    def build(self):
        cmake = CMake(self)        
        cmake.configure()
        cmake.build()
        cmake.install()    
    
        
    def generate(self):
      toolchain = CMakeToolchain(self)
      toolchain.variables["BUILD_SHARED_LIBS"] = False
      toolchain.variables["POCO_MINIMAL_BUILD"] = True
      toolchain.variables["ENABLE_UTIL"] = True
      toolchain.variables["ENABLE_FOUNDATION"] = True
      toolchain.generate()

