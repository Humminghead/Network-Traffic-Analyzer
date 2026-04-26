from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.scm import Git

class NetworkAnalyzer(ConanFile):
    name = "network_analyzer"
    version = "1.0.0"
    settings = "os", "arch", "compiler", "build_type"
    generators = "CMakeDeps"

    def requirements(self):
        self.requires("dpdk/26.03")
        self.requires("pcapplusplus/25.05@")
        self.requires("thrift_pfr_serializer/1.0.6")
        self.requires("nlohmann_json/3.11.3")
        self.requires("poco/1.15.1")

    def generate(self):        
        tc = CMakeToolchain(self)        
        # If DPDK is not in a standard path, you can also set its root
        # tc.cache_variables["DPDK_ROOT"] = self.dependencies["dpdk"].package_folder
        tc.user_presets_path = "build/ConanPresets.json"
        tc.generate()

    def layout(self):
        cmake_layout(self, build_folder="build")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def configure(self):
        self.options["pcapplusplus"].with_dpdk = True        
        self.options["boost"].without_cobalt = True
