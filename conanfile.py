from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.scm import Git

class NetworkAnalyzer(ConanFile):
    name = "network_analyzer"
    version = "1.0.0"
    settings = "os", "arch", "compiler", "build_type"
    generators = "CMakeDeps"

    def requirements(self):
        self.requires("dpdk/21.11.9")
        self.requires("pcapplusplus/25.05@")
        self.requires("thrift_pfr_serializer/1.0.5")
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
        # Disable unnecessary Poco components to speed up build and reduce size
        self.options["poco"].enable_net = False
        # self.options["poco"].enable_data = False
        self.options["poco"].enable_data_mysql = False
        self.options["poco"].enable_data_postgresql = False
        self.options["poco"].enable_netssl = False          # Keep if you need SSL        
        self.options["poco"].enable_util = True
        self.options["poco"].enable_json = False
        self.options["poco"].enable_xml = False
        self.options["poco"].enable_encodings = True
        self.options["poco"].enable_zip = False
        self.options["poco"].enable_sevenzip = False
        self.options["poco"].enable_crypto = False
        self.options["poco"].enable_file2page = False
        self.options["poco"].enable_jwt = False
        self.options["poco"].enable_mongodb = False
        self.options["poco"].enable_pagecompiler = False
        self.options["poco"].enable_pdf = False
        self.options["poco"].enable_redis = False
        self.options["poco"].enable_tasks = False
        self.options["poco"].enable_timer = False
        self.options["boost"].without_cobalt = True
