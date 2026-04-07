from conan import ConanFile
from conan.tools.cmake import cmake_layout
from conan.tools.files import get


class ExampleRecipe(ConanFile):
    name = "poco"
    version = "1.15.1"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    # def requirements(self):
    #     self.requires("poco/1.15.1")

    def layout(self):
        cmake_layout(self)

    def source(self):
        get(self, "https://github.com/pocoproject/poco/releases/download/poco-1.15.1-release/poco-1.15.1.zip",
            strip_root=True)


