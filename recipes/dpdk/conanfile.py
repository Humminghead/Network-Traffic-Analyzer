from conan import ConanFile
from conan.tools.meson import Meson, MesonToolchain
from conan.tools.files import get, copy
from conan.tools.layout import basic_layout
import os


class DPDKConan(ConanFile):
    name = "dpdk"
    version = "26.03"
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "tests": [True, False],
        "enable_docs": [True, False],
        "mbuf_refcnt_atomic": [True, False],
        "enable_stdatomic": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "tests": False,
        "enable_docs": False,
        "mbuf_refcnt_atomic": True,
        "enable_stdatomic": False,
    }
    generators = "PkgConfigDeps"

    def layout(self):
        basic_layout(self)

    def source(self):
        get(
            self,
            f"https://fast.dpdk.org/rel/dpdk-{self.version}.tar.xz",
            strip_root=True,
        )

    def generate(self):
        tc = MesonToolchain(self)
        tc.project_options["default_library"] = (
            "shared" if self.options.shared else "static"
        )
        tc.project_options["tests"] = self.options.tests
        tc.project_options["enable_docs"] = self.options.enable_docs
        tc.project_options["mbuf_refcnt_atomic"] = self.options.mbuf_refcnt_atomic
        tc.project_options["enable_stdatomic"] = self.options.enable_stdatomic
        tc.generate()

    def build(self):
        meson = Meson(self)
        meson.configure()
        meson.build()

    def package(self):
        meson = Meson(self)
        meson.install()
        copy(
            self,
            "LICENSE",
            src=self.source_folder,
            dst=os.path.join(self.package_folder, "licenses"),
        )

    def package_info(self):
        # Only the necessary libraries for project were added
        # Same libs as in {build_path}/generators/dpdk-{build_type}-x86_64-data.cmake
        self.cpp_info.libs = ["rte_ethdev","rte_mbuf","rte_eal","rte_telemetry","rte_argparse","rte_kvargs","rte_log","rte_acl","rte_stack","rte_mempool","rte_mempool_bucket","rte_mempool_ring","rte_mempool_stack","rte_net","rte_bus_vdev","librte_net_pcap", "rte_ring"]                    
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs = ["lib"]
        self.buildenv_info.define_path(
            "PKG_CONFIG_PATH", os.path.join(self.package_folder, "lib", "pkgconfig")
        )
