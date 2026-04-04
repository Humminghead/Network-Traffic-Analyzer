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
        # "platform": ["native", "generic", "auto"],
        # "enable_kmods": [True, False],
        "tests": [True, False],
        "enable_docs": [True, False],
        # "developer_mode": [True, False],
        # "use_hpet": [True, False],
        # "enable_iova_as_pa": [True, False],
        "mbuf_refcnt_atomic": [True, False],
        "enable_stdatomic": [True, False],
        # "enable_trace_fp": [True, False],
        # "ibverbs_link": ["static", "shared", "dlopen"],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        # "platform": "native",
        # "enable_kmods": False,
        "tests": False,
        "enable_docs": False,
        # "developer_mode": False,
        # "use_hpet": False,
        # "enable_iova_as_pa": True,
        "mbuf_refcnt_atomic": True,
        "enable_stdatomic": False,
        # "enable_trace_fp": False,
        # "ibverbs_link": "shared",
    }
    generators = "PkgConfigDeps"

    def layout(self):
        basic_layout(self)

    def source(self):
        get(self, f"https://fast.dpdk.org/rel/dpdk-{self.version}.tar.xz",
            strip_root=True)

    def generate(self):
        tc = MesonToolchain(self)
        # Only set options that are booleans or enums (not free strings)
        tc.project_options["default_library"] = "shared" if self.options.shared else "static"
        # tc.project_options["enable_kmods"] = self.options.enable_kmods
        tc.project_options["tests"] = self.options.tests
        tc.project_options["enable_docs"] = self.options.enable_docs
        # tc.project_options["developer_mode"] = self.options.developer_mode
        # tc.project_options["use_hpet"] = self.options.use_hpet
        # tc.project_options["enable_iova_as_pa"] = self.options.enable_iova_as_pa
        tc.project_options["mbuf_refcnt_atomic"] = self.options.mbuf_refcnt_atomic
        tc.project_options["enable_stdatomic"] = self.options.enable_stdatomic
        # tc.project_options["enable_trace_fp"] = self.options.enable_trace_fp
        # tc.project_options["ibverbs_link"] = self.options.ibverbs_link
        # examples: leave unset (default = no examples)
        # DO NOT set to "none" – that breaks the build.
        tc.generate()

    def build(self):
        meson = Meson(self)        
        meson.configure()
        meson.build()

    def package(self):
        meson = Meson(self)
        meson.install()
        copy(self, "LICENSE", src=self.source_folder,
             dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.libs = [
            "rte_node","rte_graph","rte_pipeline","rte_table","rte_pdump",
            "rte_port","rte_fib","rte_pdcp","rte_ipsec","rte_vhost","rte_stack",
            "rte_security","rte_sched","rte_reorder","rte_rib","rte_mldev",
            "rte_regexdev","rte_rawdev","rte_power","rte_pcapng","rte_member",
            "rte_lpm","rte_latencystats","rte_jobstats","rte_ip_frag","rte_gso",
            "rte_gro","rte_gpudev","rte_dispatcher","rte_eventdev","rte_efd",
            "rte_dmadev","rte_distributor","rte_cryptodev","rte_compressdev",
            "rte_cfgfile","rte_bpf","rte_bitratestats","rte_bbdev","rte_acl",
            "rte_timer","rte_hash","rte_metrics","rte_cmdline","rte_pci",
            "rte_ethdev","rte_meter","rte_net","rte_mbuf","rte_mempool","rte_rcu",
            "rte_ring","rte_eal","rte_telemetry","rte_argparse","rte_kvargs",
            "rte_log"]
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs = ["lib"]
        self.buildenv_info.define_path("PKG_CONFIG_PATH",
                                       os.path.join(self.package_folder, "lib", "pkgconfig"))