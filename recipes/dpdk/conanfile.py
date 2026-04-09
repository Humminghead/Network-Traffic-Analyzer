from conan import ConanFile
from conan.tools.meson import Meson, MesonToolchain
from conan.tools.files import get, copy, replace_in_file
from conan.tools.layout import basic_layout
import os

class DPDKConan(ConanFile):
    name = "dpdk"    
    version = "21.11.9"
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    # No exports_sources needed
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "tests": [True, False],
        "enable_docs": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "tests": False,
        "enable_docs": False,
    }
    generators = "PkgConfigDeps"

    def layout(self):
        basic_layout(self)

    def source(self):
        get(self, f"https://fast.dpdk.org/rel/dpdk-{self.version}.tar.xz", strip_root=True)

        # Fix the thin archive issue by editing gen-pmdinfo-cfile.py
        script_path = os.path.join(self.source_folder, "buildtools", "gen-pmdinfo-cfile.py")
        
        # Read original content
        with open(script_path, "r") as f:
            content = f.read()
        
        # Replace the problematic block with the fixed version
        # Find the start of the block
#         old_block = """with tempfile.TemporaryDirectory(dir=tmp_root) as temp:
#     run_ar = lambda command: subprocess.run(
#         [ar, command, os.path.abspath(archive)],
#         stdout=subprocess.PIPE, check=True, cwd=temp
#     )
#     # Don't use "ar p", because its output is corrupted on Windows.
#     run_ar("x")
#     names = run_ar("t").stdout.decode().splitlines()
#     paths = [os.path.join(temp, name) for name in names]"""

#         new_block = """archive = os.path.abspath(archive)
# names = subprocess.run([ar, "t", archive],
#         stdout=subprocess.PIPE, check=True).stdout.decode().splitlines()
# with open(archive, "rb") as f:
#     is_thin = f.read(7) == b"!<thin>"
# if is_thin:
#     # Thin archive needs no unpacking, just use the paths within.
#     paths = [os.path.join(archive, name) for name in names]
#     subprocess.run(pmdinfogen + paths + [output], check=True)
# else:
#     with tempfile.TemporaryDirectory(dir=tmp_root) as temp:
#         # Don't use "ar p", because its output is corrupted on Windows.
#         paths = [os.path.join(temp, name) for name in names]
#         subprocess.run([ar, "x", archive], check=True, cwd=temp)
#         subprocess.run(pmdinfogen + paths + [output], check=True)"""

        # if old_block in content:
        #     content = content.replace(old_block, new_block)
        #     with open(script_path, "w") as f:
        #         f.write(content)
        # else:
        #     # Fallback: use replace_in_file with a simpler pattern
        #     replace_in_file(self, script_path, 
        #         "run_ar(\"x\")",
        #         "archive = os.path.abspath(archive)\\nnames = subprocess.run([ar, \"t\", archive],\\n        stdout=subprocess.PIPE, check=True).stdout.decode().splitlines()\\nwith open(archive, \"rb\") as f:\\n    is_thin = f.read(7) == b\"!<thin>\"\\nif is_thin:\\n    paths = [os.path.join(archive, name) for name in names]\\n    subprocess.run(pmdinfogen + paths + [output], check=True)\\nelse:\\n    with tempfile.TemporaryDirectory(dir=tmp_root) as temp:\\n        paths = [os.path.join(temp, name) for name in names]\\n        subprocess.run([ar, \"x\", archive], check=True, cwd=temp)\\n        subprocess.run(pmdinfogen + paths + [output], check=True)")
            # Then remove the lines after? This is messy; better to rely on the full block replacement.

    def generate(self):
        tc = MesonToolchain(self)
        tc.project_options["default_library"] = "shared" if self.options.shared else "static"
        tc.project_options["tests"] = self.options.tests
        tc.project_options["enable_docs"] = self.options.enable_docs
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
            "rte_node","rte_graph","rte_bpf","rte_flow_classify","rte_pipeline","rte_table",
            "rte_port","rte_fib","rte_ipsec","rte_vhost","rte_stack","rte_security","rte_sched",
            "rte_reorder","rte_rib","rte_regexdev","rte_rawdev","rte_pdump","rte_power",
            "rte_member","rte_lpm","rte_latencystats","rte_kni","rte_jobstats","rte_ip_frag",
            "rte_gso","rte_gro","rte_eventdev","rte_efd","rte_distributor","rte_cryptodev",
            "rte_compressdev","rte_cfgfile","rte_bitratestats","rte_bbdev","rte_acl","rte_timer",
            "rte_hash","rte_metrics","rte_cmdline","rte_pci","rte_ethdev","rte_meter","rte_net",
            "rte_mbuf","rte_mempool","rte_rcu","rte_ring","rte_eal","rte_telemetry","rte_kvargs"
            ]
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs = ["lib"]
        self.buildenv_info.define_path("PKG_CONFIG_PATH",
                                       os.path.join(self.package_folder, "lib", "pkgconfig"))
        self.cpp_info.set_property("cmake_file_name", "dpdk")
        self.cpp_info.set_property("cmake_target_name", "dpdk::dpdk")