# PyInstaller one-folder build. User databases and logs are deliberately not bundled.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

datas = [("dashboard.py", ".")]
for package in (
    "streamlit",
    "scapy",
    "streamlit_autorefresh",
    "streamlit_cookies_controller",
    "plotly",
):
    datas += collect_data_files(package)

hiddenimports = [
    # Application modules imported when Streamlit executes dashboard.py.
    "agent_controller",
    "agent_runtime",
    "ai_analyzer",
    "alert_manager",
    "app_paths",
    "auth",
    "connectivity_monitor",
    "database",
    "detection_engine",
    "MITRE_mapping",
    "monitor_engine",
    "network_monitor",
    "risk_engine",
    # Dashboard imports performed by the Streamlit script.
    "pandas",
    "plotly.express",
    "plotly.graph_objects",
    "requests",
    "streamlit",
    "streamlit_autorefresh",
    "streamlit_cookies_controller",
    # Runtime modules dynamically loaded by Streamlit.
    "streamlit.web.bootstrap",
    "streamlit.web.server.server",
    "streamlit.runtime.scriptrunner",
    "streamlit.runtime.scriptrunner.magic_funcs",
    "streamlit.components.v1",
    # Scapy layers and Windows capture backend actually used by this app.
    "scapy.arch.windows",
    "scapy.arch.libpcap",
    "scapy.config",
    "scapy.layers.dns",
    "scapy.layers.inet",
    "scapy.layers.inet6",
    "scapy.layers.l2",
    "scapy.packet",
    "scapy.sendrecv",
]
hiddenimports += collect_submodules("streamlit.web.server")
hiddenimports += collect_submodules("streamlit.runtime.scriptrunner")

for distribution in (
    "streamlit",
    "streamlit-autorefresh",
    "streamlit-cookies-controller",
    "scapy",
):
    datas += copy_metadata(distribution)

a = Analysis(
    ["launcher.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest", "pandas.tests", "plotly.tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CybersecurityOSAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon="assets/CybersecurityOSAgent.ico",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="CybersecurityOSAgent",
)
