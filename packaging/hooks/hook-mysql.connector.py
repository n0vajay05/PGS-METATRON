from PyInstaller.utils.hooks import collect_submodules, collect_data_files, copy_metadata

hiddenimports = []
hiddenimports += collect_submodules("mysql")
hiddenimports += collect_submodules("mysql.connector")
hiddenimports += collect_submodules("mysql.connector.plugins")
hiddenimports += collect_submodules("mysql.connector.aio.plugins")

datas = []
datas += collect_data_files("mysql")
datas += collect_data_files("mysql.connector")
datas += collect_data_files("mysql.connector.plugins")
datas += collect_data_files("mysql.connector.aio.plugins")

try:
    datas += copy_metadata("mysql-connector-python")
except Exception:
    pass