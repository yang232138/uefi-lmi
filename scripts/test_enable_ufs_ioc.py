import importlib.util
from pathlib import Path

path = Path(__file__).with_name("enable_ufs_ioc.py")
spec = importlib.util.spec_from_file_location("enable_ufs_ioc", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

source = b'{"EnableUfsIOC", 0}\r\n{"Other", 0}\r\n'
assert module.transform(source) == b'{"EnableUfsIOC", 1}\r\n{"Other", 0}\r\n'
for invalid in (b'{"Other", 0}\n', b'{"EnableUfsIOC", 0}\n{"EnableUfsIOC", 0}\n'):
    try:
        module.transform(invalid)
    except AssertionError:
        pass
    else:
        raise AssertionError("Invalid source did not fail closed")
print("PASS: exact single setting update; missing and duplicate settings rejected")
