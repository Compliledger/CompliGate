# Prevent pytest from collecting manual roundtrip scripts whose
# filenames happen to match the default ``*_test.py`` discovery
# pattern. These scripts hit real external systems (XRPL testnet) and
# are not part of the unit-test suite.

collect_ignore = ["xrpl_roundtrip_test.py"]
