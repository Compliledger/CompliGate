from app import main as _app_main
import sys

sys.modules[__name__] = _app_main
