"""支持 python -m mitmlab 直接运行。"""

import sys

from .cli import main

sys.exit(main())
