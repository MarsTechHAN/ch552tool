from __future__ import absolute_import

import os
import sys

if sys.path[0] in ('', os.getcwd()):
    sys.path.pop(0)

from ch55xtool.ch55xtool import main as _main  # isort:skip # noqa

if __name__ == '__main__':
    sys.exit(_main())
