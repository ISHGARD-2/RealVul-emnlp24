#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

# import django
#
# django.setup()

from core import main


if __name__ == '__main__':

    sys.exit(main())

