#!/usr/bin/env python
# -*- coding: utf-8 -*
"""
.. $Id: zcml.py 124707 2017-12-08 21:48:18Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

# pylint: disable=inherit-non-class

import functools

from zope import interface

from zope.component.zcml import utility

from zope.schema import TextLine

from nti.app.products.yourmembership.interfaces import IYourMembershipLogonSettings

from nti.app.products.yourmembership.model import YourMembershipLogonSettings

from nti.common._compat import text_

logger = __import__('logging').getLogger(__name__)


class IRegisterYourMembershipLogonSettings(interface.Interface):

    api_endpoint = TextLine(title=u"The yourmembership API url", required=True)

    api_key = TextLine(title=u"The yourmembership api key", required=True)


def registerYourMembershipLogonSettings(_context, api_endpoint, api_key):
    factory = functools.partial(YourMembershipLogonSettings,
                                api_endpoint=text_(api_endpoint),
                                api_keygit=text_(api_key))
    utility(_context, provides=IYourMembershipLogonSettings, factory=factory)
