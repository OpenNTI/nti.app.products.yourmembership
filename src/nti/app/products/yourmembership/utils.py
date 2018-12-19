#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

from zope import interface

from zope.event import notify

from nti.app.products.yourmembership import MessageFactory as _
from nti.app.products.yourmembership import raise_http_error

from nti.app.products.yourmembership.interfaces import IYourMembershipUser

from nti.externalization.interfaces import ObjectModifiedFromExternalEvent

from nti.identifiers.interfaces import IUserExternalIdentityContainer

from nti.identifiers.utils import get_user_for_external_id

logger = __import__('logging').getLogger(__name__)

PROVIDER_ID = "yourmembership"


def set_user_yourmembership_id(user, yourmembership_id, request):
    """
    Set the given YourMembership identity for a user.
    """
    if not yourmembership_id:
        raise_http_error(request,
                         _(u"Must provide yourmembership_id."),
                         u'NoYourMembershipIdsGiven')
    interface.alsoProvides(user, IYourMembershipUser)

    identity_container = IUserExternalIdentityContainer(user)
    identity_container.add_external_mapping(PROVIDER_ID, yourmembership_id)
    logger.info("Setting Yourmembership ID for user (%s) (%s/%s)",
                user.username, PROVIDER_ID, yourmembership_id)
    notify(ObjectModifiedFromExternalEvent(user))


def get_user_for_yourmembership_id(yourmembership_id):
    """
    Find any user associated with the given YourMembership id.
    """
    return get_user_for_external_id(PROVIDER_ID, yourmembership_id)
