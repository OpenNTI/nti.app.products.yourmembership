#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id$
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

# pylint: disable=inherit-non-class,expression-not-assigned

from zope import interface

from zope.interface import Attribute

from zope.interface.interfaces import ObjectEvent
from zope.interface.interfaces import IObjectEvent

from nti.schema.field import ValidTextLine as TextLine


class IYourMembershipUser(interface.Interface):
    """
    Marker interface for a user created via YourMembership.
    """


class IYourMembershipLogonSettings(interface.Interface):

    api_endpoint = TextLine(title=u"The yourmembership API url", required=True)

    api_key = TextLine(title=u"The yourmembership api key", required=True)


class IYourMembershipUserCreatedEvent(IObjectEvent):
    """
    Fired after an Google user has been created
    """
    request = Attribute(u"Request")


@interface.implementer(IYourMembershipUserCreatedEvent)
class YourMembershipUserCreatedEvent(ObjectEvent):

    def __init__(self, obj, request=None):
        super(YourMembershipUserCreatedEvent, self).__init__(obj)
        self.request = request


class YourMembershipException(Exception):
    """
    A generic your membership API exception.
    """


class YourMembershipSessionException(YourMembershipException):
    """
    A your membership API error when fetching a session.
    """


class YourMembershipAuthTokenException(YourMembershipException):
    """
    A your membership API error when fetching an auth token.
    """


class YourMembershipUserInfoException(YourMembershipException):
    """
    An exception indicating we received an error when fetching YourMembership
    user info.
    """


class YourMembershipUserInfoNotFoundException(YourMembershipUserInfoException):
    """
    An exception indicating we received a user info response but no user info
    data.
    """
