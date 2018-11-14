#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

import os
import time
import hashlib
import requests
from collections import namedtuple

from bs4 import BeautifulSoup

import pyramid.httpexceptions as hexc

from pyramid.interfaces import IRequest

from pyramid.view import view_config

from six.moves import urllib_parse

from zope import interface
from zope import component

from zope.event import notify

from nti.app.products.yourmembership import MessageFactory as _

from nti.app.products.yourmembership.interfaces import IYourMembershipLogonSettings
from nti.app.products.yourmembership.interfaces import YourMembershipUserCreatedEvent
from nti.app.products.yourmembership.interfaces import YourMembershipUserInfoException
from nti.app.products.yourmembership.interfaces import YourMembershipUserInfoNotFoundException

from nti.app.products.yourmembership.utils import set_user_ats_imis_id
from nti.app.products.yourmembership.utils import get_user_for_ats_imis_id

from nti.appserver.interfaces import IMissingUser
from nti.appserver.interfaces import ILogonLinkProvider
from nti.appserver.interfaces import IUnauthenticatedUserLinkProvider

from nti.appserver.logon import _create_success_response
from nti.appserver.logon import _create_failure_response
from nti.appserver.logon import _deal_with_external_account

from nti.appserver.policies.interfaces import INoAccountCreationEmail

from nti.dataserver.interfaces import IDataserverFolder

from nti.dataserver.users.interfaces import IUsernameGeneratorUtility

from nti.dataserver.users.users import User

from nti.dataserver.users.utils import force_email_verification

from nti.links.links import Link

logger = __import__('logging').getLogger(__name__)

#: The initial ATS IMIS login rel
REL_LOGIN_ATS_IMIS = 'logon.ats.imis'

#: The redirect rel after ATS IMIS auth
LOGON_ATS_IMIS = 'logon.ats.imis2'

#: The ATS IMIS token query param after initial auth
ATS_IMIS_TOKEN = 'token'

ATS_IMIS_RETURN_URL_PARAM = 'returl'

ATSIMISUserInfo = namedtuple('ATSIMISUserInfo',
                             ('ats_imis_id', 'first_name',
                              'last_name', 'real_name', 'email'))


def redirect_ats_imis2_uri(request):
    root = request.route_path('objects.generic.traversal', traverse=())
    root = root[:-1] if root.endswith('/') else root
    target = urllib_parse.urljoin(request.application_url, root)
    target = target + '/' if not target.endswith('/') else target
    target = urllib_parse.urljoin(target, LOGON_ATS_IMIS)
    return target


def redirect_ats_imis2_params(request, state=None):
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    params = {'state': state,
              'response_type': 'code',
              ATS_IMIS_RETURN_URL_PARAM: redirect_ats_imis2_uri(request)}
    return params


def generate_username():
    username_util = component.getUtility(IUsernameGeneratorUtility)
    return username_util.generate_username()


def _get_auth_url():
    auth_settings = component.getUtility(IATSIMISLogonSettings)
    auth_url = auth_settings.login_url
    return auth_url[:-1] if auth_url.endswith('/') else auth_url


def _get_user_info_url():
    auth_settings = component.getUtility(IATSIMISLogonSettings)
    return auth_settings.userinfo_url


def _get_user_info_element(doc, xml_response):
    """
    Parse and validate the given xml doc, returning the user_info element.
    """
    code = doc.find('ResultCode')
    result_code = code and code.text
    if result_code and result_code != '0':
        # Error condition
        msg = doc.find('ResultMessage')
        msg = msg and msg.text
        logger.warning('Exception while fetching ATS IMIS user info (code=%s) (%s)',
                       result_code, msg or 'None')
        raise ATSIMISUserInfoException(msg)

    try:
        user_info = doc.find('Contacts').find('NextThoughtUser')
    except AttributeError:
        user_info = None

    if not user_info:
        logger.warning('Malformed ATS IMIS user info (%s)',
                       xml_response)
        raise ATSIMISUserInfoNotFoundException('NextThoughtUser not found')
    return user_info


def _parse_user_info(xml_response):
    """
    Parse the given xml response into a `ATSIMISUserInfo`.
    """
    doc = BeautifulSoup(xml_response, 'lxml-xml')
    user_info = _get_user_info_element(doc, xml_response)

    def _get_val(field):
        field_val = user_info.find(field)
        return field_val and field_val.text

    first_name = _get_val('first_name')
    last_name = _get_val('last_name')
    real_name = _get_val('real_name')
    email = _get_val('email')
    ats_imis_id = _get_val('iMIS_ID')
    result = ATSIMISUserInfo(ats_imis_id, first_name, last_name,
                             real_name, email)
    return result


def _lookup_user(user_info):
    return get_user_for_ats_imis_id(user_info.ats_imis_id)


@view_config(name=REL_LOGIN_ATS_IMIS,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='GET',
             renderer='rest')
def ats_imis_auth(request, success=None, failure=None, state=None):
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    params = redirect_ats_imis2_params(request, state)

    for key, value in (('success', success), ('failure', failure)):
        value = value or request.params.get(key)
        if value:
            request.session['ats_imis.' + key] = value

    # save state for validation
    request.session['ats_imis.state'] = state

    # redirect
    target = _get_auth_url()
    target = '%s?%s' % (target, urllib_parse.urlencode(params))
    response = hexc.HTTPSeeOther(location=target)
    return response


def _return_url(request, url_type='success'):
    if url_type in request.params:
        return request.params.get(url_type)
    return request.session.get('ats_imis.' + url_type)


@view_config(name=LOGON_ATS_IMIS,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='GET',
             renderer='rest')
def ats_imis_auth2(request):
    params = request.params

    # check for errors
    if 'error' in params or 'errorCode' in params:
        error = params.get('error') or params.get('errorCode')
        logger.warn('ATS IMIS error during auth (%s)', error)
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=error)

    # Confirm anti-forgery state token
    # In traditional oauth we would look for a state query param
    # and check it against our session state value, but ATS-IMIS doesn't
    # currently echo that state param back to us!  Still make sure
    # we have the state in the session, and if the state did come in the query
    # param check it. -cu
    if not request.session.get('ats_imis.state'):
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Missing state.'))
    if 'state' in params:
        params_state = params.get('state')
        session_state = request.session.get('ats_imis.state')
        if params_state != session_state:
            return _create_failure_response(request,
                                            _return_url(request, 'failure'),
                                            error=_(u'Incorrect state values.'))

    token = params.get(ATS_IMIS_TOKEN)

    if not token:
        logger.warn('ATS IMIS token not found after auth')
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Could not find ATS IMIS token.'))

    try:
        user_info_url = _get_user_info_url()
        data = {'token': token}
        t0 = time.time()
        response = requests.post(user_info_url, data)
        logger.info('ATS IMIS user info fetched (%.2fs) (status=%s)',
                    time.time() - t0,
                    response.status_code)
        if response.status_code != 200:
            return _create_failure_response(
                request,
                _return_url(request, 'failure'),
                error=_('Invalid response while getting access token.'))

        user_info = _parse_user_info(response.text)
        user = _lookup_user(user_info)
        if user is None:
            username = generate_username()
            interface.alsoProvides(request, INoAccountCreationEmail)
            user = _deal_with_external_account(request,
                                               username=username,
                                               fname=user_info.first_name,
                                               lname=user_info.last_name,
                                               email=user_info.email,
                                               idurl=None,
                                               iface=None,
                                               user_factory=User.create_user)
            set_user_ats_imis_id(user, user_info.ats_imis_id, request)
            force_email_verification(user)  # trusted source
            notify(ATSIMISUserCreatedEvent(user, request))
            request.environ['nti.request_had_transaction_side_effects'] = 'True'

        response = _create_success_response(request,
                                            userid=user.username,
                                            success=_return_url(request),)
    except Exception as e:  # pylint: disable=broad-except
        logger.exception('Failed to login with ats_imis')
        response = _create_failure_response(request,
                                            _return_url(request, 'failure'),
                                            error=str(e))
    return response


@component.adapter(IRequest)
@interface.implementer(IUnauthenticatedUserLinkProvider)
class _SimpleUnauthenticatedUserATSIMISLinkProvider(object):

    rel = REL_LOGIN_ATS_IMIS

    title = _('ATS-IMIS Account')

    def __init__(self, request):
        self.request = request

    def get_links(self):
        auth_settings = component.queryUtility(IATSIMISLogonSettings)
        result = []
        if auth_settings is not None:
            elements = (self.rel,)
            root = self.request.route_path('objects.generic.traversal',
                                           traverse=())
            root = root[:-1] if root.endswith('/') else root
            result.append(Link(root, elements=elements, rel=self.rel, title=self.title))
        return result


@interface.implementer(ILogonLinkProvider)
@component.adapter(IMissingUser, IRequest)
class _SimpleMissingUserATSIMISLinkProvider(_SimpleUnauthenticatedUserATSIMISLinkProvider):

    def __init__(self, user, request):
        super(_SimpleMissingUserATSIMISLinkProvider, self).__init__(request)
        self.user = user

    def __call__(self):
        links = self.get_links()
        return links[0] if links else None
