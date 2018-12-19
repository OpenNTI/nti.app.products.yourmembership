#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

import os
import uuid
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

from nti.app.products.yourmembership.interfaces import YourMembershipException
from nti.app.products.yourmembership.interfaces import IYourMembershipLogonSettings
from nti.app.products.yourmembership.interfaces import YourMembershipSessionException
from nti.app.products.yourmembership.interfaces import YourMembershipUserCreatedEvent
from nti.app.products.yourmembership.interfaces import YourMembershipUserInfoException
from nti.app.products.yourmembership.interfaces import YourMembershipAuthTokenException

from nti.app.products.yourmembership.utils import set_user_yourmembership_id
from nti.app.products.yourmembership.utils import get_user_for_yourmembership_id

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

#: The initial YOURMEMBERSHIP login rel
REL_LOGIN_YOURMEMBERSHIP = 'logon.your.membership'

#: The redirect rel after YOURMEMBERSHIP auth
LOGON_YOURMEMBERSHIP = 'logon.your.membership2'

YourMembershipUserInfo = namedtuple('YourMembershipUserInfo',
                             ('yourmembership_id',
                              'website_id',
                              'first_name',
                              'last_name',
                              'email'))

#: formatted str: api_key, call_id
CREATE_SESSION_XML = """
                    <?xml version="1.0" encoding="utf-8" ?>
                    <YourMembership>
                        <Version>2.30</Version>
                        <ApiKey>%s</ApiKey>
                        <CallID>%s</CallID>
                        <Call Method="Session.Create"></Call>
                    </YourMembership>
                    """

#: formatted str: api_key, call_id, session_id, return_url
CREATE_TOKEN_XML = """
                   <?xml version="1.0" encoding="utf-8" ?>
                   <YourMembership>
                       <Version>2.30</Version>
                       <ApiKey>%s</ApiKey>
                       <CallID>%s</CallID>
                       <SessionID>%s</SessionID>
                       <Call Method="Auth.CreateToken">
                            <RetUrl>%s</RetUrl>
                       </Call>
                   </YourMembership>
                   """

#: formatted str: api_key, call_id, session_id
GET_PROFILE_XML = """
                  <?xml version="1.0" encoding="utf-8" ?>
                  <YourMembership>
                    <Version>2.30</Version>
                    <ApiKey>%s</ApiKey>
                    <CallID>%s</CallID>
                    <SessionID>%s</SessionID>
                    <Call Method="Member.Profile.Get"></Call>
                  </YourMembership>
                  """


#: formatted str: api_key, call_id, session_id
GET_PROFILE_MINI_XML = """
                  <YourMembership>
                    <Version>2.30</Version>
                    <ApiKey>%s</ApiKey>
                    <CallID>%s</CallID>
                    <SessionID>%s</SessionID>
                    <Call Method="Member.Profile.GetMini"></Call>
                  </YourMembership>
                  """


def redirect_yourmembership2_uri(request):
    root = request.route_path('objects.generic.traversal', traverse=())
    root = root[:-1] if root.endswith('/') else root
    target = urllib_parse.urljoin(request.application_url, root)
    target = target + '/' if not target.endswith('/') else target
    target = urllib_parse.urljoin(target, LOGON_YOURMEMBERSHIP)
    return target


def redirect_yourmembership2_params(state=None):
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    params = {'state': state}
    return params


def generate_username():
    username_util = component.getUtility(IUsernameGeneratorUtility)
    return username_util.generate_username()


def _get_auth_url():
    auth_settings = component.getUtility(IYourMembershipLogonSettings)
    auth_url = auth_settings.login_url
    return auth_url[:-1] if auth_url.endswith('/') else auth_url


def _get_user_info_url():
    auth_settings = component.getUtility(IYourMembershipLogonSettings)
    return auth_settings.userinfo_url


def _parse_profile_response(xml_response):
    """
    Parse the given xml response into a `YourMembershipUserInfo`.

    <YourMembership_Response>
    <ErrCode>0</ErrCode>
    <Member.Profile.GetMini>
        <ID>8D88D43A-B15B-4041-BEA0-89B05B2D9540</ID>
        <WebsiteID>987654321</WebsiteID>
        <EmailAddr>demo@yourmembership.com</EmailAddr>
        <NamePrefix>Mrs</NamePrefix>
        <FirstName>Elizabeth</FirstName>
        <MiddleName>M</MiddleName>
        <LastName>Allen</LastName>
        <NameSuffix></NameSuffix>
        <Nickname>Lizzy</Nickname>
        <HeadshotImageURI>http://c.yourmembership.com/sites/alumni.yourmembership.com/photos/alumni/20080225_192243_17432.jpg</HeadshotImageURI>
    </Member.Profile.GetMini>
    </YourMembership_Response>
    """
    doc = BeautifulSoup(xml_response, 'lxml')

    def _get_val(field):
        field_val = doc.find(field)
        return field_val and field_val.text

    first_name = _get_val('firstname')
    last_name = _get_val('lastname')
    email = _get_val('emailaddr')
    yourmembership_id = _get_val('id')
    website_id = _get_val('websiteid')
    result = YourMembershipUserInfo(yourmembership_id, website_id,
                                    first_name, last_name,
                                    email)
    if not website_id or not email or not yourmembership_id:
        logger.warning('Missing website_id, email, or profile id when fetching yourmembership profile (%s)',
                       xml_response)
        raise YourMembershipUserInfoException("Missing website_id, email, or profile id when fetching yourmembership profile")
    return result


def _lookup_user(user_info):
    return get_user_for_yourmembership_id(user_info.yourmembership_id)


def get_call_id():
    """
    Each your membership requires a unique id.
    25 character limit.
    """
    return str(uuid.uuid4().time_low)


def _parse_auth_token_response(xml_response):
    """
    Parse the given session response.

    <YourMembership_Response>
    <ErrCode>0</ErrCode>
    <Auth.CreateToken>
        <AuthToken>78F0C1B7-3365-46D2-9BF1-6A2D4EED7C11</AuthToken>
        <GoToUrl>http://alumni.yourmembership.com/general/login.asp?authtoken=171B6494-6ECA-4FD0-905A-3A7E0D3F4DA2&persist=1&returl=http%3A%2F%2Fw3%2Eorg</GoToUrl>
    </Auth.CreateToken>
    </YourMembership_Response>
    """
    doc = BeautifulSoup(xml_response, 'lxml')
    err_code = doc.find('errcode')
    err_code = err_code and err_code.text

    if err_code and err_code != '0':
        # Error condition
        msg = doc.find('errdesc')
        msg = msg and msg.text
        logger.warning('Exception while fetching YourMembership auth token (code=%s) (%s)',
                       err_code, msg or 'None')
        raise YourMembershipAuthTokenException(msg)

    auth_token = doc.find('authtoken')
    auth_token = auth_token and auth_token.text
    if not auth_token:
        logger.warning('Auth token not returned (%s)',
                       xml_response)
        raise YourMembershipAuthTokenException('YourMembership auth token not found')

    return_url = doc.find('gotourl')
    return_url = return_url and return_url.text
    if not return_url:
        logger.warning('GoToUrl not returned (%s)',
                       xml_response)
        raise YourMembershipAuthTokenException('YourMembership GoToUrl not found')
    return return_url


def get_auth_token(request, logon_settings, session_id, return_url):
    """
    Returns the auth url.
    """
    auth_token_xml = CREATE_TOKEN_XML % (logon_settings.api_key,
                                         get_call_id(),
                                         session_id,
                                         return_url)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(logon_settings.api_endpoint,
                             auth_token_xml,
                             headers=headers)
    if response.status_code != 200:
        return _create_failure_response(
                request,
                _return_url(request, 'failure'),
                error=_('Invalid response while getting auth token.'))
    try:
        return _parse_auth_token_response(response.text)
    except YourMembershipException:
        return _create_failure_response(
                request,
                _return_url(request, 'failure'),
                error=_('Invalid response while getting auth token'))


def _parse_session_response(xml_response):
    """
    Parse the given session response.

    <YourMembership_Response>
    <ErrCode>0</ErrCode>
    <ExtendedErrorInfo></ExtendedErrorInfo>
    <Session.Create>
    <SessionID>64D638E5-3BE4-4A3D-B70B-9BF3FBF0A1ED</SessionID>
    </Session.Create>
    </YourMembership_Response>
    """
    doc = BeautifulSoup(xml_response, 'lxml')
    err_code = doc.find('errcode')
    err_code = err_code and err_code.text

    if err_code and err_code != '0':
        # Error condition
        msg = doc.find('errdesc')
        msg = msg and msg.text
        logger.warning('Exception while fetching YourMembership session (code=%s) (%s)',
                       err_code, msg or 'None')
        raise YourMembershipSessionException(msg)

    session_id = doc.find('sessionid')
    session_id = session_id and session_id.text
    if not session_id:
        logger.warning('Session id not returned (%s)',
                       xml_response)
        raise YourMembershipSessionException('YourMembership session id not found')
    return session_id


def create_session(request, logon_settings):
    session_xml = CREATE_SESSION_XML % (logon_settings.api_key, get_call_id())
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(logon_settings.api_endpoint,
                             session_xml,
                             headers=headers)
    if response.status_code != 200:
        return _create_failure_response(
                request,
                _return_url(request, 'failure'),
                error=_('Invalid response while creating session.'))
    try:
        session_id = _parse_session_response(response.text)
        return session_id
    except YourMembershipException:
        return _create_failure_response(
                request,
                _return_url(request, 'failure'),
                error=_('Invalid response while creating session.'))


@view_config(name=REL_LOGIN_YOURMEMBERSHIP,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='GET',
             renderer='rest')
def yourmembership_auth(request, success=None, failure=None, state=None):
    """
    1. Establish a session via the Session.Create call
    2. Begin the authentication process by using the Auth.CreateToken.
       This takes a return url and returns a url the browser should be sent to.
    3. Send browser to the provided url
    """
    logon_settings = component.getUtility(IYourMembershipLogonSettings)
    session_id = create_session(request, logon_settings)
    request.session['yourmembership.session_id'] = session_id
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    params = redirect_yourmembership2_params(state)
    auth2_url = redirect_yourmembership2_uri(request)

    target = get_auth_token(request, logon_settings, session_id, auth2_url)

    for key, value in (('success', success), ('failure', failure)):
        value = value or request.params.get(key)
        if value:
            request.session['yourmembership.' + key] = value

    # save state for validation
    request.session['yourmembership.state'] = state

    # redirect
    target = '%s?%s' % (target, urllib_parse.urlencode(params))
    response = hexc.HTTPSeeOther(location=target)
    return response


def _return_url(request, url_type='success'):
    if url_type in request.params:
        return request.params.get(url_type)
    return request.session.get('yourmembership.' + url_type)


@view_config(name=LOGON_YOURMEMBERSHIP,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='GET',
             renderer='rest')
def yourmembership_auth2(request):
    """
    Successfully authenticated
    """
    params = request.params
    # Confirm anti-forgery state token
    if not request.session.get('yourmembership.state'):
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Missing state.'))
    if 'state' in params:
        params_state = params.get('state')
        session_state = request.session.get('yourmembership.state')
        if params_state != session_state:
            return _create_failure_response(request,
                                            _return_url(request, 'failure'),
                                            error=_(u'Incorrect state values.'))

    logon_settings = component.getUtility(IYourMembershipLogonSettings)
    session_id = request.session.get('yourmembership.session_id')
    if not session_id:
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Missing session id.'))

    try:
        profile_xml = GET_PROFILE_MINI_XML % (logon_settings.api_key,
                                              get_call_id(),
                                              session_id)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(logon_settings.api_endpoint,
                                 profile_xml,
                                 headers=headers)
        if response.status_code != 200:
            return _create_failure_response(
                    request,
                    _return_url(request, 'failure'),
                    error=_('Invalid response while getting user profile.'))
        try:
            user_info = _parse_profile_response(response.text)
        except YourMembershipException:
            return _create_failure_response(
                    request,
                    _return_url(request, 'failure'),
                    error=_('Invalid response while getting auth token'))

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
            set_user_yourmembership_id(user, user_info.yourmembership_id, request)
            force_email_verification(user)  # trusted source
            notify(YourMembershipUserCreatedEvent(user, request))
            request.environ['nti.request_had_transaction_side_effects'] = 'True'

        response = _create_success_response(request,
                                            userid=user.username,
                                            success=_return_url(request),)
    except Exception as e:  # pylint: disable=broad-except
        logger.exception('Failed to login with your_membership')
        response = _create_failure_response(request,
                                            _return_url(request, 'failure'),
                                            error=str(e))
    return response


@component.adapter(IRequest)
@interface.implementer(IUnauthenticatedUserLinkProvider)
class _SimpleUnauthenticatedUserYourMembershipLinkProvider(object):

    rel = REL_LOGIN_YOURMEMBERSHIP

    title = _('YourMembership Account')

    def __init__(self, request):
        self.request = request

    def get_links(self):
        auth_settings = component.queryUtility(IYourMembershipLogonSettings)
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
class _SimpleMissingUserYourMembershipLinkProvider(_SimpleUnauthenticatedUserYourMembershipLinkProvider):

    def __init__(self, user, request):
        super(_SimpleMissingUserYourMembershipLinkProvider, self).__init__(request)
        self.user = user

    def __call__(self):
        links = self.get_links()
        return links[0] if links else None
