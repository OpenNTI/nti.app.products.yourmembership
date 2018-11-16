#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

# pylint: disable=protected-access,too-many-public-methods,arguments-differ

from hamcrest import is_
from hamcrest import raises
from hamcrest import calling
from hamcrest import assert_that

import unittest

from nti.app.products.yourmembership.interfaces import YourMembershipSessionException
from nti.app.products.yourmembership.interfaces import YourMembershipUserInfoException
from nti.app.products.yourmembership.interfaces import YourMembershipAuthTokenException

from nti.app.products.yourmembership.logon import _parse_session_response
from nti.app.products.yourmembership.logon import _parse_profile_response
from nti.app.products.yourmembership.logon import _parse_auth_token_response


user_info_response = \
    """
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


auth_token_response = \
    """
    <YourMembership_Response>
    <ErrCode>0</ErrCode>
    <Auth.CreateToken>
        <AuthToken>78F0C1B7-3365-46D2-9BF1-6A2D4EED7C11</AuthToken>
        <GoToUrl>http://alumni.yourmembership.com/general/login.asp?authtoken=171B6494-6ECA-4FD0-905A-3A7E0D3F4DA2&persist=1&returl=http%3A%2F%2Fw3%2Eorg</GoToUrl>
    </Auth.CreateToken>
    </YourMembership_Response>
    """


create_session_response = \
    """
    <YourMembership_Response>
    <ErrCode>0</ErrCode>
    <ExtendedErrorInfo></ExtendedErrorInfo>
    <Session.Create>
    <SessionID>64D638E5-3BE4-4A3D-B70B-9BF3FBF0A1ED</SessionID>
    </Session.Create>
    </YourMembership_Response>
    """


exception_response = \
    """
    <YourMembership_Response>
    <ErrCode>403</ErrCode>
    <ErrDesc>Method requires authentication.</ErrDesc>
    <XmlRequest>
        <YourMembership>
            <Version>2.30</Version>
            <ApiKey>3D638C5F-CCE2-4638-A2C1-355FA7BBC917</ApiKey>
            <CallID>001</CallID>
            <SessionID>A07C3BCC-0B39-4977-9E64-C00E918D572E</SessionID>
            <Call Method="Member.Profile.Get"></Call>
        </YourMembership>
    </XmlRequest>
    </YourMembership_Response>
    """


class TestResponseParsing(unittest.TestCase):

    def test_auth_token_response(self):
        """
        Test parsing an YourMembership xml auth token response.
        """
        return_url = _parse_auth_token_response(auth_token_response)
        assert_that(return_url,
                    is_('http://alumni.yourmembership.com/general/login.asp?authtoken=171B6494-6ECA-4FD0-905A-3A7E0D3F4DA2&persist=1&returl=http%3A%2F%2Fw3%2Eorg'))

    def test_auth_token_error(self):
        """
        Test parsing an YourMembership xml auth token response error
        """
        assert_that(calling(_parse_auth_token_response).with_args(exception_response),
                    raises(YourMembershipAuthTokenException))

    def test_session_response(self):
        """
        Test parsing an YourMembership xml session response.
        """
        session_id = _parse_session_response(create_session_response)
        assert_that(session_id,
                    is_('64D638E5-3BE4-4A3D-B70B-9BF3FBF0A1ED'))

    def test_session_error(self):
        """
        Test parsing an YourMembership xml session response error
        """
        assert_that(calling(_parse_session_response).with_args(exception_response),
                    raises(YourMembershipSessionException))

    def test_profile_response(self):
        """
        Test parsing an YourMembership xml profile response.
        """
        user_info = _parse_profile_response(user_info_response)
        assert_that(user_info.yourmembership_id, is_('8D88D43A-B15B-4041-BEA0-89B05B2D9540'))
        assert_that(user_info.website_id, is_('987654321'))
        assert_that(user_info.first_name, is_('Elizabeth'))
        assert_that(user_info.last_name, is_('Allen'))
        assert_that(user_info.email, is_('demo@yourmembership.com'))

    def test_profile_error(self):
        """
        Test parsing an YourMembership xml profile response error
        """
        assert_that(calling(_parse_profile_response).with_args(exception_response),
                    raises(YourMembershipUserInfoException))
