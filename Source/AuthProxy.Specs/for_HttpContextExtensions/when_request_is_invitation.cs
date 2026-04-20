// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_HttpContextExtensions;

public class when_request_is_invitation : Specification
{
    DefaultHttpContext _context;
    bool _isInvitation;
    bool _hasToken;
    string _token;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";
        _token = string.Empty;
    }

    void Because()
    {
        _isInvitation = _context.IsInvitation();
        _hasToken = _context.TryGetInvitationToken(out _token);
    }

    [Fact] void should_identify_the_request_as_invitation() => _isInvitation.ShouldBeTrue();
    [Fact] void should_extract_the_invitation_token() => _token.ShouldEqual("some-token");
    [Fact] void should_report_that_an_invitation_token_exists() => _hasToken.ShouldBeTrue();
}