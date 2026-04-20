// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_HttpContextExtensions;

public class when_request_is_authentication_bootstrap_path : Specification
{
    DefaultHttpContext _context;
    bool _isAuthenticationBootstrap;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Path = "/signin-github";
    }

    void Because() => _isAuthenticationBootstrap = _context.IsAuthenticationBootstrap();

    [Fact] void should_identify_the_request_as_authentication_bootstrap() => _isAuthenticationBootstrap.ShouldBeTrue();
}