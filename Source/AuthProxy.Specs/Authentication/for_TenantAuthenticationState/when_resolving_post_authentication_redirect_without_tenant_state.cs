// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TenantAuthenticationState;

public class when_resolving_post_authentication_redirect_without_tenant_state : Specification
{
    bool _succeeded;
    string _redirectUri = string.Empty;

    void Establish()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";

        var properties = new AuthenticationProperties { RedirectUri = "/" };

        _succeeded = TenantAuthenticationState.TryResolvePostAuthenticationRedirectUri(
            context,
            properties,
            "/",
            out _redirectUri);
    }

    [Fact] void should_not_succeed() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_redirect_uri() => _redirectUri.ShouldEqual(string.Empty);
}