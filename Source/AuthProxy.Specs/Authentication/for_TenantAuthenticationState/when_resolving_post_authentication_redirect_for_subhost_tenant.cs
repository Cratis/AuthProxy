// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TenantAuthenticationState;

public class when_resolving_post_authentication_redirect_for_subhost_tenant : Specification
{
    bool _succeeded;
    string _redirectUri = string.Empty;

    void Establish()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("auth.cratis.studio");

        var properties = new AuthenticationProperties { RedirectUri = "/" };
        properties.Items[TenantAuthenticationState.TenantIdStateKey] = "nova";
        properties.Items[TenantAuthenticationState.StrategyStateKey] = nameof(C.TenantSourceIdentifierResolverType.SubHost);
        properties.Items[TenantAuthenticationState.SubHostParentHostStateKey] = "cratis.studio";

        _succeeded = TenantAuthenticationState.TryResolvePostAuthenticationRedirectUri(
            context,
            properties,
            "/dashboard?tab=home",
            out _redirectUri);
    }

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_build_subhost_redirect_uri() => _redirectUri.ShouldEqual("https://nova.cratis.studio/dashboard?tab=home");
}