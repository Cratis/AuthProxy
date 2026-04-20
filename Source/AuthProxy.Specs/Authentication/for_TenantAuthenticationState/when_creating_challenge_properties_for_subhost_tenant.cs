// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TenantAuthenticationState;

public class when_creating_challenge_properties_for_subhost_tenant : Specification
{
    AuthenticationProperties _properties = default!;

    void Establish()
    {
        var context = new DefaultHttpContext();
        var resolver = new StubTenantResolver(new TenantResolutionResult("nova", C.TenantSourceIdentifierResolverType.SubHost, "cratis.studio"));

        _properties = TenantAuthenticationState.CreateChallengeProperties(context, resolver, "/dashboard");
    }

    [Fact] void should_set_redirect_uri() => _properties.RedirectUri.ShouldEqual("/dashboard");
    [Fact] void should_include_tenant_id() => _properties.Items[TenantAuthenticationState.TenantIdStateKey].ShouldEqual("nova");
    [Fact] void should_include_strategy() => _properties.Items[TenantAuthenticationState.StrategyStateKey].ShouldEqual(nameof(C.TenantSourceIdentifierResolverType.SubHost));
    [Fact] void should_include_subhost_parent_host() => _properties.Items[TenantAuthenticationState.SubHostParentHostStateKey].ShouldEqual("cratis.studio");

    sealed class StubTenantResolver(TenantResolutionResult resolvedResult) : ITenantResolver
    {
        public bool TryResolve(HttpContext context, out string tenantId)
        {
            tenantId = resolvedResult.TenantId;
            return true;
        }

        public bool TryResolve(HttpContext context, out TenantResolutionResult result)
        {
            result = resolvedResult;
            return true;
        }
    }
}