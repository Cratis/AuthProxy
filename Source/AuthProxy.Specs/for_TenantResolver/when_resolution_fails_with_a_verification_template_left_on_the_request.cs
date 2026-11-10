// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_resolution_fails_with_a_verification_template_left_on_the_request : a_tenant_resolver
{
    string _tenantId = "unset";
    bool _succeededWithTenantId;

    void Establish()
    {
        _context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = "https://stale.example.com/{tenant}";
        _resolver = CreateResolver(
            ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.Host)),
            new HostSourceIdentifierStrategy());
    }

    void Because()
    {
        _succeeded = _resolver.TryResolve(_context, out _result);
        _succeededWithTenantId = _resolver.TryResolve(_context, out _tenantId);
    }

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_resolve_to_a_tenant_id() => _succeededWithTenantId.ShouldBeFalse();
    [Fact] void should_return_an_empty_tenant_id() => _tenantId.ShouldEqual(string.Empty);
    [Fact] void should_return_an_empty_result() => _result.ShouldEqual(new TenantResolutionResult(string.Empty, C.TenantSourceIdentifierResolverType.None));
    [Fact] void should_clear_the_verification_template() => _context.Items.ContainsKey(TenancyMiddleware.TenantVerificationUrlTemplateItemKey).ShouldBeFalse();
}
