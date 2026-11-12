// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// Rejects a whitespace-only claim value even when a tenant lists the same source identifier.
/// </summary>
public class when_a_whitespace_claim_value_is_presented_and_the_tenant_map_lists_it : a_tenant_resolver
{
    void Establish()
    {
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_claim", " ")], "aad"));
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = [" "] } },
                Resolution(C.TenantSourceIdentifierResolverType.Claim, new ClaimOptions { ClaimType = "tenant_claim" })),
            new ClaimSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_not_report_a_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.None);
}
