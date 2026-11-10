// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// Pins current behaviour: the unusable-identifier check is skipped for whitespace (see
/// <c language="text">ClaimSourceIdentifierStrategy</c>, which only rejects null or empty), so a tenant that lists
/// a whitespace source identifier is matched by a whitespace claim value.
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

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_listing_tenant() => _result.TenantId.ShouldEqual("tenant-one");
    [Fact] void should_report_the_claim_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Claim);
}
