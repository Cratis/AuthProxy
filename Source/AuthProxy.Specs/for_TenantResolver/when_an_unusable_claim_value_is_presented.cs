// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// The unusable-identifier check runs before the tenant map is consulted, so a tenant listing the value does not
/// rescue it, and the rejection is logged.
/// </summary>
public class when_an_unusable_claim_value_is_presented : a_tenant_resolver
{
    void Establish()
    {
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_claim", "a b")], "aad"));
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["a b"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Claim, new ClaimOptions { ClaimType = "tenant_claim" })),
            new ClaimSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeTrue();
    [Fact] void should_name_the_claim_strategy_in_the_log() => _logger.Text.Contains("Claim", StringComparison.Ordinal).ShouldBeTrue();
}
