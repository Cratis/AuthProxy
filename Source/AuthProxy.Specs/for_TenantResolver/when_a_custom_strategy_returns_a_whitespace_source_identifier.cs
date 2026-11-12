// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_a_custom_strategy_returns_a_whitespace_source_identifier : a_tenant_resolver
{
    void Establish()
    {
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["tenant-one"] = new C.Tenant { SourceIdentifiers = [" \t\u2003"], Domains = [" \t\u2003"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Claim, new SpecifiedOptions())),
            new FixedIdentifierStrategy(C.TenantSourceIdentifierResolverType.Claim, " \t\u2003"));
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
}
