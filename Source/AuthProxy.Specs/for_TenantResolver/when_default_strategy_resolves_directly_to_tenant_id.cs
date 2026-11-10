// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// The configured identifier is the tenant, whether or not the tenant map knows it.
/// </summary>
public class when_default_strategy_resolves_directly_to_tenant_id : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            new C.Tenants { ["other-tenant"] = new C.Tenant { Name = "Other", SourceIdentifiers = ["lobby"] } },
            Resolution(C.TenantSourceIdentifierResolverType.Default, new DefaultOptions { TenantId = "lobby" })),
        new DefaultSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_configured_identifier() => _result.TenantId.ShouldEqual("lobby");
    [Fact] void should_report_the_default_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Default);
}
