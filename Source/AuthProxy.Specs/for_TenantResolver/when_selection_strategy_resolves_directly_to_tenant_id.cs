// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_selection_strategy_resolves_directly_to_tenant_id : a_tenant_resolver
{
    void Establish()
    {
        _context.Items[SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey] = "selected-tenant";
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["other-tenant"] = new C.Tenant { Name = "Other", SourceIdentifiers = ["selected-tenant"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Selection)),
            new SelectionSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_confirmed_tenant() => _result.TenantId.ShouldEqual("selected-tenant");
    [Fact] void should_report_the_selection_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Selection);
}
