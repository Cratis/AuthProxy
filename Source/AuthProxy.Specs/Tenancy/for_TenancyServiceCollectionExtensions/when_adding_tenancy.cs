// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Tenancy.for_TenancyServiceCollectionExtensions;

public class when_adding_tenancy : Specification
{
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddTenancy();
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact] void should_register_tenant_resolver() =>
        _serviceProvider.GetRequiredService<ITenantResolver>().ShouldBeOfExactType<TenantResolver>();

    [Fact]
    void should_register_all_source_identifier_strategies()
    {
        var strategies = _serviceProvider.GetRequiredService<IEnumerable<ISourceIdentifierStrategy>>().ToList();

        strategies.Exists(_ => _ is HostSourceIdentifierStrategy).ShouldBeTrue();
        strategies.Exists(_ => _ is ClaimSourceIdentifierStrategy).ShouldBeTrue();
        strategies.Exists(_ => _ is RouteSourceIdentifierStrategy).ShouldBeTrue();
        strategies.Exists(_ => _ is SpecifiedSourceIdentifierStrategy).ShouldBeTrue();
    }
}
