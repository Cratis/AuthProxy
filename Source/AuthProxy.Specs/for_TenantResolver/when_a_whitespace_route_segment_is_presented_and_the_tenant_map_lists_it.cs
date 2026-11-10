// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// Pins current behaviour: the unusable-identifier check is skipped for whitespace, so a tenant that lists a
/// whitespace source identifier is matched by a whitespace route segment.
/// </summary>
public class when_a_whitespace_route_segment_is_presented_and_the_tenant_map_lists_it : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Path = "/ /x";
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = [" "] } },
                Resolution(C.TenantSourceIdentifierResolverType.Route, new RouteOptions { Pattern = "^/(?<sourceIdentifier>.+)/x$" })),
            new RouteSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_listing_tenant() => _result.TenantId.ShouldEqual("tenant-one");
    [Fact] void should_report_the_route_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Route);
}
