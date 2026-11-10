// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_a_whitespace_route_segment_is_presented_and_no_tenant_map_is_configured : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Path = "/ /x";
        _resolver = CreateResolver(
            ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.Route, new RouteOptions { Pattern = "^/(?<sourceIdentifier>.+)/x$" })),
            new RouteSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_not_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeFalse();
}
