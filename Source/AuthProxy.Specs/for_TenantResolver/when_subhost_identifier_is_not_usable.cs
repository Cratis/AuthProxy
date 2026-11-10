// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// A dot segment cannot reach the resolver through a sub-host (the strategy rejects dotted sub-hosts), so an
/// identifier with a disallowed character is used instead.
/// </summary>
public class when_subhost_identifier_is_not_usable : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString("a+b.example.com");
        _resolver = CreateResolver(
            ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.SubHost, new SubHostOptions { ParentHost = "example.com" })),
            new SubHostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeTrue();
}
