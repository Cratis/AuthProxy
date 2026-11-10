// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_subhost_has_a_blank_subhost : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString(".example.com");
        _resolver = CreateResolver(
            ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.SubHost, new SubHostOptions { ParentHost = "example.com" })),
            new SubHostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_not_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeFalse();
}
