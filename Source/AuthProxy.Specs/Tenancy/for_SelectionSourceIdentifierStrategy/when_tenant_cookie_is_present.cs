// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectionSourceIdentifierStrategy;

public class when_tenant_cookie_is_present : Specification
{
    const string TenantId = "tenant-a";

    SelectionSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    bool _succeeded;
    string _sourceIdentifier = string.Empty;

    void Establish()
    {
        _strategy = new SelectionSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.Tenant}={TenantId}";
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, new SelectionOptions(), out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_the_tenant_id() => _sourceIdentifier.ShouldEqual(TenantId);
}
