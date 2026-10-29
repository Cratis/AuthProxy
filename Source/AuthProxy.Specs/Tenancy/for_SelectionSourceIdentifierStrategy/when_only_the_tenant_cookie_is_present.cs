// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectionSourceIdentifierStrategy;

public class when_only_the_tenant_cookie_is_present : Specification
{
    SelectionSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    bool _succeeded;
    string _sourceIdentifier = string.Empty;

    void Establish()
    {
        _strategy = new SelectionSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.Tenant}=tenant-a";
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, new SelectionOptions(), out _sourceIdentifier);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _sourceIdentifier.ShouldEqual(string.Empty);
}
