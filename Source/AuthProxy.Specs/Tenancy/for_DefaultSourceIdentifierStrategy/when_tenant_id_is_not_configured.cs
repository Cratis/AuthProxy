// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_DefaultSourceIdentifierStrategy;

public class when_tenant_id_is_not_configured : Specification
{
    DefaultSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    DefaultOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new DefaultSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new DefaultOptions { TenantId = null };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_string() => _sourceIdentifier.ShouldEqual(string.Empty);
}
