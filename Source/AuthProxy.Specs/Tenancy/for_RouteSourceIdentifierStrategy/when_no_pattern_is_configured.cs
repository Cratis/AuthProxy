// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_RouteSourceIdentifierStrategy;

public class when_no_pattern_is_configured : Specification
{
    RouteSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    RouteOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new RouteSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new RouteOptions { Pattern = null };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => Assert.False(_succeeded);
    [Fact] void should_return_empty_string() => Assert.Equal("", _sourceIdentifier);
}
