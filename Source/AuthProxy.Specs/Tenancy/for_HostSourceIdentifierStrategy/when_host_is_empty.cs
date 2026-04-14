// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_HostSourceIdentifierStrategy;

public class when_host_is_empty : Specification
{
    HostSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    object? _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new HostSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = null;
        _context.Request.Host = new HostString("");
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_string() => _sourceIdentifier.ShouldEqual("");
}