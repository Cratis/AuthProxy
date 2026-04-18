// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SubHostSourceIdentifierStrategy;

public class when_parent_host_is_not_configured : Specification
{
    SubHostSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    SubHostOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new SubHostSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("acme.example.com");
        _options = new SubHostOptions { ParentHost = "" };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_source_identifier() => _sourceIdentifier.ShouldEqual(string.Empty);
}
