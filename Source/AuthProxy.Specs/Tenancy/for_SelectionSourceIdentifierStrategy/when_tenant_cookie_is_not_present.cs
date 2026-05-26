// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectionSourceIdentifierStrategy;

public class when_tenant_cookie_is_not_present : Specification
{
    SelectionSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    bool _succeeded;
    string _sourceIdentifier = "initial";

    void Establish()
    {
        _strategy = new SelectionSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, new SelectionOptions(), out _sourceIdentifier);

    [Fact] void should_not_succeed() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_source_identifier() => _sourceIdentifier.ShouldEqual(string.Empty);
}
