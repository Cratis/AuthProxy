// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Tenancy;

namespace Cratis.Ingress.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_claim_is_not_found_anywhere : Specification
{
    ClaimSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    ClaimOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
        {
        _strategy = new ClaimSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new ClaimOptions { ClaimType = "nonexistent_claim" };
        }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => Assert.False(_succeeded);
    [Fact] void should_return_empty_string() => Assert.Equal("", _sourceIdentifier);
}
