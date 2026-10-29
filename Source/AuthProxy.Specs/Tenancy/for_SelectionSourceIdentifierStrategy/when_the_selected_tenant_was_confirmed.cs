// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectionSourceIdentifierStrategy;

public class when_the_selected_tenant_was_confirmed : Specification
{
    SelectionSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    bool _succeeded;
    string _sourceIdentifier = string.Empty;

    void Establish()
    {
        _strategy = new SelectionSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _context.Items[SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey] = "tenant-a";
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, new SelectionOptions(), out _sourceIdentifier);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_confirmed_tenant() => _sourceIdentifier.ShouldEqual("tenant-a");
}
