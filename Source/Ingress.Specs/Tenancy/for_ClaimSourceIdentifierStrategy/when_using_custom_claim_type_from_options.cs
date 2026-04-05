// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_using_custom_claim_type_from_options : Specification
{
    ClaimSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    JsonObject _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new ClaimSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new JsonObject { ["claimType"] = "custom_tenant_claim" };

        var identity = new ClaimsIdentity(
        [
            new Claim("custom_tenant_claim", "custom-tenant-value")
        ],
        "aad");
        _context.User = new ClaimsPrincipal(identity);
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_custom_claim_value() => Assert.Equal("custom-tenant-value", _sourceIdentifier);
}
