// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_claim_exists_on_claims_principal : Specification
{
    ClaimSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new ClaimSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
        [
            new Claim("http://schemas.microsoft.com/identity/claims/tenantid", "my-aad-tenant")
        ],
        "aad");
        _context.User = new ClaimsPrincipal(identity);
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, [], out _sourceIdentifier);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_claim_value() => Assert.Equal("my-aad-tenant", _sourceIdentifier);
}
