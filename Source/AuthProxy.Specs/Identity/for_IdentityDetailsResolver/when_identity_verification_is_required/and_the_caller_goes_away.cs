// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A cancelled call establishes nothing, and "nothing" is not "yes". Cancellation arrives as the same
/// exception family as every other transport failure, which is exactly why the released blanket handler
/// turned it into an empty-but-successful answer.
/// </summary>
public class and_the_caller_goes_away : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish()
    {
        _context.RequestAborted = new CancellationToken(canceled: true);
        _handler.Respond = (_, _, token) => Task.FromCanceled<HttpResponseMessage>(token);
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_not_record_an_authorization() => _authorizationCache.DidNotReceive().Record(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>());
    [Fact] void should_clear_any_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
}
