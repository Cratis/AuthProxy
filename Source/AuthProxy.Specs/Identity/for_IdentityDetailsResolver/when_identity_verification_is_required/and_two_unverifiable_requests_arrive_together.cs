// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// Sharing one verification between concurrent requests is a performance measure, and a performance measure
/// must never be the thing that widens access. A waiter is entitled to the answer the verification
/// established — and when it established nothing, "nothing" is what it gets, however many callers were
/// queued behind it.
/// </summary>
public class and_two_unverifiable_requests_arrive_together : given.a_required_verification_resolver
{
    readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    IdentityProviderResult[] _results;

    void Establish() => _handler.Respond = async (_, _, _) =>
    {
        await _gate.Task;
        return Response(HttpStatusCode.ServiceUnavailable, "down");
    };

    async Task Because()
    {
        var first = _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
        var second = _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
        _gate.SetResult();
        _results = await Task.WhenAll(first, second);
    }

    [Fact] void should_authorize_neither_waiter() => _results.Count(_ => _.IsAuthorized).ShouldEqual(0);
    [Fact] void should_cache_nothing_for_a_later_request() => _handler.Calls.ShouldEqual(2);
}
