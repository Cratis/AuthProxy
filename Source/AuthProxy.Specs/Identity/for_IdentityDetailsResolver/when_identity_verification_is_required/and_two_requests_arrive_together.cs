// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A single page load produces a burst of requests for the same caller, so the resolver collapses them onto
/// one verification and hands the established answer to every waiter.
/// <para>
/// The gate holds the first verification open until the second request has queued behind it, so the sharing
/// is actually exercised rather than depending on the first call happening to finish first.
/// </para>
/// </summary>
public class and_two_requests_arrive_together : given.a_required_verification_resolver
{
    readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    IdentityProviderResult[] _results;

    void Establish() => _handler.Respond = async (_, _, _) =>
    {
        await _gate.Task;
        return Response(HttpStatusCode.OK, PositiveBody);
    };

    async Task Because()
    {
        var first = _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
        var second = _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
        _gate.SetResult();
        _results = await Task.WhenAll(first, second);
    }

    [Fact] void should_verify_once() => _handler.Calls.ShouldEqual(1);
    [Fact] void should_authorize_both_waiters() => _results.Count(_ => _.IsAuthorized).ShouldEqual(2);
}
