// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_best_effort;

/// <summary>
/// A deployment that states a timeout gets one whatever the mode is — the mode decides what an
/// <em>unstated</em> timeout means, not whether a stated one is obeyed. What the mode does decide is what
/// running out of time costs: here the caller is admitted anyway, with that service's details missing,
/// because enrichment that did not arrive is the thing best-effort is named after.
/// </summary>
public class and_a_configured_timeout_elapses : given.a_best_effort_verification_resolver
{
    volatile bool _theCallWasAbandoned;
    IdentityProviderResult _result;

    void Establish()
    {
        _service.IdentityVerificationTimeout = TimeSpan.FromMilliseconds(50);
        _handler.Respond = async (_, token) =>
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            }
            catch (OperationCanceledException)
            {
                _theCallWasAbandoned = true;
                throw;
            }

            return Response(HttpStatusCode.OK, NegativeBody);
        };
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_abandon_the_call() => _theCallWasAbandoned.ShouldBeTrue();
    [Fact] void should_still_admit_the_caller() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_carry_no_details_from_a_service_that_never_answered() => Detail(_result.Details, DetailName).ShouldBeEmpty();
}
