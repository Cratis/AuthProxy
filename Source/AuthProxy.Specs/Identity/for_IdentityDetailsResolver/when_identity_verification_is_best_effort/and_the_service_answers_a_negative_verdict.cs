// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_best_effort;

/// <summary>
/// The compatibility fence for the default mode. The released proxy read no verdict out of a successful
/// body at all — it took <c>details</c> and forwarded the caller — so a service answering the full envelope
/// with <c>isAuthorized: false</c> was admitted and enriched. That is the exact shape
/// <c>IdentityProviderResult</c> serializes, so it is what a service reaching for the documented response
/// type writes, and there are deployments answering it today for reasons that have nothing to do with
/// authorization: an account mid-onboarding, a trial that has lapsed into read-only, a profile the
/// application renders a banner for.
/// <para>
/// Reading it as a refusal here would take those deployments down on an upgrade, without a configuration
/// change and without anything to look at but a forbidden page. A deployment that wants the verdict
/// enforced asks for it with <see cref="C.IdentityVerificationMode.Required"/>, and
/// <c>when_identity_verification_is_required/and_the_service_refuses_the_caller</c> is the same body pinned
/// on the other side of that choice.
/// </para>
/// </summary>
public class and_the_service_answers_a_negative_verdict : given.a_best_effort_verification_resolver
{
    IdentityProviderResult _result;

    void Establish() => _handler.Respond = (_, _) => Task.FromResult(Response(HttpStatusCode.OK, NegativeBody));

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_authorize_the_caller() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_merge_the_details_the_service_supplied() => Detail(_result.Details, DetailName).ShouldEqual(DetailValue);
    [Fact] void should_write_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Identity);
    [Fact] void should_leave_the_response_status_alone() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_not_clear_the_recorded_authorization() => _authorizationCache.DidNotReceive().Clear(Arg.Any<HttpContext>());
}
