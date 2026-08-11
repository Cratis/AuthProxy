// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_best_effort;

/// <summary>
/// A body claiming the caller is authorized while denying they are authenticated establishes nothing, and
/// under <see cref="C.IdentityVerificationMode.Required"/> establishing nothing is a refusal. Here it is
/// not: the released proxy never compared the two properties, so a service that has been answering this
/// combination — a placeholder, a partially populated envelope, a serializer writing defaults — has been
/// admitted all along, and the default mode keeps admitting it.
/// </summary>
public class and_the_service_answers_conflicting_verdicts : given.a_best_effort_verification_resolver
{
    IdentityProviderResult _result;

    void Establish() => _handler.Respond = (_, _) => Task.FromResult(Response(HttpStatusCode.OK, ConflictingBody));

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_authorize_the_caller() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_merge_the_details_the_service_supplied() => Detail(_result.Details, DetailName).ShouldEqual(DetailValue);
    [Fact] void should_leave_the_response_status_alone() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
