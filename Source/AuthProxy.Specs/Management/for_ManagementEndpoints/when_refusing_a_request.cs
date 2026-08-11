// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints;

/// <summary>
/// Everything the management listener does not own gets the deployment's one refusal — the same answer
/// whether the request was a management path on the public listener or an application path on the management
/// one, and the same answer an unadmitted request gets from the admission gate.
/// <para>
/// Uniform on purpose, and uniform with <em>that</em> on purpose. This middleware runs ahead of the
/// admission gate, so a management path offered to the public listener is refused here and never reaches it
/// — and a refusal of its own shape would tell an unadmitted caller that an AuthProxy is here, that it has a
/// management listener, and what its paths are called. Writing the same refusal is what stops the two
/// answers from being two answers.
/// </para>
/// </summary>
public class when_refusing_a_request : given.a_management_endpoint
{
    async Task Because() => await _endpoints.Answer(_context, ManagementDisposition.Refuse);

    [Fact] void should_answer_not_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_answer_the_deployments_one_refusal() => Body.ShouldEqual(UniformDenial.Body);
    [Fact] void should_not_consult_readiness() => _readiness.Consulted.ShouldEqual(0);
    [Fact] void should_not_carry_a_challenge() => _context.Response.Headers.ContainsKey(HeaderNames.WWWAuthenticate).ShouldBeFalse();
    [Fact] void should_not_carry_a_session() => _context.Response.Headers.ContainsKey(HeaderNames.SetCookie).ShouldBeFalse();
}
