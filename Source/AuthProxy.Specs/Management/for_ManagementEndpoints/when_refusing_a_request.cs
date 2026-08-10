// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints;

/// <summary>
/// Everything the management listener does not own gets the same empty not-found — the same answer whether
/// the request was a management path on the public listener or an application path on the management one.
/// <para>
/// Uniform on purpose. A refusal that varied by reason would let a caller map which paths exist on which
/// listener without ever being allowed to use one, and a refusal carrying a challenge would invite a
/// caller to authenticate against a surface that has no notion of identity at all.
/// </para>
/// </summary>
public class when_refusing_a_request : given.a_management_endpoint
{
    async Task Because() => await _endpoints.Answer(_context, ManagementDisposition.Refuse);

    [Fact] void should_answer_not_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_answer_an_empty_body() => Body.ShouldBeEmpty();
    [Fact] void should_not_consult_readiness() => _readiness.Consulted.ShouldEqual(0);
    [Fact] void should_not_carry_a_challenge() => _context.Response.Headers.ContainsKey(HeaderNames.WWWAuthenticate).ShouldBeFalse();
    [Fact] void should_not_carry_a_session() => _context.Response.Headers.ContainsKey(HeaderNames.SetCookie).ShouldBeFalse();
}
