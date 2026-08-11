// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints;

/// <summary>
/// Liveness answers that the request loop is servicing requests, and consults nothing to do it.
/// <para>
/// Not even readiness. An orchestrator restarts a container that fails its liveness probe, so a liveness
/// answer that depended on storage, an identity provider or a backend would turn somebody else's outage
/// into a restart loop of the one component that was still working.
/// </para>
/// </summary>
public class when_answering_liveness : given.a_management_endpoint
{
    async Task Because() => await _endpoints.Answer(_context, ManagementDisposition.Live);

    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_not_consult_readiness() => _readiness.Consulted.ShouldEqual(0);
    [Fact] void should_answer_a_bounded_body() => Body.ShouldEqual(ManagementEndpoints.LiveBody);
    [Fact] void should_not_carry_a_challenge() => _context.Response.Headers.ContainsKey(HeaderNames.WWWAuthenticate).ShouldBeFalse();
    [Fact] void should_not_carry_a_session() => _context.Response.Headers.ContainsKey(HeaderNames.SetCookie).ShouldBeFalse();
    [Fact] void should_not_be_cached() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
}
