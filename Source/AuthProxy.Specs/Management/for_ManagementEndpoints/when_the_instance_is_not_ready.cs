// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints;

/// <summary>
/// An instance that cannot serve traffic answers <c>503</c> — and says no more about it than a ready one
/// does.
/// <para>
/// The reason is the interesting part to an attacker and useless to a probe: it names a filesystem path, a
/// key identifier or an exception type, all of which describe the deployment to whoever can reach the port.
/// It belongs in the log, where an operator reads it and a caller does not.
/// </para>
/// </summary>
public class when_the_instance_is_not_ready : given.a_management_endpoint
{
    protected override bool IsReady => false;

    async Task Because() => await _endpoints.Answer(_context, ManagementDisposition.Ready);

    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_answer_a_bounded_body() => Body.ShouldEqual(ManagementEndpoints.NotReadyBody);
    [Fact] void should_not_name_a_filesystem_path() => Body.ShouldNotContain("/");
    [Fact] void should_not_disclose_an_exception_type() => Body.Contains("Exception", StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_disclose_a_stack_frame() => Body.Contains("at Cratis.AuthProxy.", StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_disclose_a_stack_trace() => Body.Contains("StackTrace", StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_disclose_a_source_file_and_line() => Body.Contains(".cs:line ", StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_name_the_product() => Body.Contains("AuthProxy", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
    [Fact] void should_not_carry_a_challenge() => _context.Response.Headers.ContainsKey(HeaderNames.WWWAuthenticate).ShouldBeFalse();
    [Fact] void should_not_carry_a_session() => _context.Response.Headers.ContainsKey(HeaderNames.SetCookie).ShouldBeFalse();
}
