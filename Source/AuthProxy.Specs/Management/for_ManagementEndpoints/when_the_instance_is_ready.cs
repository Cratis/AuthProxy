// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints;

/// <summary>
/// A ready instance answers <c>200</c>, having asked the readiness check for the answer.
/// </summary>
public class when_the_instance_is_ready : given.a_management_endpoint
{
    async Task Because() => await _endpoints.Answer(_context, ManagementDisposition.Ready);

    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_have_consulted_readiness() => _readiness.Consulted.ShouldEqual(1);
    [Fact] void should_answer_a_bounded_body() => Body.ShouldEqual(ManagementEndpoints.ReadyBody);
}
