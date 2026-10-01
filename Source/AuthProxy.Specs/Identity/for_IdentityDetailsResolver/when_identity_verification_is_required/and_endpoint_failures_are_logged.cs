// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_endpoint_failures_are_logged : given.a_required_verification_resolver
{
    readonly List<int> _warningCounts = [];
    readonly List<bool> _authorized = [];

    async Task Because()
    {
        Func<HttpRequestMessage, int, CancellationToken, Task<HttpResponseMessage>>[] failures =
        [
            (_, _, _) => Task.FromResult(Response(HttpStatusCode.NotFound)),
            (_, _, _) => Task.FromResult(Response(HttpStatusCode.InternalServerError)),
            (_, _, _) => Task.FromResult(Response(HttpStatusCode.OK, "not-json")),
            (_, _, _) => throw new HttpRequestException("connection refused")
        ];

        for (var index = 0; index < failures.Length; index++)
        {
            _handler.Respond = failures[index];
            var warningsBefore = _logger.Levels.Count(_ => _ == LogLevel.Warning);
            var result = await _resolver.Resolve(new DefaultHttpContext(), Principal($"user-{index}"), TenantId);
            _authorized.Add(result.IsAuthorized);
            _warningCounts.Add(_logger.Levels.Count(_ => _ == LogLevel.Warning) - warningsBefore);
        }
    }

    [Fact] void should_warn_exactly_once_for_each_failure() => _warningCounts.ShouldContainOnly([1, 1, 1, 1]);
    [Fact] void should_not_log_an_error_for_any_failure() => _logger.Levels.ShouldNotContain(LogLevel.Error);
    [Fact] void should_deny_each_unverified_caller() => _authorized.ShouldContainOnly([false, false, false, false]);
    [Fact] void should_include_the_opt_out_in_the_warning() => _logger.Text.ShouldContain("Cratis__AuthProxy__Services__main__IdentityVerification=BestEffort");
}
