// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_a_request_exhausts_the_queue_budget_for_several_services : given.a_required_verification_resolver
{
    readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    IdentityProviderResult _result;
    int _warningCount;
    string _logs;

    void Establish()
    {
        _service.IdentityVerificationTimeout = TimeSpan.FromMilliseconds(30);
        _config.Services["second"] = new C.Service
        {
            Backend = _service.Backend,
            IdentityVerificationTimeout = TimeSpan.FromMilliseconds(30)
        };

        // Hold the endpoint on a signal to observe a request waiting behind it, not on a sleep.
        _handler.Respond = async (_, _, _) =>
        {
            _entered.TrySetResult();
            await _release.Task;
            return Response(HttpStatusCode.OK, PositiveBody);
        };
    }

    async Task Because()
    {
        var first = _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
        try
        {
            await _entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            _result = await _resolver.Resolve(_context, Principal(), TenantId);
            _warningCount = _logger.Levels.Count(_ => _ == LogLevel.Warning);
            _logs = _logger.Text;
        }
        finally
        {
            _release.TrySetResult();
            await first;
        }
    }

    [Fact] void should_deny_the_waiting_request() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_warn_only_once() => _warningCount.ShouldEqual(1);
    [Fact] void should_include_the_first_service_opt_out() => _logs.ShouldContain("Cratis__AuthProxy__Services__main__IdentityVerification=BestEffort");
    [Fact] void should_include_the_second_service_opt_out() => _logs.ShouldContain("Cratis__AuthProxy__Services__second__IdentityVerification=BestEffort");
}
