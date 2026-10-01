// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_the_caller_disconnects_during_the_call : given.a_required_verification_resolver
{
    readonly List<bool> _authorized = [];

    async Task Because()
    {
        foreach (var mode in new[] { C.IdentityVerificationMode.Required, C.IdentityVerificationMode.BestEffort })
        {
            using var cancellation = new CancellationTokenSource();
            _service.IdentityVerification = mode;
            var context = new DefaultHttpContext { RequestAborted = cancellation.Token };
            _handler.Respond = async (_, _, token) =>
            {
                // Cancel only after SendAsync has started, not while waiting for the resolver lock.
                await cancellation.CancelAsync();
                return await Task.FromCanceled<HttpResponseMessage>(token);
            };
            var result = await _resolver.Resolve(context, Principal($"user-{mode}"), TenantId);
            _authorized.Add(result.IsAuthorized);
        }
    }

    [Fact] void should_have_started_both_calls() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_deny_only_under_required() => _authorized.ShouldContainOnly([false, true]);
    [Fact] void should_not_warn_for_a_client_disconnect_in_either_mode() => _logger.Levels.ShouldNotContain(LogLevel.Warning);
    [Fact] void should_not_log_an_error_for_a_client_disconnect_in_either_mode() => _logger.Levels.ShouldNotContain(LogLevel.Error);
    [Fact] void should_explain_the_required_denial_at_debug_level() => _logger.Text.ShouldContain(nameof(IdentityVerificationReason.Canceled));
    [Fact] void should_not_advise_changing_verification() => _logger.Text.ShouldNotContain("IdentityVerification=BestEffort");
}
