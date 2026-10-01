// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_browser_cancels_a_rotating_refresh : given.user_access_tokens
{
    Exception? _error;
    UserTokenSession? _session;
    UserAccessTokenResult _next;

    async Task Because()
    {
        var issued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliver = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _endpoint.AnswerAsync = async token =>
        {
            issued.SetResult();
            await deliver.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, token);
            return TokenEndpoint.Bearer("rotated-access-token", 3600, "rotated-refresh-token");
        };
        using var browser = new CancellationTokenSource();
        var request = _tokens.GetFor(_sessionId, _accessToken, browser.Token);
        await issued.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        await browser.CancelAsync();
        _error = await Catch.Exception(async () => await request);
        deliver.SetResult();
        _next = await Get().WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _session = await _store.Get(_sessionId, CancellationToken.None);
    }

    [Fact] void should_let_the_browser_stop_waiting() => (_error is OperationCanceledException).ShouldBeTrue();
    [Fact] void should_persist_the_rotated_refresh_token() => _session!.RefreshToken.ShouldEqual("rotated-refresh-token");
    [Fact] void should_cache_the_completed_access_token() => _next.Token.ShouldEqual("rotated-access-token");
    [Fact] void should_not_redeem_the_obsolete_refresh_token_again() => _endpoint.Received.Count.ShouldEqual(1);
}
