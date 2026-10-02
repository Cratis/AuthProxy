// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_AccessTokenForwarding;

/// <summary>
/// A token awaited for the old backend must never be forwarded to a newly configured origin.
/// </summary>
public class when_the_backend_changes_during_token_acquisition : IAsyncLifetime
{
    readonly ReloadingHarness _harness = new();
    HttpClient? _client;
    HttpRequestMessage? _oldRequest;
    Task<HttpResponseMessage>? _inFlight;
    ForwardedRequest? _oldBackendRequest;
    ForwardedRequest? _newBackendRequest;

    public async Task InitializeAsync()
    {
        _client = _harness.CreateSecurityClient();
        _client.Timeout = TimeSpan.FromSeconds(20);
        _oldRequest = AccessTokenForwardingHarness.FromSession("/api/old", "blocked-session");
        _inFlight = _client.SendAsync(_oldRequest);
        await _harness.Tokens.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var endpoints = _harness.Services.GetRequiredService<EndpointDataSource>();
        _ = endpoints.Endpoints;
        var reloaded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var changed = endpoints.GetChangeToken().RegisterChangeCallback(_ => reloaded.TrySetResult(), null);
        var config = (IConfigurationRoot)_harness.Services.GetRequiredService<IConfiguration>();
        config[$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:BaseUrl"] = _harness.Frontend.BaseUrl;
        config[$"{C.AuthProxy.SectionKey}:Services:reporting:AccessToken:Scopes:0"] = "api://new-backend/access_as_user";
        config.Reload();
        await reloaded.Task.WaitAsync(TimeSpan.FromSeconds(10));

        using var newRequest = AccessTokenForwardingHarness.FromSession("/api/new", "new-session");
        using var newResponse = await _client.SendAsync(newRequest);
        newResponse.EnsureSuccessStatusCode();
        _harness.Tokens.Resume.TrySetResult();
        using var oldResponse = await _inFlight;
        oldResponse.EnsureSuccessStatusCode();

        _oldBackendRequest = _harness.Backend.LastRequestTo("/api/old");
        _newBackendRequest = _harness.Frontend.LastRequestTo("/api/new");
    }

    public async Task DisposeAsync()
    {
        _harness.Tokens.Resume.TrySetResult();
        try
        {
            if (_inFlight is not null)
            {
                using var response = await _inFlight;
            }
        }
        finally
        {
            _oldRequest?.Dispose();
            _client?.Dispose();
            await _harness.DisposeAsync();
        }
    }

    [Fact]
    public void should_send_the_old_token_only_to_the_old_backend() =>
        Assert.Equal("Bearer token-for-api://reporting/access_as_user", _oldBackendRequest!.Value("Authorization"));

    [Fact]
    public void should_send_the_new_audiences_token_to_the_new_backend() =>
        Assert.Equal("Bearer token-for-api://new-backend/access_as_user", _newBackendRequest!.Value("Authorization"));

    [Fact]
    public void should_never_send_the_in_flight_request_to_the_new_backend() =>
        Assert.False(_harness.Frontend.ReceivedAnythingFor("/api/old"));

    sealed class ReloadingHarness : AccessTokenForwardingHarness
    {
        public BlockingTokens Tokens { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services => services.AddSingleton<IUserAccessTokens>(Tokens));
        }
    }

    sealed class BlockingTokens : IUserAccessTokens
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<UserAccessTokenResult> GetFor(string sessionId, C.ServiceAccessToken accessToken, CancellationToken cancellationToken)
        {
            if (sessionId == "blocked-session")
            {
                Started.TrySetResult();
                await Resume.Task.WaitAsync(cancellationToken);
            }

            return UserAccessTokenResult.Success($"token-for-{accessToken.Scopes.Single()}");
        }
    }
}
