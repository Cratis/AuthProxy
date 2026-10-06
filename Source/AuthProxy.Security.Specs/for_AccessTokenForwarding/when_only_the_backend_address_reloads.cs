// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NSubstitute;

namespace Cratis.AuthProxy.Security.for_AccessTokenForwarding;

public class when_only_the_backend_address_reloads : IAsyncLifetime
{
    readonly ReloadingHarness _harness = new();
    ForwardedRequest? _before;
    ForwardedRequest? _after;
    int _redemptionsBeforeReload;

    public async Task InitializeAsync()
    {
        using var client = _harness.CreateSecurityClient();
        var store = _harness.Services.GetRequiredService<IUserTokenStore>();
        var session = await store.Create(new("provider-one", "refresh-token"), CancellationToken.None);
        using var before = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/api/before", session));
        before.EnsureSuccessStatusCode();
        using var cached = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/api/before", session));
        cached.EnsureSuccessStatusCode();
        _before = _harness.Backend.LastRequestTo("/api/before");
        _redemptionsBeforeReload = _harness.Endpoint.Redemptions;

        var endpoints = _harness.Services.GetRequiredService<EndpointDataSource>();
        _ = endpoints.Endpoints;
        var reloaded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var changed = endpoints.GetChangeToken().RegisterChangeCallback(_ => reloaded.TrySetResult(), null);
        var config = (IConfigurationRoot)_harness.Services.GetRequiredService<IConfiguration>();
        config[$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:BaseUrl"] = _harness.Frontend.BaseUrl;
        config.Reload();
        await reloaded.Task.WaitAsync(TimeSpan.FromSeconds(10));

        using var after = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/api/after", session));
        after.EnsureSuccessStatusCode();
        _after = _harness.Frontend.LastRequestTo("/api/after");
    }

    public Task DisposeAsync() => _harness.DisposeAsync().AsTask();

    [Fact] public void should_reuse_the_cached_token_before_reload() => Assert.Equal(1, _redemptionsBeforeReload);
    [Fact] public void should_forward_the_original_token_only_to_the_original_backend() => Assert.Equal("Bearer redemption-1", _before!.Value("Authorization"));
    [Fact] public void should_obtain_a_new_token_for_the_same_session_and_audience() => Assert.Equal(2, _harness.Endpoint.Redemptions);
    [Fact] public void should_forward_the_new_token_to_the_new_backend() => Assert.Equal("Bearer redemption-2", _after!.Value("Authorization"));
    [Fact] public void should_not_send_the_new_request_to_the_old_backend() => Assert.False(_harness.Backend.ReceivedAnythingFor("/api/after"));

    sealed class ReloadingHarness : AccessTokenForwardingHarness
    {
        public TokenEndpoint Endpoint { get; } = new();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services => services.AddSingleton<IUserAccessTokens>(provider =>
            {
                var options = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();
                options.Get("provider-one").Returns(new OpenIdConnectOptions
                {
                    ClientId = "client-one",
                    ClientSecret = "client-secret",
                    Configuration = new OpenIdConnectConfiguration { TokenEndpoint = "https://login.example.test/token" },
                });
                var clients = Substitute.For<IHttpClientFactory>();
                clients.CreateClient(UserAccessTokens.HttpClientName).Returns(_ => new HttpClient(Endpoint, disposeHandler: false));
                return new UserAccessTokens(provider.GetRequiredService<IUserTokenStore>(), options, provider.GetRequiredService<IOptionsMonitor<C.Authentication>>(), Substitute.For<IOidcClientAssertions>(), clients, TimeProvider.System, provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<UserAccessTokens>>());
            }));
        }
    }

    sealed class TokenEndpoint : HttpMessageHandler
    {
        public int Redemptions { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Redemptions++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"access_token":"redemption-{{Redemptions}}","token_type":"Bearer","expires_in":3600}""", System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
