// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.given;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_signing_is_enabled_after_an_http_callback_is_queued : Specification
{
    SignInCallbackSender _sender;
    SignInCallbackQueue _queue;
    IHttpClientFactory _factory;
    RespondingHttpMessageHandler _handler;
    ServiceProvider _provider;
    bool _queued;
    bool _delivered;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy());
        _queue = new();
        _queued = _queue.TryEnqueue(new("app", "http://callback.example/notify", TimeSpan.FromSeconds(2), string.Empty, SignInCallbackKind.SignedIn, new ClientPrincipal { UserId = "spec-user", UserDetails = "Spec User" }, "spec-tenant", DateTimeOffset.UtcNow));
        _handler = new(HttpStatusCode.NoContent);
        _factory = _handler.AsFactory();
        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton(_factory);
        services.AddSingleton<IForwardedIdentitySigner>(new ForwardedIdentitySigner(options, TimeProvider.System, NullLogger<ForwardedIdentitySigner>.Instance));
        services.AddSingleton<ILogger<SignInCallbackSender>>(new RecordingLogger<SignInCallbackSender>());
        services.AddTransient<SignInCallbackSender>();
        _provider = services.BuildServiceProvider();
        _sender = _provider.GetRequiredService<SignInCallbackSender>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = "https://callback.example" }, ForwardedIdentity = new() { Audience = "callback", KeyId = "spec-key", SecretBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)42, 32).ToArray()) } }
            }
        });
    }

    async Task Because()
    {
        await using var messages = _queue.ReadAll(CancellationToken.None).GetAsyncEnumerator();
        await messages.MoveNextAsync();
        _delivered = await _sender.Send(messages.Current, CancellationToken.None);
    }

    [Fact] void should_have_queued_the_callback() => _queued.ShouldBeTrue();
    [Fact] void should_not_deliver_the_old_http_destination() => _delivered.ShouldBeFalse();
    [Fact] void should_not_create_a_client() => _factory.DidNotReceive().CreateClient(Arg.Any<string>());
    [Fact] void should_not_send_the_request() => _handler.Calls.ShouldEqual(0);

    void Destroy()
    {
        _provider.Dispose();
        _handler.Dispose();
    }
}
