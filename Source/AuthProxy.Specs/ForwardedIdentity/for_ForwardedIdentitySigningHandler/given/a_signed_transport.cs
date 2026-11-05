// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler.given;

public class a_signed_transport : Specification
{
    protected HttpRequestMessage request;
    protected C.ForwardedIdentitySigning settings;
    protected HttpMessageInvoker invoker;
    protected RecordingTransport transport;
    protected Exception exception;
    protected string proof;

    void Establish()
    {
        settings = new() { Audience = "backend", KeyId = "key-1", SecretBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)42, 32).ToArray()) };
        request = new(HttpMethod.Post, "https://backend.example/base/a%2fb?x=1");
        request.Headers.Add(Headers.Principal, "principal");
        request.Headers.Add(Headers.PrincipalId, "user");
        request.Headers.Add(Headers.PrincipalName, "name");
        transport = new();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = settings } } });
        invoker = new(new ForwardedIdentitySigningHandler(new ForwardedIdentitySigner(monitor, new FixedClock(), NullLogger<ForwardedIdentitySigner>.Instance), NullLogger<ForwardedIdentitySigningHandler>.Instance) { InnerHandler = transport });
    }

    protected async Task Send(bool configured = true)
    {
        try
        {
            request.Options.Set(ForwardedIdentitySigningTarget.OptionsKey, new(ForwardedIdentityFlow.ProxiedRequest, configured ? "app" : "unconfigured"));
            using var response = await invoker.SendAsync(request, CancellationToken.None);
            proof = request.Headers.TryGetValues(Headers.ForwardedIdentitySignature, out var values) ? values.Single() : null;
        }
        catch (Exception error)
        {
            exception = error;
        }
    }

    void Destroy()
    {
        request.Dispose();
        invoker.Dispose();
    }

    protected class RecordingTransport : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(1700000000);
    }
}
