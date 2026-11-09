// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.SignInCallbacks;
using Cratis.AuthProxy.SignInCallbacks.given;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_retrying_queued_browser_snapshots : Specification
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_stop_sending_at_the_original_snapshot_deadline_without_renewing_it_on_retry(bool signedIn)
    {
        using var fixture = new BrowserSessionFixture();
        var service = new C.Service
        {
            Backend = new() { BaseUrl = "https://backend.example/" },
            SignInCallback = new() { Path = "/callback" },
            ForwardedIdentity = fixture.Settings
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = service } });
        var time = new ManualTimeProvider();
        var queue = new RecordingCallbackQueue();
        var dispatcher = new SignInCallbackDispatcher(monitor, queue, fixture.Context.RequestServices, time, NullLogger<SignInCallbackDispatcher>.Instance);
        if (signedIn) dispatcher.SignedIn(fixture.Context, fixture.Principal, BrowserSessionFixture.Scheme, fixture.Properties);
        else dispatcher.Returned(fixture.Context, "app", service, fixture.Context.BuildClientPrincipal()!, "tenant-one");
        var callback = Assert.Single(queue.Requests);
        Assert.Equal(time.GetUtcNow().AddSeconds(60), callback.TrustedContext!.SnapshotExpiresUtc);
        fixture.Accessor.HttpContext = null;
        using var signer = new ForwardedIdentitySigner(monitor, time, NullLogger<ForwardedIdentitySigner>.Instance, fixture.Accessor);
        using var handler = new RefusingBackend();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler, disposeHandler: false));
        var sender = new SignInCallbackSender(factory, signer, monitor, NullLogger<SignInCallbackSender>.Instance);
        Assert.False(await sender.Send(callback, CancellationToken.None));
        time.Advance(TimeSpan.FromSeconds(59));
        Assert.False(await sender.Send(callback, CancellationToken.None));
        Assert.Equal(2, handler.Proofs.Count);
        Assert.NotEqual(handler.Proofs[0], handler.Proofs[1]);
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.False(await sender.Send(callback, CancellationToken.None));
        Assert.Equal(2, handler.Proofs.Count);
    }

    sealed class RefusingBackend : HttpMessageHandler
    {
        internal List<string> Proofs { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Proofs.Add(request.Headers.GetValues(Headers.ForwardedIdentitySignature).Single());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        }
    }
}
