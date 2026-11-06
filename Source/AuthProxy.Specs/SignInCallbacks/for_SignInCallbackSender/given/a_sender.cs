// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.given;
using Cratis.AuthProxy.SignIns;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender.given;

/// <summary>
/// Provides a sender whose HTTP transport records the request it is asked to make.
/// </summary>
public class a_sender : Specification
{
    protected const string Url = "http://app.internal:8080/.cratis/showrunner/sign-in";

    protected RecordingHttpMessageHandler _handler;
    protected SignInCallbackSender _sender;
    protected IHttpClientFactory _factory;
    protected IForwardedIdentitySigner _signer;
    protected RecordingLogger<SignInCallbackSender> _deliveryLogger;

    protected virtual ForwardedIdentitySigningOutcome SigningOutcome => ForwardedIdentitySigningOutcome.NotConfigured;
    protected bool _delivered;
    protected DateTimeOffset _occurred = new(2026, 11, 3, 9, 0, 0, TimeSpan.Zero);

    protected virtual HttpMessageHandler CreateHandler() => _handler = new RecordingHttpMessageHandler(HttpStatusCode.OK);

    protected virtual string? Tenant => "tenant-a";

    protected virtual string Secret => "s3cret";

    protected virtual TimeSpan Timeout => TimeSpan.FromSeconds(5);

    protected SignInCallbackRequest CreateRequest(SignInCallbackKind kind = SignInCallbackKind.SignedIn) =>
        new(
            "app",
            Url,
            Timeout,
            Secret,
            kind,
            new ClientPrincipal
            {
                IdentityProvider = "github",
                UserId = "user-1",
                UserDetails = "user.one@example.com",
                Claims =
                [
                    new ClientPrincipalClaim { Type = "name", Value = "User One" },
                    new ClientPrincipalClaim { Type = "email", Value = "user.one@example.com" }
                ]
            },
            Tenant,
            _occurred);

    protected string Header(string name) => _handler.LastRequest!.Headers.GetValues(name).Single();

    void Establish()
    {
        _factory = Substitute.For<IHttpClientFactory>();
        var handler = CreateHandler();
        _factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler, false));
        _signer = Substitute.For<IForwardedIdentitySigner>();
        _signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<ForwardedIdentitySigningTarget>()).Returns(_ => SigningOutcome);
        _deliveryLogger = new RecordingLogger<SignInCallbackSender>();
        _sender = new SignInCallbackSender(_factory, _signer, _deliveryLogger);
    }
}
