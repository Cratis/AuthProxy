// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Ingress;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.SignIns.for_SignInsServiceCollectionExtensions;

/// <summary>
/// Registration is only correct if the container hands the notifier every collaborator it needs. The notifier
/// carries overloaded constructors for its optional collaborators, so convention-based selection silently
/// drops all of them the moment one is unregistered — and a notifier without its signer refuses every
/// notification a signing deployment asks for. Resolving it through the real registrations and posting a real
/// notification is what proves the wiring; a spec on the constructor list alone would not.
/// </summary>
public class when_notifying_through_the_registered_services : Specification
{
    const string NotifyUrl = "https://studio.example.com/api/internal/sign-ins";
    const string KeyId = "sign-in-2026-08";

    RecordingHttpMessageHandler _handler;
    ICanonicalIdentityResolver _canonicalIdentityResolver;
    SignInNotificationResult _result;

    async Task Establish()
    {
        _handler = new RecordingHttpMessageHandler(HttpStatusCode.OK);
        using var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();

        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "subject-123")], "github"));
        _canonicalIdentityResolver = Substitute.For<ICanonicalIdentityResolver>();
        _canonicalIdentityResolver
            .Resolve(Arg.Any<ClaimsPrincipal?>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.SanitizedLegacy(principal));

        var builder = WebApplication.CreateBuilder();
        builder.Services.AddHttpClient(string.Empty).ConfigurePrimaryHttpMessageHandler(() => _handler);
        builder.Services.AddSingleton(_canonicalIdentityResolver);
        builder.Services.Configure<C.AuthProxy>(options =>
        {
            options.SignIn = new C.SignIn
            {
                NotifyUrl = NotifyUrl,
                Attestation = new C.SignInAttestation
                {
                    Issuer = "https://auth.example.com",
                    Audience = "ada",
                    ActiveKeyId = KeyId,
                    Lifetime = TimeSpan.FromSeconds(60),
                    SigningKeys = [new C.SignInAttestationSigningKey { KeyId = KeyId, PrivateKeyPem = privateKeyPem }],
                },
            };
        });
        builder.AddSignIns();

        await using var serviceProvider = builder.Services.BuildServiceProvider();
        var notifier = serviceProvider.GetRequiredService<ISignInNotifier>();

        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.5");
        context.MarkTrustedProxyPeer(true);

        _result = await notifier.Notify(context, principal);
    }

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_authenticate_the_notification() => _handler.LastRequestAuthorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_carry_an_envelope() => _handler.LastRequestAuthorization!.Parameter!.ShouldNotBeEmpty();

    [Fact] void should_consult_the_registered_canonical_identity_resolver() =>
        _canonicalIdentityResolver.Received(1).Resolve(Arg.Any<ClaimsPrincipal?>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>());
}
