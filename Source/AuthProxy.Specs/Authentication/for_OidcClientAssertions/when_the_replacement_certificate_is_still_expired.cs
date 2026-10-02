// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_replacement_certificate_is_still_expired : Specification
{
    X509Certificate2 _expired;
    X509Certificate2 _replacement;
    ICredentialsLoader _loader;
    OidcClientAssertions _assertions;
    C.OidcProvider _provider;
    Exception[] _failures;

    void Establish()
    {
        _expired = ClientCertificates.Rsa(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        _replacement = ClientCertificates.Rsa(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        var loads = new Queue<X509Certificate2>([_expired, _replacement]);
        _loader = Substitute.For<ICredentialsLoader>();
        _loader.LoadCredentialsIfNeededAsync(Arg.Any<CredentialDescription>(), Arg.Any<CredentialSourceLoaderParameters?>())
            .Returns(call =>
            {
                var description = call.Arg<CredentialDescription>();
                description.Certificate ??= loads.Dequeue();
                return Task.CompletedTask;
            });
        _loader.When(_ => _.ResetCredentials(Arg.Any<IEnumerable<CredentialDescription>>()))
            .Do(call => call.Arg<IEnumerable<CredentialDescription>>().Single().Certificate = null);
        _provider = new()
        {
            Name = "Workforce",
            ClientId = "client-id",
            Authority = "https://login.example.com/tenant",
            ClientCredential = new() { Source = C.OidcClientCredentialSource.CertificateFile }
        };
        _assertions = new(_loader, TimeProvider.System, NullLogger<OidcClientAssertions>.Instance);
    }

    async Task Because() => _failures =
    [
        await Catch.Exception(() => _assertions.Create("workforce", _provider, "https://login.example.com/token", CancellationToken.None)),
        await Catch.Exception(() => _assertions.Create("workforce", _provider, "https://login.example.com/token", CancellationToken.None))
    ];

    void Destroy()
    {
        _expired.Dispose();
        _replacement.Dispose();
    }

    [Fact] void should_fail_instead_of_signing_with_an_expired_certificate() => _failures.All(_ => _ is OidcClientCredentialUnavailable).ShouldBeTrue();
    [Fact] void should_not_reload_on_every_request() => _loader.Received(1).ResetCredentials(Arg.Any<IEnumerable<CredentialDescription>>());
}
