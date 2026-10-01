// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_loaded_certificate_has_expired : Specification
{
    X509Certificate2 _expired;
    X509Certificate2 _rotated;
    ICredentialsLoader _loader;
    C.OidcProvider _provider;
    OidcClientAssertions _assertions;
    JsonWebToken _assertion;

    void Establish()
    {
        _expired = ClientCertificates.Rsa(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        _rotated = ClientCertificates.Rsa();
        var loads = new Queue<X509Certificate2>([_expired, _rotated]);

        _loader = Substitute.For<ICredentialsLoader>();
        _loader
            .When(_ => _.LoadCredentialsIfNeededAsync(Arg.Any<CredentialDescription>(), Arg.Any<CredentialSourceLoaderParameters?>()))
            .Do(call =>
            {
                var description = call.Arg<CredentialDescription>();
                description.Certificate ??= loads.Dequeue();
            });
        _loader
            .When(_ => _.ResetCredentials(Arg.Any<IEnumerable<CredentialDescription>>()))
            .Do(call =>
            {
                foreach (var description in call.Arg<IEnumerable<CredentialDescription>>())
                {
                    description.Certificate = null;
                }
            });

        _provider = new()
        {
            Name = "Workforce",
            Authority = "https://login.example.com/tenant/v2.0",
            ClientId = "client-id",
            ClientCredential = new() { Source = C.OidcClientCredentialSource.KeyVaultCertificate }
        };
        _assertions = new(_loader, TimeProvider.System, NullLogger<OidcClientAssertions>.Instance);
    }

    async Task Because() => _assertion = new(await _assertions.Create("workforce", _provider, "https://login.example.com/token", CancellationToken.None));

    void Destroy()
    {
        _expired.Dispose();
        _rotated.Dispose();
    }

    [Fact] void should_sign_with_the_rotated_certificate() => _assertion.X5t.ShouldEqual(Base64UrlEncoder.Encode(_rotated.GetCertHash()));
}
