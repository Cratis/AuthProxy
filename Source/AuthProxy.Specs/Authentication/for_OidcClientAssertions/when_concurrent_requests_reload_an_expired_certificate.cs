// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_concurrent_requests_reload_an_expired_certificate : Specification
{
    readonly TaskCompletionSource _reloading = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly TaskCompletionSource _allowReload = new(TaskCreationOptions.RunContinuationsAsynchronously);
    X509Certificate2 _expired;
    X509Certificate2 _rotated;
    ICredentialsLoader _loader;
    OidcClientAssertions _assertions;
    C.OidcProvider _provider;
    string[] _tokens;
    bool _secondRequestWaited;

    void Establish()
    {
        _expired = ClientCertificates.Rsa(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        _rotated = ClientCertificates.Rsa();
        var loads = 0;
        _loader = Substitute.For<ICredentialsLoader>();
        _loader.LoadCredentialsIfNeededAsync(Arg.Any<CredentialDescription>(), Arg.Any<CredentialSourceLoaderParameters?>())
            .Returns(async call =>
            {
                var description = call.Arg<CredentialDescription>();
                var load = Interlocked.Increment(ref loads);
                if (load == 1)
                {
                    description.Certificate = _expired;
                    return;
                }

                if (load == 2)
                {
                    _reloading.SetResult();
                    await _allowReload.Task;
                }

                description.Certificate = _rotated;
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

    async Task Because()
    {
        var first = _assertions.Create("workforce", _provider, "https://login.example.com/token", CancellationToken.None);
        await _reloading.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = _assertions.Create("workforce", _provider, "https://login.example.com/token", CancellationToken.None);
        _secondRequestWaited = !second.IsCompleted;
        _allowReload.SetResult();
        _tokens = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(5));
    }

    void Destroy()
    {
        _expired.Dispose();
        _rotated.Dispose();
    }

    [Fact] void should_wait_for_the_in_progress_reload() => _secondRequestWaited.ShouldBeTrue();
    [Fact] void should_sign_both_requests_with_the_replacement() => _tokens.Select(_ => new JsonWebToken(_).X5t).ShouldEqual([Base64UrlEncoder.Encode(_rotated.GetCertHash()), Base64UrlEncoder.Encode(_rotated.GetCertHash())]);
    [Fact] void should_dispose_the_replaced_certificate() => Catch.Exception(() => _expired.GetCertHash()).ShouldBeOfExactType<CryptographicException>();
    [Fact] void should_reset_the_credential_only_once() => _loader.Received(1).ResetCredentials(Arg.Any<IEnumerable<CredentialDescription>>());
}
