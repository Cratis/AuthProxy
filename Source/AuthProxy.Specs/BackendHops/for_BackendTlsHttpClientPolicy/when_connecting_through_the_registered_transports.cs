// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_connecting_through_the_registered_transports
{
    [Theory]
    [InlineData("default", true)]
    [InlineData("signed", true)]
    [InlineData("yarp", true)]
    [InlineData("sticky", true)]
    [InlineData("default", false)]
    [InlineData("signed", false)]
    [InlineData("yarp", false)]
    public async Task should_authenticate_both_ends_of_the_backend_hop(string transport, bool trusted)
    {
        using var certificates = new given.TestCertificates();
        using var other = new given.TestCertificates();
        using var server = trusted ? certificates.Issue() : other.Issue();
        var originBuilder = WebApplication.CreateSlimBuilder();
        originBuilder.Logging.ClearProviders();
        originBuilder.WebHost.UseKestrelHttpsConfiguration();
        originBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(new HttpsConnectionAdapterOptions
        {
            ServerCertificate = server,
            ClientCertificateMode = ClientCertificateMode.AllowCertificate,
            ClientCertificateValidation = (_, _, _) => true
        })));
        await using var origin = originBuilder.Build();
        origin.Run(context =>
        {
            context.Response.Headers["X-Spec-Connection"] = context.Connection.Id;
            return context.Response.WriteAsync(context.Connection.ClientCertificate?.GetCertHashString(HashAlgorithmName.SHA256) ?? "missing client certificate");
        });
        await origin.StartAsync(TestContext.Current.CancellationToken);
        var address = origin.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        var uri = new Uri(address.Replace("127.0.0.1", "localhost", StringComparison.Ordinal));

        var builder = WebApplication.CreateBuilder();
        builder.AddIngressConfiguration();
        builder.AddForwardedIdentitySigning();
        builder.Services.Configure<C.AuthProxy>(options =>
        {
            options.BackendTls = certificates.Settings;
            options.BackendTls.ReloadInterval = C.BackendTls.MinimumReloadInterval;
            options.Services["app"] = new() { Backend = new() { BaseUrl = uri.ToString() }, IdentityVerification = C.IdentityVerificationMode.BestEffort };
        });
        await using var services = builder.Services.BuildServiceProvider();
        HttpMessageInvoker client;
        if (transport == "yarp" || transport == "sticky")
        {
            var factory = new SigningForwarderHttpClientFactory(NullLogger<ForwarderHttpClientFactory>.Instance, Substitute.For<IForwardedIdentitySigner>(), services.GetRequiredService<BackendTlsHttpClientPolicy>());
            client = factory.CreateClient(new ForwarderHttpClientContext { NewConfig = new HttpClientConfig { DangerousAcceptAnyServerCertificate = true } });
        }
        else
        {
            client = services.GetRequiredService<IHttpClientFactory>().CreateClient(transport == "signed" ? ForwardedIdentityServiceCollectionExtensions.HttpClientName : string.Empty);
        }
        using (client)
        using (var request = new HttpRequestMessage(HttpMethod.Get, transport == "sticky" ? address : uri.ToString()))
        {
            if (transport == "sticky") request.Headers.Host = uri.Authority;
            if (trusted)
            {
                using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
                response.EnsureSuccessStatusCode();
                using var leaf = X509Certificate2.CreateFromPemFile(certificates.CertificatePath, certificates.KeyPath);
                (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldEqual(leaf.GetCertHashString(HashAlgorithmName.SHA256));
                await AssertNewConnectionUsesRotatedCertificate(client, response, certificates, services);
            }
            else
            {
                await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(request, TestContext.Current.CancellationToken));
            }
        }
        await origin.StopAsync(TestContext.Current.CancellationToken);
    }

    static async Task AssertNewConnectionUsesRotatedCertificate(HttpMessageInvoker client, HttpResponseMessage response, given.TestCertificates certificates, IServiceProvider services)
    {
        using var replacement = certificates.Issue(client: true);
        certificates.WriteClient(replacement);
        services.GetRequiredService<IBackendTlsMaterialSource>().TryReload().ShouldBeTrue();
        await Task.Delay(C.BackendTls.MinimumReloadInterval + TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.NotNull(response.RequestMessage);
        using var rotated = new HttpRequestMessage(HttpMethod.Get, response.RequestMessage.RequestUri);
        rotated.Headers.Host = response.RequestMessage.Headers.Host;
        using var rotatedResponse = await client.SendAsync(rotated, TestContext.Current.CancellationToken);
        rotatedResponse.EnsureSuccessStatusCode();
        rotatedResponse.Headers.GetValues("X-Spec-Connection").Single().ShouldNotEqual(response.Headers.GetValues("X-Spec-Connection").Single());
        (await rotatedResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldEqual(replacement.GetCertHashString(HashAlgorithmName.SHA256));
    }
}
