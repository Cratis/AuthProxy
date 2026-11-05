// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A real TLS origin that requests client authentication during the handshake.</summary>
/// <param name="ServerCertificate">The server certificate including its private key.</param>
/// <param name="CloseConnections">Whether every response closes the connection for deterministic rotation checks.</param>
public sealed record RecordingBackendTls(X509Certificate2 ServerCertificate, bool CloseConnections = true)
{
    /// <summary>Configures the loopback HTTPS listener.</summary>
    /// <param name="builder">The origin's web host.</param>
    public void Configure(IWebHostBuilder builder)
    {
        builder.UseKestrelHttpsConfiguration();
        builder.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(new HttpsConnectionAdapterOptions
        {
            ServerCertificate = ServerCertificate,
            ClientCertificateMode = ClientCertificateMode.AllowCertificate,

            // This recording origin measures what the proxy sends, not backend authorization policy.
            ClientCertificateValidation = (_, _, _) => true
        })));
    }
}
