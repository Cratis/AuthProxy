// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A production-profile signed deployment with real HTTPS backend connections.</summary>
/// <param name="certificates">The mounted credentials and trust bundle.</param>
/// <param name="tls">The backend server's TLS settings, or null for HTTP.</param>
/// <param name="local">Whether to explicitly permit reduced local transport.</param>
/// <param name="client">Whether to configure client credentials.</param>
public class BackendTlsHarness(HopCertificates certificates, RecordingBackendTls? tls, bool local = false, bool client = true) : ForwardedIdentityHarness(tls)
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string root = C.AuthProxy.SectionKey;
        settings[$"{root}:Profile"] = local ? nameof(C.DeploymentProfile.LocalDevelopment) : nameof(C.DeploymentProfile.Default);
        settings[$"{root}:BackendTls:TrustedCertificateAuthoritiesPath"] = certificates.BundlePath;
        if (client)
        {
            settings[$"{root}:BackendTls:ClientCertificate:CertificatePath"] = certificates.CertificatePath;
            settings[$"{root}:BackendTls:ClientCertificate:KeyPath"] = certificates.KeyPath;
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        base.ConfigureHost(builder);
    }
}
