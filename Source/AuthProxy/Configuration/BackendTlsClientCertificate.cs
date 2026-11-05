// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Identifies PEM files containing the client identity presented to backends.
/// </summary>
public class BackendTlsClientCertificate
{
    /// <summary>
    /// Gets or sets the certificate file path. The first certificate is the leaf.
    /// </summary>
    public string CertificatePath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the unencrypted PEM private-key file path.
    /// </summary>
    public string KeyPath { get; set; } = string.Empty;
}
