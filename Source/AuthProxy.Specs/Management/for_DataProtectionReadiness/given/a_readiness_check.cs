// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_DataProtectionReadiness.given;

/// <summary>
/// A readiness check over a real Data Protection stack, whose key persistence a spec chooses.
/// </summary>
/// <remarks>
/// Deliberately the real stack rather than a substituted <see cref="IDataProtectionProvider"/>. What is
/// being specified is that a <c>Protect</c>/<c>Unprotect</c> round-trip forces the key ring to initialize
/// and reports what happened when it does — and a substitute would answer whatever it was told to,
/// including for the failure that matters.
/// <para>
/// The check itself is held in a private-protected field because it is internal, and a protected member of
/// a public class may not be of a less accessible type.
/// </para>
/// </remarks>
public class a_readiness_check : Specification
{
    protected string _keysPath;
    protected ServiceProvider _services;

    private protected DataProtectionReadiness _readiness;

    protected virtual IXmlRepository? KeyStorage => null;

    void Establish()
    {
        _keysPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_keysPath);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection()
            .SetApplicationName("Cratis.AuthProxy.Specs")
            .PersistKeysToFileSystem(new DirectoryInfo(_keysPath));

        var storage = KeyStorage;
        if (storage is not null)
        {
            services.Configure<KeyManagementOptions>(options => options.XmlRepository = storage);
        }

        _services = services.BuildServiceProvider();
        _readiness = new DataProtectionReadiness(
            _services.GetRequiredService<IDataProtectionProvider>(),
            _services.GetRequiredService<ILogger<DataProtectionReadiness>>());
    }

    void Destroy()
    {
        _services.Dispose();

        if (Directory.Exists(_keysPath))
        {
            Directory.Delete(_keysPath, recursive: true);
        }
    }
}
