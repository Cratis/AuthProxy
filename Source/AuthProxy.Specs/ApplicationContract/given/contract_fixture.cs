// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.ApplicationContract.given;

/// <summary>
/// Loads the shared contract fixture in either of its forms, with the one secret it leaves out supplied
/// through a secrets directory.
/// </summary>
public class contract_fixture : Specification
{
    protected const string PrivateKeyName = "onboarding.attestation.privateKeyPem";

    protected string _secrets;
    protected Dictionary<string, string?> _overrides;

    void Establish()
    {
        _secrets = Path.Combine(Path.GetTempPath(), $"authproxy-contract-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_secrets);
        using var rsa = RSA.Create(2048);
        File.WriteAllText(Path.Combine(_secrets, PrivateKeyName), rsa.ExportPkcs8PrivateKeyPem() + "\n");
        _overrides = new(StringComparer.OrdinalIgnoreCase)
        {
            [ApplicationContractKeys.SecretsDirectoryKey] = _secrets
        };
    }

    void Destroy() => Directory.Delete(_secrets, recursive: true);

    protected static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Contract", name);

    protected IConfiguration FromJson() => new ConfigurationBuilder()
        .AddJsonFile(FixturePath("application-contract.fixture.json"))
        .AddInMemoryCollection(_overrides)
        .Build();

    protected IConfiguration FromEnvironmentFile()
    {
        var values = File.ReadAllLines(FixturePath("application-contract.fixture.env"))
            .Where(_ => _.Length > 0 && !_.StartsWith('#'))
            .Select(_ => _.Split('=', 2))
            .ToDictionary(_ => _[0].Replace("__", ":", StringComparison.Ordinal), _ => (string?)_[1], StringComparer.OrdinalIgnoreCase);
        foreach (var item in _overrides)
        {
            values[item.Key] = item.Value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    protected static C.AuthProxy Bind(IReadOnlyDictionary<string, string?> translated, IConfiguration source) =>
        new ConfigurationBuilder()
            .AddConfiguration(source)
            .AddInMemoryCollection(translated)
            .Build()
            .GetSection(C.AuthProxy.SectionKey)
            .Get<C.AuthProxy>()!;
}
