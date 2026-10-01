// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

public class when_key_vault_protection_is_enabled_for_an_existing_ring : Specification
{
    const string Purpose = "existing-session";

    readonly List<XElement> _elements = [];
    IXmlRepository _repository;
    ServiceProvider _originalServices;
    ServiceProvider _protectedServices;
    Guid _keyId;
    string _session;
    string _originalXml;
    string _unprotected;

    void Establish()
    {
        _repository = Substitute.For<IXmlRepository>();
        _repository.GetAllElements().Returns(_elements);
        _repository.When(repository => repository.StoreElement(Arg.Any<XElement>(), Arg.Any<string>()))
            .Do(call => _elements.Add(new XElement(call.Arg<XElement>())));
        _originalServices = Build(new ConfigurationBuilder().Build());
        var manager = _originalServices.GetRequiredService<IKeyManager>();
        _keyId = manager.CreateNewKey(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90)).KeyId;
        _session = _originalServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).Protect("signed-in");
        _originalXml = _repository.GetAllElements().Single().ToString();
    }

    void Because()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Cratis:AuthProxy:DataProtection:KeyVault:KeyIdentifier"] = "https://example.vault.azure.net/keys/authproxy",
        }).Build();
        _protectedServices = Build(configuration);
        _unprotected = _protectedServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).Unprotect(_session);
    }

    [Fact] void should_keep_existing_sessions_readable() => _unprotected.ShouldEqual("signed-in");
    [Fact] void should_keep_the_existing_key() => _protectedServices.GetRequiredService<IKeyManager>().GetAllKeys().Single().KeyId.ShouldEqual(_keyId);
    [Fact] void should_not_rewrite_the_plaintext_key() => _repository.GetAllElements().Single().ToString().ShouldEqual(_originalXml);
    [Fact] void should_encrypt_future_keys_with_key_vault() => _protectedServices.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlEncryptor.GetType().Name.ShouldEqual("AzureKeyVaultXmlEncryptor");

    ServiceProvider Build(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection()
            .SetApplicationName("Cratis.AuthProxy.Specs")
            .ApplyConfiguredKeyRing(configuration)
            .DisableAutomaticKeyGeneration();
        services.Configure<KeyManagementOptions>(options => options.XmlRepository = _repository);

        return services.BuildServiceProvider();
    }

    void Destroy()
    {
        _protectedServices?.Dispose();
        _originalServices?.Dispose();
    }
}
