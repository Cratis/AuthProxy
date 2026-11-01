// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Maps the application's Ante onto <see cref="Invite"/>.
/// </summary>
public static class OnboardingTranslation
{
    /// <summary>
    /// The environment keys, relative to <c language="text">onboarding</c>, that must be present.
    /// </summary>
    public static readonly IReadOnlyList<string> RequiredKeys =
    [
        "stageUrl",
        "exchangeUrl",
        "tokenMetadataUrl",
        "issuer",
        "audience",
        "lobbyFrontendBaseUrl",
        "attestation.issuer",
        "attestation.audience",
        "attestation.keyId",
        "attestation.privateKeyPem"
    ];

    /// <summary>
    /// The environment keys, relative to <c language="text">onboarding</c>, that may be present.
    /// </summary>
    public static readonly IReadOnlyList<string> OptionalKeys =
    [
        "lobbyBackendBaseUrl",
        "registrationBaseUrl",
        "subjectAlreadyExistsUrl",
        "tenantClaim",
        "emailClaim",
        "attestation.lifetimeSeconds"
    ];

    /// <summary>
    /// Writes the invite options.
    /// </summary>
    /// <param name="environment">The environment.</param>
    /// <param name="settings">The settings to write into.</param>
    /// <exception cref="ApplicationContractException">Thrown when a required key is missing or a value is invalid.</exception>
    public static void Translate(ApplicationEnvironment environment, ContractSettings settings)
    {
        string Require(string key) => environment.Require(ApplicationContractKeys.OnboardingValue(key), "onboarding");
        string RequireUrl(string key) => ContractUrl.Validate(Require(key), ApplicationContractKeys.OnboardingValue(key), environment);
        void OptionalUrl(string key, string target)
        {
            var value = environment.Find(ApplicationContractKeys.OnboardingValue(key));
            if (value is not null)
            {
                settings.Set(target, ContractUrl.Validate(value, ApplicationContractKeys.OnboardingValue(key), environment));
            }
        }

        const string invite = "Invite";
        settings.Set($"{invite}:StageUrl", RequireUrl("stageUrl"));
        settings.Set($"{invite}:ExchangeUrl", RequireUrl("exchangeUrl"));
        settings.Set($"{invite}:TokenMetadataUrl", RequireUrl("tokenMetadataUrl"));
        settings.Set($"{invite}:Issuer", Require("issuer"));
        settings.Set($"{invite}:Audience", Require("audience"));
        settings.Set($"{invite}:TenantClaim", environment.Find(ApplicationContractKeys.OnboardingValue("tenantClaim")) ?? "tenant_id");
        settings.Set($"{invite}:EmailClaim", environment.Find(ApplicationContractKeys.OnboardingValue("emailClaim")) ?? "email");
        settings.Set($"{invite}:Lobby:Frontend:BaseUrl", RequireUrl("lobbyFrontendBaseUrl"));
        OptionalUrl("lobbyBackendBaseUrl", $"{invite}:Lobby:Backend:BaseUrl");
        OptionalUrl("registrationBaseUrl", $"{invite}:Lobby:Registration:BaseUrl");
        OptionalUrl("subjectAlreadyExistsUrl", $"{invite}:SubjectAlreadyExistsUrl");

        var keyId = Require("attestation.keyId");
        settings.Set($"{invite}:Attestation:Issuer", Require("attestation.issuer"));
        settings.Set($"{invite}:Attestation:Audience", Require("attestation.audience"));
        settings.Set($"{invite}:Attestation:ActiveKeyId", keyId);
        settings.Set($"{invite}:Attestation:SigningKeys:0:KeyId", keyId);
        settings.Set($"{invite}:Attestation:SigningKeys:0:PrivateKeyPem", Require("attestation.privateKeyPem"));

        var lifetime = environment.Find(ApplicationContractKeys.OnboardingValue("attestation.lifetimeSeconds"));
        if (lifetime is not null)
        {
            if (!int.TryParse(lifetime, out var seconds))
            {
                throw new ApplicationContractException(
                    $"Environment '{environment.Name}': key '{ApplicationContractKeys.OnboardingValue("attestation.lifetimeSeconds")}' must be a whole number of seconds.");
            }

            settings.Set($"{invite}:Attestation:Lifetime", TimeSpan.FromSeconds(seconds).ToString());
        }
    }
}
