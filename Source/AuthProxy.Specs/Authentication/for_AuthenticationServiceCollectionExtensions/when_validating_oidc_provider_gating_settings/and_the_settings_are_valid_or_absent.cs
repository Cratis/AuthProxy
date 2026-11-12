// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_oidc_provider_gating_settings;

/// <summary>
/// Specifies that a provider without the settings, and one with a well-formed set, both pass.
/// </summary>
public class and_the_settings_are_valid_or_absent : given.canonical_configuration_validation
{
    Exception? _withoutSettings;
    Exception? _withSettings;

    void Establish()
    {
        var configured = ValidOidcProvider();
        configured[$"{C.Authentication.SectionKey}:OidcProviders:0:AuthorizationParameters:connection"] = "email";
        configured[$"{C.Authentication.SectionKey}:OidcProviders:0:RequireVerifiedEmail"] = "true";
        configured[$"{C.Authentication.SectionKey}:OidcProviders:0:DenialResponse"] = "FailedSignIn";
        _withSettings = ResolveAuthenticationOptions(BuildServices(configured));
        _withoutSettings = ResolveAuthenticationOptions(BuildServices(ValidOidcProvider()));
    }

    [Fact] void should_accept_a_provider_without_the_settings() => _withoutSettings.ShouldBeNull();
    [Fact] void should_accept_a_provider_with_valid_settings() => _withSettings.ShouldBeNull();
}
