// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_translating_the_json_fixture : given.contract_fixture
{
    C.AuthProxy _options;
    ValidateOptionsResult _attestationValidation;

    void Because()
    {
        var source = FromJson();
        _options = Bind(ApplicationContractTranslator.Translate(source), source);
        _attestationValidation = new InvitationAttestationConfigurationValidator().Validate(null, _options);
    }

    [Fact] void should_produce_four_openid_connect_providers() => _options.Authentication.OidcProviders.Select(_ => _.Name).ShouldEqual(["EntraId", "Google", "Apple", "Partner"]);
    [Fact] void should_produce_one_oauth_provider() => _options.Authentication.OAuthProviders.Select(_ => _.Name).ShouldEqual(["GitHub"]);
    [Fact] void should_derive_the_entra_authority_from_the_tenant() => _options.Authentication.OidcProviders[0].Authority.ShouldEqual("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0");
    [Fact] void should_brand_entra_as_microsoft() => _options.Authentication.OidcProviders[0].Type.ShouldEqual(C.OidcProviderType.Microsoft);
    [Fact] void should_split_the_scopes() => string.Join(',', _options.Authentication.OidcProviders[2].Scopes).ShouldEqual("name,email");
    [Fact] void should_use_the_apple_response_mode() => _options.Authentication.OidcProviders[2].ResponseMode.ShouldEqual(C.OidcResponseMode.FormPost);
    [Fact] void should_use_the_named_authority_for_the_openid_provider() => _options.Authentication.OidcProviders[3].Authority.ShouldEqual("http://localhost:5556/dex");
    [Fact] void should_name_the_github_endpoints() => _options.Authentication.OAuthProviders[0].TokenEndpoint.ShouldEqual("https://github.com/login/oauth/access_token");
    [Fact] void should_map_the_github_subject() => _options.Authentication.OAuthProviders[0].ClaimMappings["sub"].ShouldEqual("id");
    [Fact] void should_carry_the_client_id() => _options.Authentication.OAuthProviders[0].ClientId.ShouldEqual("placeholder-github-client-id");
    [Fact] void should_enable_invitation_completion_with_the_entra_object_id() => _options.Authentication.OidcProviders[0].CanonicalIdentity!.SubjectClaimType.ShouldEqual("oid");
    [Fact] void should_key_the_github_issuer() => _options.Authentication.OAuthProviders[0].CanonicalIdentity!.Issuer.ShouldEqual("https://github.com");
    [Fact] void should_point_the_invite_at_the_stage_url() => _options.Invite!.StageUrl.ShouldEqual("http://localhost:8080/_invite/stage");
    [Fact] void should_point_the_invite_at_the_exchange_url() => _options.Invite!.ExchangeUrl.ShouldEqual("http://localhost:8080/_invite/exchange");
    [Fact] void should_point_the_lobby_at_the_frontend() => _options.Invite!.Lobby!.Frontend!.BaseUrl.ShouldEqual("http://localhost:8080/");
    [Fact] void should_read_the_signing_key_from_the_secrets_directory() => _options.Invite!.Attestation!.SigningKeys.Single().PrivateKeyPem.ShouldContain("PRIVATE KEY");
    [Fact] void should_make_the_signed_invitation_configuration_valid() => _attestationValidation.Succeeded.ShouldBeTrue();
}
