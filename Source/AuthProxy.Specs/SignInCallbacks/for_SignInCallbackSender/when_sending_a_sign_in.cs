// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

/// <summary>
/// Pins the contract a receiving service is written against: the method, the identity headers, the marker, the secret
/// and the exact shape of the body.
/// </summary>
public class when_sending_a_sign_in : given.a_sender
{
    JsonElement _body;

    async Task Because()
    {
        _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);
        _body = JsonElement.Parse(_handler.LastRequestBody!);
    }

    [Fact] void should_report_it_delivered() => _delivered.ShouldBeTrue();
    [Fact] void should_post() => _handler.LastRequest!.Method.ShouldEqual(HttpMethod.Post);
    [Fact] void should_post_to_the_callback_address() => _handler.LastRequest!.RequestUri!.ToString().ShouldEqual(Url);
    [Fact] void should_send_json() => _handler.LastRequest!.Content!.Headers.ContentType!.MediaType.ShouldEqual("application/json");
    [Fact] void should_mark_the_call_as_a_sign_in() => Header(Headers.SignInCallback).ShouldEqual("SignedIn");
    [Fact] void should_present_the_secret() => Header(Headers.SignInCallbackSecret).ShouldEqual("s3cret");
    [Fact] void should_carry_the_principal_id() => Header(Headers.PrincipalId).ShouldEqual("user-1");
    [Fact] void should_carry_the_principal_name() => Header(Headers.PrincipalName).ShouldEqual("user.one@example.com");
    [Fact] void should_carry_the_encoded_principal() => Header(Headers.Principal).ShouldNotBeEmpty();
    [Fact] void should_carry_the_tenant() => Header(Headers.TenantId).ShouldEqual("tenant-a");
    [Fact] void should_carry_the_legacy_tenant() => Header(Headers.LegacyTenantId).ShouldEqual("tenant-a");
    [Fact] void should_carry_the_service() => Header(Headers.ServiceId).ShouldEqual("app");
    [Fact] void should_carry_the_legacy_service() => Header(Headers.LegacyServiceId).ShouldEqual("app");
    [Fact] void should_send_no_authorization() => _handler.LastRequestAuthorization.ShouldBeNull();
    [Fact] void should_name_the_kind() => _body.GetProperty("kind").GetString().ShouldEqual("SignedIn");
    [Fact] void should_name_the_subject() => _body.GetProperty("subject").GetString().ShouldEqual("user-1");
    [Fact] void should_name_the_user() => _body.GetProperty("name").GetString().ShouldEqual("User One");
    [Fact] void should_give_the_email() => _body.GetProperty("email").GetString().ShouldEqual("user.one@example.com");
    [Fact] void should_name_the_identity_provider() => _body.GetProperty("identityProvider").GetString().ShouldEqual("github");
    [Fact] void should_name_the_tenant() => _body.GetProperty("tenant").GetString().ShouldEqual("tenant-a");
    [Fact] void should_say_when_it_happened() => _body.GetProperty("occurred").GetDateTimeOffset().ShouldEqual(_occurred);
    [Fact] void should_carry_nothing_else() => _body.EnumerateObject().Select(_ => _.Name).Order().ShouldEqual(["email", "identityProvider", "kind", "name", "occurred", "subject", "tenant"]);
}
