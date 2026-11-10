// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.BearerRoutes.for_BearerTokenIntrospector.given;
using Cratis.AuthProxy.BearerRoutes.Introspection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenIntrospector;

/// <summary>
/// Only a well-formed 200 says anything about the token. An <c language="text">active:false</c> is Inactive; an answer
/// that contradicts the validated token is Inactive; everything else — a failing endpoint, our own client being
/// refused, redirects, junk — is Unavailable, never read as the token being active.
/// </summary>
public class when_the_endpoint_answers : Specification
{
    IntrospectionVerdict _active;
    IntrospectionVerdict _inactive;
    IntrospectionVerdict _otherSubject;
    IntrospectionVerdict _otherClient;
    IntrospectionVerdict _otherIssuer;
    IntrospectionVerdict _otherTokenType;
    IntrospectionVerdict _extraFields;
    IntrospectionVerdict _serverError;
    IntrospectionVerdict _tooManyRequests;
    IntrospectionVerdict _unauthorized;
    IntrospectionVerdict _forbidden;
    IntrospectionVerdict _redirected;
    IntrospectionVerdict _notJson;
    IntrospectionVerdict _noActiveField;
    IntrospectionVerdict _activeAsString;
    IntrospectionVerdict _badRequest;
    IntrospectionVerdict _unreachable;
    string _body;
    string _authorization;
    string _method;
    bool _sentCookie;
    string _query;
    string _allLogs;

    async Task Because()
    {
        _active = await Ask("""{"active":true}""");
        _extraFields = await Ask("""{"active":true,"scope":"admin","tid":"x","aud":"other","username":"mallory","roles":["admin"]}""");
        _inactive = await Ask("""{"active":false}""");
        _otherSubject = await Ask("""{"active":true,"sub":"someone-else"}""");
        _otherClient = await Ask("""{"active":true,"client_id":"another"}""");
        _otherIssuer = await Ask("""{"active":true,"iss":"https://evil.example.test/"}""");
        _otherTokenType = await Ask("""{"active":true,"token_type":"DPoP"}""");
        _serverError = await Ask("{}", HttpStatusCode.InternalServerError);
        _tooManyRequests = await Ask("{}", HttpStatusCode.TooManyRequests);
        _unauthorized = await Ask("""{"error":"invalid_client"}""", HttpStatusCode.Unauthorized);
        _forbidden = await Ask("""{"error":"x"}""", HttpStatusCode.Forbidden);
        _redirected = await Ask("{}", HttpStatusCode.Redirect);
        _badRequest = await Ask("""{"active":false}""", HttpStatusCode.BadRequest);
        _notJson = await Ask("<html>no</html>");
        _noActiveField = await Ask("""{"sub":"account-1"}""");
        _activeAsString = await Ask("""{"active":"true"}""");

        var scripted = new ScriptedIntrospection(_ => throw new HttpRequestException("boom"));
        _unreachable = await scripted.Introspect();

        scripted = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json("""{"active":true}""")));
        await scripted.Introspect();
        _body = scripted.LastBody!;
        _authorization = scripted.LastAuthorization!;
        _method = scripted.LastRequest!.Method.Method;
        _sentCookie = scripted.LastRequest.Headers.Contains("Cookie");
        _query = scripted.LastRequest.RequestUri!.Query;
        _allLogs = string.Join('\n', _logs);
    }

    readonly List<string> _logs = [];

    [Fact] void should_report_active_for_an_active_answer() => _active.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_ignore_everything_but_active() => _extraFields.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_report_inactive_for_an_inactive_answer() => _inactive.ShouldEqual(IntrospectionVerdict.Inactive);
    [Fact] void should_refuse_an_answer_naming_another_subject() => _otherSubject.ShouldEqual(IntrospectionVerdict.Inactive);
    [Fact] void should_refuse_an_answer_naming_another_client() => _otherClient.ShouldEqual(IntrospectionVerdict.Inactive);
    [Fact] void should_refuse_an_answer_naming_another_issuer() => _otherIssuer.ShouldEqual(IntrospectionVerdict.Inactive);
    [Fact] void should_refuse_an_answer_for_another_token_type() => _otherTokenType.ShouldEqual(IntrospectionVerdict.Inactive);
    [Fact] void should_be_unavailable_on_a_server_error() => _serverError.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_throttled() => _tooManyRequests.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_our_client_is_refused() => _unauthorized.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_our_client_is_forbidden() => _forbidden.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_on_a_redirect() => _redirected.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_on_any_other_non_200() => _badRequest.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_the_answer_is_not_json() => _notJson.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_the_answer_has_no_active_field() => _noActiveField.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_active_is_not_a_boolean() => _activeAsString.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_be_unavailable_when_the_endpoint_cannot_be_reached() => _unreachable.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_post() => _method.ShouldEqual("POST");
    [Fact] void should_send_only_the_token_and_its_hint() => _body.ShouldEqual("token=header.payload.signature&token_type_hint=access_token");
    [Fact] void should_authenticate_with_basic_client_credentials() => _authorization.ShouldEqual("Basic " + Convert.ToBase64String("authproxy:not-a-real-secret"u8));
    [Fact] void should_not_send_a_cookie() => _sentCookie.ShouldBeFalse();
    [Fact] void should_not_put_anything_in_the_url() => _query.ShouldBeEmpty();
    [Fact] void should_not_log_the_token_or_the_secret() => (_allLogs.Contains(ScriptedIntrospection.Token, StringComparison.Ordinal) || _allLogs.Contains(ScriptedIntrospection.Secret, StringComparison.Ordinal)).ShouldBeFalse();

    [Theory]
    [InlineData("\"cnf\":{\"jkt\":\"synthetic-key\"}")]
    [InlineData("\"cnf\":{\"x5t#S256\":\"synthetic-certificate\"},\"token_type\":\"Bearer\"")]
    [InlineData("\"cnf\":{\"jwk\":{}},\"token_type\":\"DPoP\"")]
    [InlineData("\"cnf\":\"synthetic-binding\",\"token_type\":null")]
    [InlineData("\"cnf\":null,\"token_type\":\"Bearer\"")]
    [InlineData("\"Cnf\":\"{invalid-json\"")]
    public async Task should_treat_any_confirmation_as_inactive_regardless_of_token_type(string fields)
    {
        var verdict = await Ask("{\"active\":true," + fields + "}");

        verdict.ShouldEqual(IntrospectionVerdict.Inactive);
    }

    async Task<IntrospectionVerdict> Ask(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var scripted = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json(body, status)));
        var verdict = await scripted.Introspect();
        _logs.AddRange(scripted.Logs);
        return verdict;
    }
}
