// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange;

public class when_identity_answers
{
    const string Token = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjQwMDAwMDAwMDB9.c2ln";

    [Theory]
    [InlineData("access_token", null)]
    [InlineData("access_token", "")]
    [InlineData("access_token", "not a jwt")]
    [InlineData("access_token", "a.b.c\r\n")]
    [InlineData("token_type", "DPoP")]
    [InlineData("token_type", null)]
    [InlineData("issued_token_type", "urn:wrong")]
    [InlineData("refresh_token", "forbidden")]
    [InlineData("unexpected", "value")]
    public async Task should_refuse_an_invalid_field(string field, string? value)
    {
        var body = Success();
        body[field] = value;
        (await Call(JsonSerializer.Serialize(body))).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("not-json")]
    [InlineData("{\"access_token\":null,\"access_token\":\"x\"}")]
    public async Task should_refuse_unknown_json_shapes(string body) =>
        (await Call(body)).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    [InlineData("30")]
    [InlineData(1.5)]
    public async Task should_refuse_an_unbounded_lifetime(object? lifetime)
    {
        var body = Success();
        body["expires_in"] = lifetime;
        (await Call(JsonSerializer.Serialize(body))).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);
    }

    [Theory]
    [InlineData(HttpStatusCode.Redirect, TokenExchangeVerdict.Refused)]
    [InlineData(HttpStatusCode.BadRequest, TokenExchangeVerdict.Refused)]
    [InlineData(HttpStatusCode.Unauthorized, TokenExchangeVerdict.Refused)]
    [InlineData(HttpStatusCode.TooManyRequests, TokenExchangeVerdict.Unavailable)]
    [InlineData(HttpStatusCode.InternalServerError, TokenExchangeVerdict.Unavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, TokenExchangeVerdict.Unavailable)]
    public async Task should_classify_http_errors(HttpStatusCode status, TokenExchangeVerdict expected) =>
        (await Call(Response("{\"error\":\"invalid_grant\"}", status))).Verdict.ShouldEqual(expected);

    [Theory]
    [InlineData("text/html")]
    [InlineData("text/plain")]
    public async Task should_refuse_a_non_json_content_type(string type) =>
        (await Call(Response(JsonSerializer.Serialize(Success()), type: type))).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);

    [Fact]
    public async Task should_accept_the_documented_identity_response()
    {
        var result = await Call(JsonSerializer.Serialize(Success()));
        result.Verdict.ShouldEqual(TokenExchangeVerdict.Success);
        result.Token.ShouldEqual(Token);
        result.ExpiresIn.ShouldEqual(300);
        result.ToString().ShouldEqual(nameof(TokenExchangeResult));
    }

    [Fact]
    public async Task should_refuse_an_oversize_body() =>
        (await Call(new string(' ', 16385) + JsonSerializer.Serialize(Success()))).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);

    [Fact]
    public async Task should_refuse_duplicate_fields() =>
        (await Call(JsonSerializer.Serialize(Success()).Replace("{", "{\"token_type\":\"Bearer\","))).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);

    [Theory]
    [InlineData("7", 7)]
    [InlineData("61", null)]
    [InlineData("-1", null)]
    [InlineData("Wed, 21 Oct 2015 07:28:00 GMT", null)]
    public async Task should_only_expose_bounded_integer_retry_after(string retry, int? expected)
    {
        var response = Response("{\"error\":\"temporarily_unavailable\"}", HttpStatusCode.BadRequest);
        response.Headers.TryAddWithoutValidation("Retry-After", retry);
        var result = await Client(new Handler(_ => Task.FromResult(response))).Exchange(Configuration(), Issuer(), "subject", "tenant-a", TestContext.Current.CancellationToken);
        result.Verdict.ShouldEqual(TokenExchangeVerdict.Unavailable);
        result.RetryAfter.ShouldEqual(expected);
    }

    [Fact]
    public async Task should_send_only_the_contract_form_and_basic_auth()
    {
        Dictionary<string, string?>? form = null;
        AuthenticationHeaderValue? authorization = null;
        var handler = new Handler(async request =>
        {
            request.RequestUri!.AbsoluteUri.ShouldEqual(Configuration().Endpoint);
            request.Method.ShouldEqual(HttpMethod.Post);
            authorization = request.Headers.Authorization;
            var values = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync());
            form = values.ToDictionary(_ => _.Key, _ => (string?)_.Value.ToString());
            return Response(JsonSerializer.Serialize(Success()));
        });
        await Client(handler).Exchange(Configuration(), Issuer(), "raw-subject", "tenant-a", TestContext.Current.CancellationToken);
        form!.Count.ShouldEqual(6);
        form["grant_type"].ShouldEqual("urn:ietf:params:oauth:grant-type:token-exchange");
        form["subject_token"].ShouldEqual("raw-subject");
        form["subject_token_type"].ShouldEqual("urn:ietf:params:oauth:token-type:jwt");
        form["resource"].ShouldEqual("https://cratis.direct/mcp");
        form["scope"].ShouldEqual("direct-mcp:read");
        form["tenant"].ShouldEqual("tenant-a");
        authorization!.Scheme.ShouldEqual("Basic");
        Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Parameter!)).ShouldEqual($"{Configuration().ClientId}:{Configuration().ClientSecret}");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_not_leak_transport_errors(bool timeout)
    {
        var handler = new Handler(_ => timeout ? throw new OperationCanceledException(Configuration().ClientSecret) : throw new HttpRequestException(Configuration().ClientSecret));
        var result = await Client(handler).Exchange(Configuration(), Issuer(), "raw-subject", "tenant-a", TestContext.Current.CancellationToken);
        result.Verdict.ShouldEqual(TokenExchangeVerdict.Unavailable);
    }

    [Fact]
    public async Task should_enforce_the_deadline_on_a_stalled_authority()
    {
        var configuration = Configuration();
        configuration.Timeout = TimeSpan.FromMilliseconds(100);
        var result = await Client(new StalledHandler()).Exchange(configuration, Issuer(), "subject", "tenant-a", TestContext.Current.CancellationToken);
        result.Verdict.ShouldEqual(TokenExchangeVerdict.Unavailable);
    }

    [Fact]
    public async Task should_bound_a_body_without_content_length()
    {
        using var content = new StreamingContent(Encoding.UTF8.GetBytes(new string(' ', 16385)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        (await Call(response)).Verdict.ShouldEqual(TokenExchangeVerdict.Refused);
    }

    [Fact]
    public async Task should_map_the_configured_access_token_subject_type()
    {
        var issuer = Issuer();
        issuer.SubjectTokenType = "access_token";
        var handler = new Handler(async request =>
        {
            var form = await request.Content!.ReadAsStringAsync();
            form.ShouldContain("urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token");
            return Response(JsonSerializer.Serialize(Success()));
        });
        await Client(handler).Exchange(Configuration(), issuer, "subject", "tenant-a", TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task should_honor_caller_cancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Client(new Handler(_ => throw new OperationCanceledException())).Exchange(Configuration(), Issuer(), "subject", "tenant-a", cancellation.Token));
    }

    internal static C.BearerTokenExchange Configuration() => new()
    {
        Endpoint = "https://identity.example/connect/token",
        ClientId = "synthetic-client",
        ClientSecret = string.Concat("synthetic-", "not-a-credential"),
        Resource = "https://cratis.direct/mcp",
        Audience = "direct-mcp",
        Scopes = ["direct-mcp:read"],
        ResultIssuer = "https://identity.example",
        Issuers = [Issuer()],
    };

    internal static C.BearerTokenExchangeIssuer Issuer() => new() { Issuer = "https://external.example" };

    static Dictionary<string, object?> Success() => new()
    {
        ["access_token"] = Token,
        ["token_type"] = "Bearer",
        ["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["expires_in"] = 300,
    };

    static Task<TokenExchangeResult> Call(string body) => Call(Response(body));

    static Task<TokenExchangeResult> Call(HttpResponseMessage response) =>
        Client(new Handler(_ => Task.FromResult(response))).Exchange(Configuration(), Issuer(), "subject", "tenant-a", TestContext.Current.CancellationToken);

    static IdentityTokenExchangeClient Client(HttpMessageHandler handler)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(handler));
        return new(factory);
    }

    static HttpResponseMessage Response(string body, HttpStatusCode status = HttpStatusCode.OK, string type = "application/json") => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, type),
    };

    sealed class StalledHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new(HttpStatusCode.OK);
        }
    }

    sealed class StreamingContent(byte[] body) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(body).AsTask();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new MemoryStream(body));
    }

    sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(request);
    }
}
