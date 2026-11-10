// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.Dpop;
using Cratis.Specifications;
using NSubstitute;

namespace Cratis.AuthProxy.Security.for_Dpop;

public class when_a_bound_token_reaches_the_proxy : Specification
{
    const string Path = "/mcp/tools";
    const string Target = "https://direct.example.test" + Path;
    DpopHarness _harness;
    ForwardedRequest _forwarded;
    HttpStatusCode _valid;
    HttpStatusCode _replay;
    HttpStatusCode _bearer;
    HttpStatusCode _wrongTarget;
    HttpStatusCode _unbound;
    int _hostileForwarded;

    void Establish()
    {
        var seen = new ConcurrentDictionary<string, bool>();
        var store = Substitute.For<IDpopReplayStore>();
        store.CheckHealth(Arg.Any<CancellationToken>()).Returns(DpopReplayResult.Accepted);
        store.TryConsume(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => seen.TryAdd(call.ArgAt<string>(0) + "\0" + call.ArgAt<string>(1) + "\0" + call.ArgAt<string>(2), true) ? DpopReplayResult.Accepted : DpopReplayResult.Replay);
        _harness = new(store);
    }

    async Task Because()
    {
        using var client = _harness.CreateBearerClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        var x = Encode(point.X!);
        var y = Encode(point.Y!);
        var jwk = new { kty = "EC", crv = "P-256", x, y };
        var jkt = Hash($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        var token = _harness.Issuer.Token(new Dictionary<string, object> { ["cnf"] = new Dictionary<string, object> { ["jkt"] = jkt } });
        var proof = Sign(key, jwk, token, Target);
        using var accepted = await client.SendAsync(Request(token, proof));
        _valid = accepted.StatusCode;
        _forwarded = _harness.Origin.LastRequestTo(Path)!;
        _harness.Origin.Clear();
        using var replayed = await client.SendAsync(Request(token, proof));
        _replay = replayed.StatusCode;
        using var asBearer = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, token));
        _bearer = asBearer.StatusCode;
        using var wrong = await client.SendAsync(Request(token, Sign(key, jwk, token, Target + "/other")));
        _wrongTarget = wrong.StatusCode;
        _hostileForwarded = _harness.Origin.LastRequestTo(Path) is null ? 0 : 1;
        using var ordinary = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, _harness.Issuer.Token()));
        _unbound = ordinary.StatusCode;
    }

    async Task Destroy() => await _harness.DisposeAsync();

    [Fact] void should_accept_a_real_signed_bound_token_and_proof() => Assert.Equal(HttpStatusCode.OK, _valid);
    [Fact] void should_never_forward_the_raw_authorization() => Assert.Empty(_forwarded.Value("Authorization"));
    [Fact] void should_never_forward_the_raw_proof() => Assert.Empty(_forwarded.Value("DPoP"));
    [Fact] void should_refuse_replay_even_with_cached_token_validation() => Assert.Equal(HttpStatusCode.Unauthorized, _replay);
    [Fact] void should_refuse_a_bound_token_as_bearer() => Assert.Equal(HttpStatusCode.Unauthorized, _bearer);
    [Fact] void should_refuse_wrong_target() => Assert.Equal(HttpStatusCode.Unauthorized, _wrongTarget);
    [Fact] void should_forward_no_hostile_request() => Assert.Equal(0, _hostileForwarded);
    [Fact] void should_leave_unbound_bearer_behavior_unchanged() => Assert.Equal(HttpStatusCode.OK, _unbound);

    static HttpRequestMessage Request(string token, string proof)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Path);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        request.Headers.Add("DPoP", proof);
        return request;
    }

    static string Sign(ECDsa key, object jwk, string token, string target)
    {
        var header = Encode(JsonSerializer.SerializeToUtf8Bytes(new { typ = "dpop+jwt", alg = "ES256", jwk }));
        var payload = Encode(JsonSerializer.SerializeToUtf8Bytes(new { jti = Guid.NewGuid().ToString(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), htm = "GET", htu = target, ath = Hash(token) }));
        var input = header + "." + payload;
        return input + "." + Encode(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    static string Hash(string value) => Encode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
