// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput.given;

/// <summary>
/// Public test-only fixture from Cratis/Arc@a8599847b0cf19a4dd5cb1a81f53dd5d2203f559,
/// Source/DotNET/Specs.Shared/ForwardedIdentityForSpecs.cs and
/// Arc.Core.Specs/Identity/ForwardedIdentityAuthentication/when_verifying_the_published_vector.cs.
/// </summary>
public class the_published_vector : Specification
{
    protected const string Principal = "eyJpZGVudGl0eVByb3ZpZGVyIjoiYWFkIiwidXNlcklkIjoidSIsInVzZXJEZXRhaWxzIjoibiIsInVzZXJSb2xlcyI6W10sImNsYWltcyI6W119";
    protected const string NonceA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    protected const string NonceB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    protected const string MacA = "jgVyScoemstnZgj25AE70omcBbrUuzl9bIoesbV_BHo";
    protected const string MacB = "ql7vBinbDwBTqcRq5op-eA4hyMWHf0LFh5MqPlG6qsI";
    protected const string Envelope = $"v1.k1.1700000000.{NonceA}.{MacA}";
    protected const string ExpectedCanonical = "Cratis.AuthProxy.ForwardedIdentity.v1\n8:arc-test\n2:k1\n10:1700000000\n43:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n4:POST\n11:/base/a%2Fb\n1:3\n21:x-ms-client-principal\n112:" + Principal + "\n24:x-ms-client-principal-id\n1:u\n26:x-ms-client-principal-name\n1:n\n";
    protected byte[] key;
    protected HttpRequestMessage request;
    protected byte[] canonical;
    private protected ForwardedIdentityRefusal refusal;
    protected bool accepted;
    protected string mac;

    void Establish()
    {
        key = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        request = new(HttpMethod.Post, "http://backend.example/base/a%2fb?x=1");
        request.Headers.Add(Headers.Principal, Principal);
        request.Headers.Add(Headers.PrincipalId, "u");
        request.Headers.Add(Headers.PrincipalName, "n");
    }

    protected void Canonicalize(string nonce = NonceA, string audience = "arc-test", string keyId = "k1")
    {
        accepted = ForwardedIdentityCanonicalInput.TryCreate(request, audience, keyId, "1700000000", nonce, out canonical, out refusal);
        mac = ForwardedIdentityEnvelope.Mac(key, canonical);
    }

    protected string CanonicalText() => Encoding.UTF8.GetString(canonical);
}
