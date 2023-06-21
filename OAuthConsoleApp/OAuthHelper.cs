using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OAuthConsoleApp
{
    public class OAuthRequestValue
    {
        public OAuthRequestValue(string key, string value = null)
        {
            Key = key;
            Value = value;
        }

        public string Key { get; set; }
        public string Value { get; set; }

        public bool IsValid => !Key.IsNullOrEmpty() && !Value.IsNullOrEmpty();
    }

    public class OAuthRequestCodeParams
    {
        public OAuthRequestValue RedirectUri { get; set; } = new("redirect_uri");
        public OAuthRequestValue ResponseType { get; set; } = new("response_type", "code");
        public OAuthRequestValue Scope { get; set; } = new("scope");
        public OAuthRequestValue ClientId { get; set; } = new("client_id");
        public OAuthRequestValue State { get; set; } = new("state");

        public string ResponseCodeKey { get; set; } = "code";
        public string ResponseStateKey { get; set; } = "state";

        public IEnumerable<OAuthRequestValue> Values => new[]
        {
            RedirectUri,
            ResponseType,
            Scope,
            ClientId,
            State
        };
    }

    public class OAuthRequestTokenParams
    {
        public OAuthRequestValue RedirectUri { get; set; } = new("redirect_uri");
        public OAuthRequestValue Code { get; set; } = new("code");
        public OAuthRequestValue ClientId { get; set; } = new("client_id");
        public OAuthRequestValue ClientSecret { get; set; } = new("client_secret");
        public OAuthRequestValue CodeVerifier { get; set; } = new("code_verifier");
        public OAuthRequestValue Scope { get; set; } = new("scope");
        public OAuthRequestValue GrantType { get; set; } = new("grant_type", "authorization_code");

        public string ResponseAccessTokenKey { get; set; } = "access_token";
        public string ResponseRefreshTokenKey { get; set; } = "refresh_token";
        public string ResponseExpirationKey { get; set; } = "expiration";

        public IEnumerable<OAuthRequestValue> Values => new[]
        {
            RedirectUri,
            Code,
            ClientId,
            ClientSecret,
            CodeVerifier,
            Scope,
            GrantType
        };
    }

    public class OAuthToken
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? Expiration { get; set; }
    }

    public class OAuthHelper
    {
        public OAuthRequestCodeParams RequestCodeParams { get; } = new();
        public OAuthRequestTokenParams RequestTokenParams { get; } = new();

        public Uri RequestCodeUrl { get; set; }// = new("https://accounts.google.com/o/oauth2/v2/auth");
        public Uri RequestTokenUrl { get; set; }// = new("https://www.googleapis.com/oauth2/v4/token");
        public string FinishHtmlCode { get; set; } = "<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>";

        public async Task<OAuthToken> Run()
        {
            var httpServerTask = StartHttpServer();

            RequestCode();

            var code = await httpServerTask;

            return await RequestToken(code);
        }

        private void RequestCode()
        {
            var state = GenerateRandomDataBase64url(32);
            RequestCodeParams.State.Value = state;

            var urlBuilder = new UriBuilder(RequestCodeUrl);
            urlBuilder.Query = RequestCodeParams.Values
                .Where(i => i.IsValid)
                .Select(i => $"{i.Key}={Uri.EscapeDataString(i.Value)}")
                .JoinString("&");

            // Creates the OAuth 2.0 authorization request.
            var request = urlBuilder.ToString();

            // Opens request in the browser.
            var pi = new ProcessStartInfo(request, "");
            pi.UseShellExecute = true;
            Process.Start(pi);
        }

        private async Task<OAuthToken> RequestToken(string code)
        {
            RequestTokenParams.Code.Value = code;
            RequestTokenParams.RedirectUri.Value = RequestCodeParams.RedirectUri.Value;

            // ???
            RequestTokenParams.CodeVerifier.Value = GenerateRandomDataBase64url(32);

            var tokenRequest = new HttpClient();

            var formValues = RequestTokenParams.Values
                .Where(i => i.IsValid)
                .ToDictionary(i => i.Key, i => Uri.EscapeDataString(i.Value));

            var content = new FormUrlEncodedContent(formValues);

            var tokenResponse = await tokenRequest.PostAsync(RequestTokenUrl, content);

            //var responseText = await tokenResponse.Content.ReadAsStringAsync();
            var response = await tokenResponse.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            if (response == null)
            {
                throw new Exception("Invalid response");
            }

            return new OAuthToken
            {
                AccessToken = GetValue(RequestTokenParams.ResponseAccessTokenKey, true, i => i),
                RefreshToken = GetValue(RequestTokenParams.ResponseRefreshTokenKey, true, i => i),
                Expiration = GetValue(RequestTokenParams.ResponseExpirationKey, true, ToDateTime)
            };

            T? GetValue<T>(string key, bool mandatory, Func<string, T?> parser)
            {
                if (response.TryGetValue(key, out var value))
                {
                    return parser(value);
                }

                if (mandatory)
                {
                    throw new Exception($"Request for token didn't return '{key}' value");
                }

                return default;
            }

            DateTime? ToDateTime(string str)
            {
                // TODO implement parser
                return null;
            }
        }

        private async Task<string> StartHttpServer()
        {
            // Creates a redirect URI using an available port on the loopback address.
            string redirectUri = $"http://{IPAddress.Loopback}:{GetRandomUnusedPort()}/";

            RequestCodeParams.RedirectUri.Value = redirectUri;
            RequestTokenParams.RedirectUri.Value = redirectUri;

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectUri);
            http.Start();

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            var buffer = Encoding.UTF8.GetBytes(FinishHtmlCode);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            await responseOutput.WriteAsync(buffer, 0, buffer.Length);
            responseOutput.Close();
            http.Stop();

            string error = context.Request.QueryString.Get("error");
            if (error is not null)
            {
                // process error
                throw new Exception(error);
            }

            // extracts the code + state
            var code = context.Request.QueryString.Get(RequestCodeParams.ResponseCodeKey);
            if (code.IsNullOrEmpty())
            {
                throw new Exception("Code is empty");
            }

            var state = context.Request.QueryString.Get(RequestCodeParams.ResponseStateKey);
            var stateIsRequested = RequestCodeParams.State.IsValid;
            if (stateIsRequested && state.IsNullOrEmpty())
            {
                // process error
                throw new Exception("State is not received");
            }

            return code;
        }

        // ref http://stackoverflow.com/a/3978040
        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        /// <summary> Returns URI-safe data with a given input length. </summary>
        private static string GenerateRandomDataBase64url(int length)
        {
            byte[] bytes = RandomNumberGenerator.GetBytes(length);
            return Base64UrlEncodeNoPadding(bytes);
        }

        /// <summary> Base64url no-padding encodes the given input buffer. </summary>
        private static string Base64UrlEncodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
    }

    static class StringExtensions
    {
        public static bool IsNullOrEmpty(this string str)
        {
            return string.IsNullOrEmpty(str);
        }

        public static string JoinString(this IEnumerable<string> strings, string separator = ",")
        {
            return strings != null ? string.Join(separator, strings) : null;
        }
    }
}
