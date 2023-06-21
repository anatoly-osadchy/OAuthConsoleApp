// Copyright 2016 Google Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OAuthConsoleApp
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // ANOA: credentials of my test registered app "MyOAuthTestApp"
            string clientId = "1084886105350-60j8b8mgifkpvet5t798io42dtcgmgeb.apps.googleusercontent.com";
            string clientSecret = "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";

            Console.WriteLine("+-----------------------+");
            Console.WriteLine("|  Sign in with Google  |");
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("");
            Console.WriteLine("Press any key to sign in...");
            //Console.ReadKey();

            var authHelper = new OAuthHelper
            {
                RequestCodeUrl = new ("https://accounts.google.com/o/oauth2/v2/auth"),
                RequestTokenUrl = new ("https://www.googleapis.com/oauth2/v4/token")
            };

            authHelper.RequestCodeParams.Scope.Value = "openid https://www.googleapis.com/auth/userinfo.email";

            authHelper.RequestCodeParams.ClientId.Value = clientId;
            authHelper.RequestTokenParams.ClientId.Value = clientId;
            authHelper.RequestTokenParams.ClientSecret.Value = clientSecret;

            var token = await authHelper.Run();
            Console.WriteLine("AccessToken:");
            Console.WriteLine(token);

            //await DoOAuthAsync(clientId, clientSecret);

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return 0;
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

        private static async Task DoOAuthAsync(string clientId, string clientSecret)
        {
            // Generates state and PKCE values.
            string state = GenerateRandomDataBase64url(32);
            string codeVerifier = GenerateRandomDataBase64url(32);
            const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";

            // Creates a redirect URI using an available port on the loopback address.
            string redirectUri = $"http://{IPAddress.Loopback}:{GetRandomUnusedPort()}/";
            Log("redirect URI: " + redirectUri);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectUri);
            Log("Listening..");
            http.Start();

            (string key, string value)[] queryParts =
                {
                    ("redirect_uri", redirectUri),
                    ("response_type", "code"),
                    ("scope", "openid https://www.googleapis.com/auth/userinfo.email"),
                    ("client_id", clientId),
                    ("state", state),
                };
            var urlBuilder = new UriBuilder(AuthorizationEndpoint);
            urlBuilder.Query = queryParts
                .Select(i => $"{i.key}={Uri.EscapeDataString(i.value)}")
                .JoinString("&");


            // Creates the OAuth 2.0 authorization request.
            // Opens request in the browser.
            var request = urlBuilder.ToString();
            Log($"Request: {request}");
            var pi = new ProcessStartInfo(request, "");
            pi.UseShellExecute = true;
            Process.Start(pi);

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Brings the Console to Focus.
            BringConsoleToFront();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            string responseString = "<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            await responseOutput.WriteAsync(buffer, 0, buffer.Length);
            responseOutput.Close();
            http.Stop();
            Log("HTTP server stopped.");

            // Checks for errors.
            string error = context.Request.QueryString.Get("error");
            if (error is not null)
            {
                Log($"OAuth authorization error: {error}.");
                return;
            }
            if (context.Request.QueryString.Get("code") is null
                || context.Request.QueryString.Get("state") is null)
            {
                Log($"Malformed authorization response. {context.Request.QueryString}");
                return;
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incomingState = context.Request.QueryString.Get("state");

            // Compares the received state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incomingState != state)
            {
                Log($"Received request with invalid state ({incomingState})");
                return;
            }
            Log("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            await ExchangeCodeForTokensAsync(code, codeVerifier, redirectUri, clientId, clientSecret);
        }

        private static async Task ExchangeCodeForTokensAsync(string code, string codeVerifier, string redirectUri, string clientId, string clientSecret)
        {
            Log("Exchanging code for tokens...");

            // builds the  request
            string tokenRequestUri = "https://www.googleapis.com/oauth2/v4/token";

            // sends the request
            var tokenRequest = new HttpClient();
            //tokenRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            //tokenRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
            //tokenRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml;q=0.9"));
            //tokenRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*;q=0.8"));

            try
            {
                // gets the response
                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "code", code },
                    { "redirect_uri", Uri.EscapeDataString(redirectUri) },
                    { "client_id", clientId },
                    { "code_verifier", codeVerifier },
                    { "client_secret", clientSecret },
                    { "scope", "" },
                    { "grant_type", "authorization_code" }
                });
                var tokenResponse = await tokenRequest.PostAsync(new Uri(tokenRequestUri), content);
                var responseText = await tokenResponse.Content.ReadAsStringAsync();
                Console.WriteLine(responseText);

                // converts to dictionary
                var response = await tokenResponse.Content.ReadFromJsonAsync<Dictionary<string, string>>();

                string accessToken = response!["access_token"];
                await RequestUserInfoAsync(accessToken);
            }
            catch (HttpRequestException ex)
            {
                Log($"HTTP: {ex.StatusCode}\r\nException: {ex}");
            }
        }

        private static async Task RequestUserInfoAsync(string accessToken)
        {
            Log("Making API Call to UserInfo...");

            // builds the  request
            string userInfoRequestUri = "https://www.googleapis.com/oauth2/v3/userinfo";

            // sends the request
            var userInfoRequest = new HttpClient();
            userInfoRequest.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            //userInfoRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            //userInfoRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
            //userInfoRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml;q=0.9"));
            //userInfoRequest.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*;q=0.8"));

            // gets the response
            var userInfoResponse = await userInfoRequest.GetAsync(new Uri(userInfoRequestUri));
            var userInfoResponseText = await userInfoResponse.Content.ReadAsStringAsync();
            Log(userInfoResponseText);
        }

        /// <summary> Appends the given string to the on-screen log, and the debug console. </summary>
        private static void Log(string output, ConsoleColor? fgColor = null, ConsoleColor? bgColor = null)
        {
            var colors = (fg: Console.ForegroundColor, bg: Console.BackgroundColor);
            if (fgColor != null || bgColor != null)
            {
                Console.ForegroundColor = fgColor ?? colors.fg;
                Console.BackgroundColor = bgColor ?? colors.bg;
            }

            Console.WriteLine(output);

            (Console.ForegroundColor, Console.BackgroundColor) = colors;
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        private static string GenerateRandomDataBase64url(int length)
        {
            byte[] bytes = RandomNumberGenerator.GetBytes(length);
            return Base64UrlEncodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string, which is assumed to be ASCII.
        /// </summary>
        private static byte[] Sha256Ascii(string text)
        {
            var bytes = Encoding.ASCII.GetBytes(text);
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
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

        // Hack to bring the Console window to front.
        // ref: http://stackoverflow.com/a/12066376

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        private static void BringConsoleToFront()
        {
            SetForegroundWindow(GetConsoleWindow());
        }
    }
}
