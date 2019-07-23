using Microsoft.Azure.KeyVault;
using Microsoft.Identity.Client;
using System;
using System.Security;
using System.Threading.Tasks;

namespace UnitTestProject1
{
    public class UserAndPassword
    {
        public string User { get; set; }
        public string Password { get; set; }
    }

    public class KeyVaultSecretFetcher
    {
        private const string KeyVaultClientId = "4bf2b2cf-1fec-4ee9-8d95-e862d8d425a6";
        private IConfidentialClientApplication _cca;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly string _secret;

        public KeyVaultSecretFetcher(string secret)
        {
            _keyVaultClient = new KeyVaultClient(KeyVaultAuthenticationCallback);
            _secret = secret;
        }

        public async Task<UserAndPassword> FetchUserAsync()
        {
            var username = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-username");
            var password = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-password");

            return new UserAndPassword() { User = username.Value, Password = password.Value };
        }

        private async Task<string> KeyVaultAuthenticationCallback(string authority, string resource, string scope)
        {
            if (String.IsNullOrEmpty(_secret))
            {
                throw new InvalidOperationException("Test Setup Error: Could not find a setting named kvsecret");
            }

            if (_cca == null)
            {
                _cca = ConfidentialClientApplicationBuilder
                        .Create(KeyVaultClientId)
                        .WithAuthority(new Uri(authority), true)
                        .WithClientSecret(_secret)
                        .Build();
            }

            var scopes = new[] { resource + "/.default" };

            var authResult = await _cca
                .AcquireTokenForClient(scopes)
                .ExecuteAsync()
                .ConfigureAwait(false);

            return authResult.AccessToken;

        }

    }
}
