using Microsoft.Azure.KeyVault;
using Microsoft.Identity.Client;
using System;
using System.Security;
using System.Threading.Tasks;

namespace ConsoleApp1
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


        public KeyVaultSecretFetcher()
        {
            _keyVaultClient = new KeyVaultClient(KeyVaultAuthenticationCallback);
        }

        public async Task<UserAndPassword> FetchUserAsync()
        {
            var username = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-username/67b2a6026d764e6e84d79af56c71d643");
            var password = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-password/5eec3143d3ff4c3a97f99403e0f74338");

            return new UserAndPassword() { User = username.Value, Password = password.Value };
        }

        //private static async Task<string> FetchAtAsync(KeyVaultClient keyVaultClient)
        //{


        //    var pca = PublicClientApplicationBuilder.Create(null).WithB2CAuthority(null).Build();
        //    SecureString secureString = new SecureString();
        //    foreach (char c in password.Value)
        //    {
        //        secureString.AppendChar(c);
        //    }

        //    var result = await pca.AcquireTokenByUsernamePassword(null, username.Value, secureString).ExecuteAsync();

        //    return result.AccessToken;
        //}

        private async Task<string> KeyVaultAuthenticationCallback(string authority, string resource, string scope)
        {
            string secret = Environment.GetEnvironmentVariable("kv_secret") ; // get it from VSTS 

            if (_cca != null)
            {
                _cca = ConfidentialClientApplicationBuilder
                        .Create(KeyVaultClientId)
                        .WithAuthority(new Uri(authority), true)
                        .WithClientSecret(secret)
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
