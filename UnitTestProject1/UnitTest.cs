using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        public TestContext TestContext { get; set; }

        private const string AuthorityUri = "https://bgavrilb2c.b2clogin.com/tfp/bgavrilb2c.onmicrosoft.com/b2c_1_ropc";
        private const string Scope = "https://bgavrilb2c.onmicrosoft.com/hello3/user_impersonation";
        private const string KeyVaultSecret = "kvsecret";
        string B2CAppId = "a7bb8dac-fdda-42f0-b277-b9c4e5ca0dac";

        [TestMethod]
        public async Task TestAsync()
        {
            // The CI should inject his secret as an env variable
            string secret = Environment.GetEnvironmentVariable(KeyVaultSecret);

            // TODO: if the test is not run from the CI, use   
            // PublicClientApplication.AcquireTokenInteractive to fetch the secrets s(i.e. have the developer login)

            VerifySecretExists(secret);

            KeyVaultSecretFetcher fetcher = new KeyVaultSecretFetcher(secret);
            var userPassword = await fetcher.FetchUserAsync().ConfigureAwait(false);

            IPublicClientApplication publicClient = PublicClientApplicationBuilder
                .Create(B2CAppId)
                .WithB2CAuthority(AuthorityUri)
                .Build();

            // MSAL wants a secure string
            SecureString secureString = new SecureString();
            foreach (char c in userPassword.Password)
            {
                secureString.AppendChar(c);
            }

            var result = await publicClient.AcquireTokenByUsernamePassword(
                new[] { Scope },
                userPassword.User,
                secureString).ExecuteAsync();

            Assert.IsNotNull(result);
        }

        private static void VerifySecretExists(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                IDictionary allEnvs = Environment.GetEnvironmentVariables();
                StringBuilder sb = new StringBuilder();
                foreach (DictionaryEntry kvp in allEnvs)
                {
                    sb.Append($"{kvp.Key}  = {kvp.Value}; ");
                }

                throw new InvalidOperationException($"Could not find an env variable that holds the " +
                    $"Confidential Client secret needed to access keyvault. Looking for a variable named {KeyVaultSecret} " +
                    $"Existing variables are: {sb.ToString()}");
            }
        }
    }
}
