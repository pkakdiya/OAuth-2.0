using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using WebAPI.OAuth.Authentication.Models;

namespace WebAPI.OAuth.Authentication.Help
{
    public class AppOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly string _publicClientId;

        private OAuthAPIEntities_API databaseContext = new OAuthAPIEntities_API();

        public AppOAuthProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException(nameof(publicClientId));
            }

            _publicClientId = publicClientId;
        }

        #region Grant Resource Owner Credential override method

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            string userName = context.UserName;
            string password = context.Password;
            var user = this.databaseContext.LoginByUsernamePassword(userName, password).ToList();

            /*Verification*/
            if (user == null || user.Count() <= 0)
            {
                context.SetError("Invalid_Grant", "The username or password is incorrect");

                return;
            }

            /*Initialization*/
            var claims = new List<Claim>();
            var userInfo = user.FirstOrDefault();

            claims.Add(new Claim(ClaimTypes.Name, userInfo.username));

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookieClaimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationType);

            AuthenticationProperties properties = CreateProperties(userInfo.username);
            AuthenticationTicket ticket = new AuthenticationTicket(claimsIdentity, properties);

            context.Validated(ticket);
            context.Request.Context.Authentication.SignIn(cookieClaimIdentity);
        }


        public static AuthenticationProperties CreateProperties(string userName)
        {
            // Settings.
            IDictionary<string, string> data = new Dictionary<string, string>
                                               {
                                                   { "userName", userName }
                                               };

            // Return info.
            return new AuthenticationProperties(data);
        }

        #endregion

        #region Token endpoint override method.

        /// <summary>
        /// Token endpoint override method
        /// </summary>
        /// <param name="context">Context parameter</param>
        /// <returns>Returns when task is completed</returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                // Adding.
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion

        #region Validate Client authntication override method

        /// <summary>
        /// Validate Client authntication override method
        /// </summary>
        /// <param name="context">Contect parameter</param>
        /// <returns>Returns validation of client authentication</returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                // Validate Authoorization.
                context.Validated();
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion

        #region Validate client redirect URI override method

        /// <summary>
        /// Validate client redirect URI override method
        /// </summary>
        /// <param name="context">Context parmeter</param>
        /// <returns>Returns validation of client redirect URI</returns>
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            // Verification.
            if (context.ClientId == _publicClientId)
            {
                // Initialization.
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                // Verification.
                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    // Validating.
                    context.Validated();
                }
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion
    }
}