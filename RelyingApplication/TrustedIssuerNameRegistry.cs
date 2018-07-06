using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web;

namespace RelyingApplication
{
    public class TrustedIssuerNameRegistry:IssuerNameRegistry
    {
        /// <summary>
        ///  Returns the issuer Name from the security token.
        /// </summary>
        /// <param name="securityToken">The security token that contains the STS's certificates.</param>
        /// <returns>The name of the issuer who signed the security token.</returns>
        public override string GetIssuerName(SecurityToken securityToken)
        {
            X509SecurityToken x509Token = securityToken as X509SecurityToken;
            if (x509Token != null)
            {
                if (String.Equals(x509Token.Certificate.SubjectName.Name, "CN=localhost"))
                {
                    return x509Token.Certificate.SubjectName.Name;
                }
            }

            throw new SecurityTokenException("Untrusted issuer.");
        }
    }
}