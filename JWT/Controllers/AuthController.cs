using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;

namespace JWT.Controllers
{
    [RoutePrefix("Auth")]
    public class AuthController : ApiController
    {
        [Route("validate")]
        public HttpResponseMessage Generate([FromBody]string token)
        {
            var plainTextSecurityKey = Convert.FromBase64String("VGhpcyBpcyBteSBzaGFyZWQsIG5vdCBzbyBzZWNyZXQsIHNlY3JldCE=");
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(plainTextSecurityKey, ecKey, 256 / 8);

            var tokenHandler = new JwtSecurityTokenHandler();
            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                {
                    "http://my.website1.com"
                },
                ValidIssuers = new string[]
                {
                    "http://my.tokenissuer1.com"
                },
                IssuerSigningKey = new SymmetricSecurityKey(plainTextSecurityKey),
                 TokenDecryptionKey = new SymmetricSecurityKey(ecKey)
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
            }
            catch (System.ArgumentException ex0)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex0.Message.ToString());
                //IDX10703: Unable to decode the 'signature': 'eyJuYW1laWQiOiJteWVtYWlsQG15cHJvdmlkZXIuY29tIiwiaXNzIjoiaHR0cDovL215LnRva2VuaXNzdWVyLmNvbSIsImF1ZCI6Imh0dHA6Ly9teS53ZWJzaXRlLmNvbSIsImV4cCI6MTQ4MDMxNjIzMCwibmJmIjoxNDgwMzE2MTcwfQ' as Base64url encoded string. jwtEncodedString: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1laWQiOiJteWVtYWlsQG15cHJvdmlkZXIuY29tIiwiaXNzIjoiaHR0cDovL215LnRva2VuaXNzdWVyLmNvbSIsImF1ZCI6Imh0dHA6Ly9teS53ZWJzaXRlLmNvbSIsImV4cCI6MTQ4MDMxNjIzMCwibmJmIjoxNDgwMzE2MTcwfQ.B-KhAWqGfR9Bw7tQu7DmadeXLCRC088HEkFQs2QUx'.
            }
            catch (Microsoft.IdentityModel.Tokens.SecurityTokenInvalidAudienceException ex1)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex1.Message.ToString());
                //IDX10214: Audience validation failed. Audiences: 'http://my.website1.com'. Did not match:  validationParameters.ValidAudience: 'null' or validationParameters.ValidAudiences: 'http://my.website.com, http://my.otherwebsite.com'
            }
            catch (Microsoft.IdentityModel.Tokens.SecurityTokenInvalidIssuerException ex2)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex2.Message.ToString());
                //IDX10205: Issuer validation failed. Issuer: 'http://my.tokenissuer1.com'. Did not match: validationParameters.ValidIssuer: 'null' or validationParameters.ValidIssuers: 'http://my.tokenissuer.com, http://my.othertokenissuer.com'.
            }
            catch (Exception ex)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex.Message.ToString());
            }

            if (validatedToken.ValidTo >= DateTime.UtcNow)
                return Request.CreateResponse(HttpStatusCode.OK, "Valid Token");
            else
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, "Token Expires");

            return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, "Internal Server Error");
        }
    }
}
