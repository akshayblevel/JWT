using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using  Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers
{
    [RoutePrefix("Token")]
    public class TokenController : ApiController
    {
        
        [Route("Generate")]
        public string Generate([FromBody]TokenRequest tokenRequest)
        {
            var plainTextSecurityKey = Convert.FromBase64String("VGhpcyBpcyBteSBzaGFyZWQsIG5vdCBzbyBzZWNyZXQsIHNlY3JldCE=");
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(plainTextSecurityKey, ecKey, 256 / 8);


            var tokenHandler = new JwtSecurityTokenHandler();

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, "Name"),
                    new Claim(ClaimTypes.PrimaryGroupSid,"GroupId"),
                }, "Custom"),

                Expires = DateTime.UtcNow.AddMinutes(20),

                Audience = "http://my.website1.com",                      
                Issuer = "http://my.tokenissuer1.com",        
                
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(plainTextSecurityKey),SecurityAlgorithms.HmacSha256Signature),
             
                EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(ecKey), SecurityAlgorithms.Aes256KW,SecurityAlgorithms.Aes256CbcHmacSha512)
            };

            
            var plainToken = tokenHandler.CreateJwtSecurityToken(securityTokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);

            return signedAndEncodedToken;
        }

       
    }

    public class TokenRequest
    {
        public string Name { get; set; }
    }
}
