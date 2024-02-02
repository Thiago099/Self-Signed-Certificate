using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


string domain = "localhost";
string certificateName = "Test self signed certificate";
string fileName = "testSelfSigned";
string password = "P@55w0rd";
int expiresInYears = 5;

// THIS CREATES THE CERTIFICATE
var rsa = RSA.Create(); // generate asymmetric key pair
var req = new CertificateRequest($"CN={domain}", rsa, HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);

req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

//1: ISO(International Organization for Standardization)
//3: Identified Organization
//6: Internet
//1: Private enterprises
//5: Security
//5: Internet Security
//7: Extended key usage
//3: Server Authentication

var sanBuilder = new SubjectAlternativeNameBuilder();
sanBuilder.AddDnsName(domain);
req.CertificateExtensions.Add(sanBuilder.Build());
var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(expiresInYears));

cert.FriendlyName = certificateName;

// THIS TRUSTS THE CERTIFICATE, you might want to delete them later on certmgr / Trusted Root Certification Authorities

var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
store.Open(OpenFlags.ReadWrite);
store.Add(cert);
store.Close();

File.WriteAllBytes($"./{fileName}.pfx", cert.Export(X509ContentType.Pfx, password));

// THE FOLLOWING COMENTED CODE IS NOT TESTED BUT IT SHOULD WORK
//// Create Base 64 encoded CER (public key only)
//File.WriteAllText("./mycert.cer",
//    "-----BEGIN CERTIFICATE-----\r\n"
//    + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
//    + "\r\n-----END CERTIFICATE-----");
