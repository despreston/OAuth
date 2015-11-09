/* Desmond Preston 2015

Oauth implementation

*/

#include "stdio.h"
#include <iostream>
#include <time.h>
#include <openssl/hmac.h>
#include <map>


using namespace std;

// Application Specific. Generated from apps.twitter.com
string Consumerkey = "uvSDDZJW7XiG64akUzMgS44tF";
string ConsumerSecret = "CCu9u5pRUOtXeO9VsitmgVSL4RbQwbiWX06aBLkaRsJRVt6EKL";

const string HOSTNAME = "http://twitter.com";
const string REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token";
const string OAUTH_VER = "1.0";
const string OAUTH_CALLBACK = "oob";

typedef std::map <string, string> OAuthParameters;

string generateNonce()
{
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string nonce;

    for (int i = 0; i <= 16; i++) 
    {
        nonce += alphanum[rand() % (sizeof(alphanum) -1)];
    }
    return nonce;
}

string generateTimeStamp()
{
    time_t t = time(0);
    return to_string(t);
}

OAuthParameters BuildSignedParameters(string& url, string& httpMethod, string& consumerKey, string& consumerSecret, const string& requestToken = "", const string& requestTokenSecret = "", const string& pin = "")
{
    string timeStamp = generateTimeStamp();
    string nonce = generateNonce();

    OAuthParameters oauthParameters;

    oauthParameters["oauth_timestamp"] = timeStamp;
    oauthParameters["oauth_nonce"] = nonce;
    oauthParameters["oauth_version"] = OAUTH_VER;
    oauthParameters["oauth_signature_method"] = "HMAC-SHA1";
    oauthParameters["oauth_consumer_key"] = consumerKey;

    if (!requestToken.empty()) 
    {
        oauthParameters["oauth_token"] = requestToken;
    }
    if (!pin.empty())
    {
        oauthParameters["oauth_verifier"] = pin;
    }
}

string OauthRequestSubmit(OAuthParameters& parameters, string url)
{
    
}

string OauthWebRequest(
    string& url,
    string& httpMethod,
    string& consumerKey,
    string& consumerSecret,
    const string& oauthToken = "",
    const string& oauthTokenSecret = "",
    const string& pin = ""
    )
{
    // For now assuming that there are no query parameters
    OAuthParameters oauthSignedParameters = BuildSignedParameters(url, httpMethod, consumerKey, consumerSecret, oauthToken, oauthTokenSecret, pin);
    return OauthRequestSubmit(oauthSignedParameters, url);
}

string HMACSHA1(char key[], char data[])
{
    unsigned char* digest;
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*) data, strlen(data), NULL, NULL);    
 
    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
    // Change the length accordingly with your choosen hash engine
    char mdString[20];
    for(int i = 0; i < 20; i++)
         sprintf(&mdString[i], "%02x", (unsigned int)digest[i]);
 
    return string((const char *)mdString);
}

int main() {
    // For testing
    char key[] = "012345678";
    char data[] = "hello world";
    string signature = HMACSHA1(key, data);
    cout << signature << "\n";
}

