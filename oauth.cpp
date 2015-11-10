/* Desmond Preston 2015

Oauth implementation

*/

#include "stdio.h"
#include <iostream>
#include <time.h>
#include <openssl/hmac.h>
#include <map>

using namespace std;

typedef map<string, string> OAuthParameters;

/* Contains all info relevant to all requests. e.g Info shared among every OAuth instance */
struct ConnectionConfig {
    string Consumerkey, ConsumerSecret, hostname, request_token_url, oauth_ver, oauth_callback, auth_token;
};

/* OAuth represents a single web request. */
class OAuth {
    public: 
        OAuth(ConnectionConfig connection, string, string);
        void printOAuth();
    private: 
        ConnectionConfig conn;
        OAuthParameters params;
        void BuildParameters(const string& requestToken = "", const string& httpMethod = "", const string& pin = "");
        string generateNonce();
        string generateTimeStamp();
        string createSignature(const string& requestTokenSecret = "");
        string urlencode(const string&);
        string char2hex(char);
        string HMACSHA1(char[], char[]);
        string nonce, timeStamp, signature, method, url;
}; 

OAuth::OAuth(ConnectionConfig ConnectionToUse, string httpMethod, string urlToUse) 
{
    conn = ConnectionToUse;
    method = httpMethod;
    url = urlToUse;
    nonce = generateNonce();
    timeStamp = generateTimeStamp(); 
    BuildParameters();
}

void OAuth::BuildParameters(const string& requestToken, const string& requestTokenSecret, const string& pin)
{
    //Set first params provided from connection settings
    params["Authorization"] = "OAuth";
    params["oauth_consumer_key"] = conn.Consumerkey;
    params["oauth_nonce"] = nonce;
    params["oauth_timestamp"] = timeStamp;
    params["oauth_version"] = conn.oauth_ver;
    params["oauth_signature_method"] = "HMAC-SHA1";

    if (!requestToken.empty())
    {
        params["oauth_token"] = requestToken;
    }

    if (!pin.empty())
    {
        params["oauth_verifier"] = pin;
    }

    string signature = createSignature(requestTokenSecret);
}

string OAuth::createSignature(const string& requestTokenSecret)
{
    /* 
        1. Create a single string of query params from the params map
        2. Generate key from ConsumerSecret and requestTokenSecret (if it exists)
        3. Generate signature base from http method, base Url, and the single string of query params
        4. Generate signature from key and signature base
    */

    //Parameters need to be converted to a single string to be used as query parameters in the url
    string normalizedParams;

    for (OAuthParameters::const_iterator it = params.begin(); it != params.end(); it++)
    {
        if (normalizedParams.size() > 0)
        {
            normalizedParams += "&";
        }
        normalizedParams += it->first + "=" + it->second;
    }

    string key = urlencode(conn.ConsumerSecret) + "&" + urlencode(requestTokenSecret);
    string signatureBase = method + "&" + urlencode(url) + "&" + urlencode(normalizedParams);

    char keych[1024];
    char signatureBasech[1024];
    strcpy(keych, key.c_str());
    strcpy(signatureBasech, signatureBase.c_str());
    string signature = HMACSHA1(keych, signatureBasech);
    
    return signature;
}

void OAuth::printOAuth()
{
    cout << "Nonce: " << nonce << endl
         << "Timestamp: " << timeStamp << endl
         << "=================================" << endl
         << "Connection Details: " << endl
         << "Consumer Key: " << conn.Consumerkey << endl
         << "Consumer Secret: " << conn.ConsumerSecret << endl
         << "Hostname: " << conn.hostname << endl
         << "Request Token URL: " << conn.request_token_url << endl
         << "OAuth Version: " << conn.oauth_ver << endl
         << "OAuth CallBack: " << conn.oauth_callback << endl;
}

string OAuth::generateNonce()
{
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string nonce;

    for (int i = 0; i <= 16; i++) 
    {
        nonce += alphanum[rand() % (sizeof(alphanum) -1)];
    }
    return nonce;
}

string OAuth::generateTimeStamp()
{
    time_t t = time(0);
    return to_string(t);
}

// char2hex and urlencode from http://www.zedwood.com/article/111/cpp-urlencode-function
// modified according to http://oauth.net/core/1.0a/#encoding_parameters
string OAuth::char2hex( char dec )
{
    char dig1 = (dec&0xF0)>>4;
    char dig2 = (dec&0x0F);
    if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0,48 in ascii
    if (10<= dig1 && dig1<=15) dig1+=65-10; //A,65 in ascii
    if ( 0<= dig2 && dig2<= 9) dig2+=48;
    if (10<= dig2 && dig2<=15) dig2+=65-10;

    string r;
    r.append( &dig1, 1);
    r.append( &dig2, 1);
    return r;
}

string OAuth::urlencode(const string &c)
{
    string escaped;
    int max = c.length();
    for(int i=0; i<max; i++)
    {
        if ( (48 <= c[i] && c[i] <= 57) ||//0-9
            (65 <= c[i] && c[i] <= 90) ||//ABC...XYZ
            (97 <= c[i] && c[i] <= 122) || //abc...xyz
            (c[i]=='~' || c[i]=='-' || c[i]=='_' || c[i]=='.')
            )
        {
            escaped.append( &c[i], 1);
        }
        else
        {
            escaped.append("%");
            escaped.append( char2hex(c[i]) );//converts char 255 to string "FF"
        }
    }
    return escaped;
}

string OAuth::HMACSHA1(char key[], char data[])
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

    // 1. Create a new connection config instance for Twitter. This will be used for all OAuth connections related to Twitter
    ConnectionConfig Twitter;
    Twitter.Consumerkey = "uvSDDZJW7XiG64akUzMgS44tF";
    Twitter.ConsumerSecret = "CCu9u5pRUOtXeO9VsitmgVSL4RbQwbiWX06aBLkaRsJRVt6EKL";
    Twitter.hostname = "http://twitter.com";
    Twitter.request_token_url = "https://api.twitter.com/oauth/request_token";
    Twitter.oauth_ver = "1.0";
    Twitter.oauth_callback = "oob";

    // 2. Create a new connection using Twitter connection config
    OAuth test(Twitter, "GET", "https://api.twitter.com/oauth/request_token");
    return 0;
}

