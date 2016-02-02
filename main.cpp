#include <iostream>
#include "oauth.h"

using namespace std;

int main() {

    // 1. Create a new connection config instance for Twitter. This will be used for all OAuth connections related to Twitter
    ConnectionConfig Twitter;
    Twitter.Consumerkey = "uvSDDZJW7XiG64akUzMgS44tF";
    Twitter.ConsumerSecret = "CCu9u5pRUOtXeO9VsitmgVSL4RbQwbiWX06aBLkaRsJRVt6EKL";
    Twitter.hostname = "http://twitter.com";
    Twitter.request_token_url = "https://api.twitter.com/oauth/request_token";
    Twitter.authenticate_url = "https://twitter.com/oauth/authenticate";
    Twitter.oauth_ver = "1.0";
    Twitter.oauth_callback = "oob";
    Twitter.nickname = "des_twitter";

    // 2. Create a new connection using Twitter connection config.
    OAuth getTimeLine(&Twitter, "GET", "https://api.twitter.com/1.1/statuses/home_timeline.json");

    if (!Twitter.hasSavedFile()) {
        OAuth requestToken(&Twitter, "POST", "https://api.twitter.com/oauth/request_token");
        requestToken.doRequest();
        // cout << requestToken.response << endl;
        // cout << "\n\n\n\n\n";

        OAuth accessToken(&Twitter, "POST", "https://api.twitter.com/oauth/access_token");
        accessToken.doRequest();
        // cout << accessToken.response << endl;
        // cout << "\n\n\n\n\n";
    }
    
    getTimeLine.doRequest();
    cout << getTimeLine.response << endl;
    
    return 0;
}