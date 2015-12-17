# OAuth
OAuth in C++

Ongoing project to create a resuable OAuth library in C++. 

May notice I am using Twitter's API to test as I develop.

The OAuth class will go through the process of obtaining a request token 
and then a pin that the user can use to authenticate the application (This process
usually occurs during the first connection when it determines there is no token present).
The OAuth class will also go through the process of exchanging the request token and pin
for an access token when it sees that there is a token but it has not been authenticated.

