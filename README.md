# saml
XQuery / JS SAML implementation

This module is to be imported into an existing XQuery/MarkLogic project to allow client authentication and authorization supporting SAML assertions.

# Steps to complete
1. Obtain certificate and populate public-cert.xml accordingly.
2. Have your admin install this certificate document within the security database
  * curl --anyauth --user user:password -T ./public-cert.xml -i -H "Content-type: application/xml" http://localhost:8000/v1/documents?uri=/saml/public-cert/layer7.xml\&database=Security
3. Register your function as an AMPed function
4. Update your config file to indicate the URI of the certificate document
