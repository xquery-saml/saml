xquery version "1.0-ml";

module namespace libsaml = "http://marklogic.com/lib-saml";


declare namespace ds = "http://www.w3.org/2000/09/xmldsig#";
declare namespace saml2 = "urn:oasis:names:tc:SAML:2.0:assertion";
declare namespace sp = 'saml:project';

declare option xdmp:mapping "false";

declare variable $SAML-TOKEN-HEADER := "saml";

(:
  Placeholder for handling the public cert.
  A few ways we might handle the cert:
    1) Get the cert from the SAML and verify against a certificate authority
    2) Get the cert from the (Security?) database and (optionally) check against the one in the SAML
:)
declare function libsaml:get-public-cert() as xs:string
{
(: Don't pass anything in
 : Create an AMPED function to retrieve saml certificate
 :)

 let $eval-str := "
xquery version '1.0-ml';
declare namespace ds = 'http://www.w3.org/2000/09/xmldsig#';
declare namespace sp = 'saml:project';

declare variable $sp:ModuleDatabase as xs:string external;

/sp:SamlSignature[sp:ModuleDatabase = $sp:ModuleDatabase]/ds:SignatureType/ds:KeyInfo/ds:X509Data/ds:X509Certificate/data()
"

  let $ext-vars := map:new((
    map:entry(xdmp:key-from-QName(xs:QName('sp:ModuleDatabase')), xdmp:modules-database()!xdmp:database-name(.))
  ))
  return
    xdmp:eval($eval-str, $ext-vars, <options xmlns="xdmp:eval"><database>{xdmp:security-database()}</database></options>)
};

declare function libsaml:get-saml() as element(saml2:Assertion)?
{
  let $saml := xdmp:get-request-header($SAML-TOKEN-HEADER)
  return
    if (fn:empty($saml)) then
      ()
    else
      xdmp:unquote(xdmp:base64-decode($saml))/*
};

declare function libsaml:verify-saml-and-get-attributes() as map:map
{
  libsaml:verify-saml-and-get-attributes(libsaml:get-saml())
};

declare function libsaml:verify-saml-and-get-attributes($saml as element(saml2:Assertion)?) as map:map
{
  let $saml := libsaml:get-saml()
  return
  (
    libsaml:verify-saml($saml),
    libsaml:get-attributes($saml)
  )
};

declare function libsaml:get-attributes() as map:map
{
  libsaml:get-attributes(libsaml:get-saml())
};

declare function libsaml:get-attributes($saml as element(saml2:Assertion)?) as map:map
{
  let $attributes := map:map()

  let $_ :=
    if (fn:exists($saml)) then
      for $a in $saml/saml2:AttributeStatement/saml2:Attribute
      let $name := $a/fn:data(@Name)
      let $value := $a/fn:data(saml2:AttributeValue)
      return map:put($attributes, $name, $value)
    else
      map:put($attributes, "current-user", xdmp:get-current-user())

  return $attributes
};

(: throws exception if SAML could not be verified :)
declare function libsaml:verify-saml() as empty-sequence()
{
  libsaml:verify-saml(libsaml:get-saml())
};

(: throws exception if SAML could not be verified :)
declare function libsaml:verify-saml($saml as element(saml2:Assertion)?) as empty-sequence()
{
  let $_ :=
    if (fn:empty($saml)) then
      fn:error((), "No SAML Assertion in header")
    else
      ()

  (: remove the Signature element from the SAML then get a canonicalized string of the SAML XML :)
  let $saml-no-sig-c14n := libsaml:canonicalize(libsaml:remove-sig($saml))

  (: calculate our own SHA-1 digest of the canonicalized SAML minus Signature :)
  let $our-saml-hex-digest := xdmp:sha1($saml-no-sig-c14n)

  (: get the base64-encoded SHA-1 digest from the SAML :)
  let $digest-value := $saml/ds:Signature/ds:SignedInfo/ds:Reference/fn:string(ds:DigestValue)

  (: call out to jsrsasign to convert $digest-value from SAML to a hex string :)
  let $digest-value-hex := libsaml:base64-digest-to-hex($digest-value)

  (: get the base64-encoded signature value from the SAML :)
  let $signature-value := $saml/ds:Signature/fn:data(ds:SignatureValue)

  let $public-cert := libsaml:get-public-cert()

  (: Verify the SignatureValue against the cert and the canonicalized SignedInfo element :)
  let $sig-verified :=
    libsaml:verify-sig(
      $public-cert,
      libsaml:canonicalize($saml/ds:Signature/ds:SignedInfo),
      $signature-value
    )

  (: verify-sig can return 0 or -1 in certain error conditions :)
  let $sig-verified :=
    if ($sig-verified instance of xs:integer) then
      fn:false()
    else
      $sig-verified

  (: the message is verified if both the digest and signature can be verified :)
  let $result := ($our-saml-hex-digest = $digest-value-hex) and $sig-verified
  return
    if (fn:not($result)) then
      fn:error((), "Could not verify SAML Assertion")
    else
      ()
};

declare private function libsaml:get-base-module-directory()
{
  xdmp:get-invoked-path() !
  xdmp:filesystem-filepath(.) !
  fn:string-join(fn:tokenize(., '/')[1 to last()-1],'/')
};

declare function libsaml:canonicalize($e as element())
{
  let $str := xdmp:quote($e)
  let $path := libsaml:get-base-module-directory()
  return
  xdmp:javascript-eval("
    var str;

    var c14n = require('" || $path || "/js/xml-c14n/index.js')();
    var DOMParser = require('" || $path || "/js/xmldom/dom-parser').DOMParser;

    var doc = new DOMParser().parseFromString(str, 'text/xml');
    var canonicaliser = c14n.createCanonicaliser('http://www.w3.org/2001/10/xml-exc-c14n#');

    canonicaliser.canonicalise(doc.documentElement, function(err, res) {
      if (err) {
        err.stack;
      }
      res;
    });


    ",
    map:new((
      map:entry("str", $str)
    ))
  )
};

declare function libsaml:verify-sig($pem as xs:string, $msg as xs:string, $sig as xs:string)
{
  let $path := libsaml:get-base-module-directory()

  return
  xdmp:javascript-eval("
    var pem, msg, sig;

    var mod = require('" || $path || "/js/jsrsasign/jsrsasign');

    var x509 = new mod.X509();
    x509.readCertPEM(pem);
    sig = mod.b64tohex(sig);
    var isValid = x509.subjectPublicKeyRSA.verifyString(msg, sig);

    isValid;
    ",
    map:new((
      map:entry("pem", $pem),
      map:entry("msg", $msg),
      map:entry("sig", $sig)
    ))
  )
};

declare function libsaml:base64-digest-to-hex($digest as xs:string)
{
  let $path := libsaml:get-base-module-directory()

  return
  xdmp:javascript-eval("
    var digest;

    var mod = require('" || $path || "/js/jsrsasign/jsrsasign');

    mod.b64tohex(digest);
    ",
    map:new((
      map:entry("digest", $digest)
    ))
  )
};

declare function libsaml:remove-sig($saml as element(saml2:Assertion)) as element(saml2:Assertion)
{
  element { fn:node-name($saml) }
  {
    $saml/@*,
    $saml/node()[fn:not(. instance of element(ds:Signature))]
  }
};

