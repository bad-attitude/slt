---
title: "SLT: The TLS come_hither Extension for Consensual Role Reversal"
abbrev: "come_hither"
category: std

docname: draft-bm-tls-slt-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - role reversal
 - come hither
 - authenticating party
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "bad-attitude/slt"
  latest: "https://bad-attitude.github.io/slt/draft-bm-tls-slt.html"

author:
 -
    fullname: "Martin Thomson"
    organization: Mozilla
    email: "mt@lowentropy.net"
 -
    fullname: "Bob Beck"
    organization: OpenSSL
    email: "beck@obtuse.com"

normative:
  RFC2119:
  RFC8174:
  RFC9846:
  RFC6066:
  RFC9849:
informative:
  RFC8446:

...

--- abstract

This document defines the "come_hither" extension for the Transport
Layer Security (TLS) protocol version 1.3.  A client that includes the
extension in its ClientHello indicates that it is willing to SLT: to run
the handshake backwards, advertising names for which it holds
certificates and is willing to act as a server.  A server that accepts
responds with its own ClientHello targeting one of those names, inverting
the roles of the two endpoints.  The handshake then proceeds as an
ordinary TLS 1.3 handshake in the reversed direction.

--- middle

# Introduction

In the Transport Layer Security (TLS) protocol {{RFC9846}}, the roles of
the two endpoints are fixed by the direction of connection
establishment.  The endpoint that initiates the connection sends the
ClientHello and acts as the relying party; the endpoint that accepts the
connection sends the ServerHello and is the party that authenticates,
typically by presenting a certificate for the name the client requested.
This binding of TLS role to transport role is convenient but
occasionally inconvenient: there are deployments in which the endpoint
best placed to open a connection is also the endpoint that ought to
prove its identity.

Existing workarounds require the transport-initiating endpoint to wait
to be connected to, which is not always possible in the presence of
Network Address Translators, firewalls, or asymmetric reachability.
This document takes the opposite approach and permits the two endpoints
to consensually exchange their TLS roles after the connection has been
opened, without opening a second connection.

The mechanism is a single ClientHello extension, "come_hither".  A
client that possesses certificates for one or more names, and that is
willing to be a server for those names, lists them in the extension.  A
server that sees the extension and wishes to take up the offer responds
not with a ServerHello but with a fresh ClientHello of its own, aimed at
one of the offered names.  From that point the protocol runs in reverse:
the original client authenticates as a server for the selected name, and
the original server verifies that authentication as a client.  The
inversion happens exactly once per connection and is protected against
tampering by binding the original ClientHello into the transcript of the
reversed handshake.

Because the extension repurposes the Encrypted Client Hello (ECH)
machinery of {{RFC9849}}, the name ultimately selected by the responding
endpoint can be concealed from observers of the network, just as the
Server Name Indication is concealed in an ordinary ECH deployment.

TLS 1.3 was originally specified in {{RFC8446}} and is re-published, with
the terminology used here, in {{RFC9846}}.  This document is a companion
to {{RFC9846}} and does not change any TLS 1.3 behavior other than what
is described herein.  It updates nothing; it merely asks nicely.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terminology of {{RFC9846}}.  The presentation
language used for data structures is the one defined in Section 3 of
{{RFC9846}}.

The following additional terms are used:

Beckoner:
: The endpoint that opens the transport connection and sends the first
  ClientHello carrying the "come_hither" extension.  This endpoint holds
  the TLS client role initially.  If role reversal occurs, the Beckoner
  becomes the authenticating party and assumes the TLS server role -- the
  SLT server -- for the remainder of the connection.

Suitor:
: The endpoint that accepts the transport connection.  This endpoint
  holds the TLS server role initially.  If it accepts the invitation, it
  becomes the relying party and assumes the TLS client role -- the SLT
  client -- for the remainder of the connection.

SLT client:
: The role held by the Suitor after role reversal.  The SLT client sends
  the Reversed ClientHello and behaves in every respect as a TLS client,
  verifying the SLT server's authentication.

SLT server:
: The role held by the Beckoner after role reversal.  The SLT server
  responds to the Reversed ClientHello with a ServerHello and
  authenticates, as a TLS server does, for the selected Offered Name.

Originating ClientHello (CH0):
: The ClientHello sent by the Beckoner that carries the "come_hither"
  extension.

Reversed ClientHello (CH1):
: The ClientHello sent by the Suitor in response to a "come_hither"
  extension, indicating acceptance of role reversal.

Offered Name:
: A name listed in the "come_hither" extension for which the Beckoner
  asserts it holds a certificate and is willing to act as a server.

# The "come_hither" Extension

## Extension Data {#ext-data}

The "come_hither" extension is carried in the ClientHello message.  Its
"extension_data" field takes one of two forms:

* The offer form, a ComeHitherOffer structure, appears only in the
  Originating ClientHello (CH0) sent by the Beckoner.  This is the
  invitation to SLT.

* The acceptance form appears only in the Reversed ClientHello (CH1) sent
  by an accepting Suitor.  It is either empty (zero length), for a plain
  acceptance, or a SuitorConfirmation structure, for a pre-authenticated
  acceptance (see {{preauth}}).

~~~
opaque HostName<1..2^16-1>;

struct {
    HostName name;
} OfferedName;

struct {
    OfferedName offered_names<1..2^16-1>;
    opaque willing_configs<0..2^16-1>;
} ComeHitherOffer;

struct {
    uint16 selected_identity;
    opaque suitor_binder<32..255>;
} SuitorConfirmation;
~~~

An endpoint that receives an offer form in a Reversed ClientHello, or an
acceptance form in an Originating ClientHello, MUST terminate the
connection with an "illegal_parameter" alert.  The fields of
SuitorConfirmation are defined in {{preauth}}.

offered_names:
: A non-empty list of names for which the Beckoner holds a certificate
  and is willing to act as a server.  Each name is a HostName as defined
  for the "server_name" extension in Section 3 of {{RFC6066}}.  The list
  MUST contain at least one OfferedName.  The order of the list is not
  significant and expresses no preference; the Beckoner is equally
  willing to act as a server for any name in the list, and the Suitor MAY
  select any of them.  A Beckoner MUST NOT include a name for which it is
  unable to complete server authentication.

willing_configs:
: Either an empty vector, or an ECHConfigList as defined in Section 4 of
  {{RFC9849}}.  When non-empty, it provides one or more ECH
  configurations that the Suitor MAY use to protect the Reversed
  ClientHello (see {{ech}}).  Because the Beckoner will act as the ECH
  client-facing server for the Reversed ClientHello, the Beckoner MUST
  possess the private keys corresponding to every configuration it
  advertises here.

## Beckoner Behavior

A Beckoner that wishes to invite role reversal includes the
"come_hither" extension in its Originating ClientHello (CH0).  A Beckoner
MUST NOT include the "come_hither" extension in any ClientHello other
than the first one it sends on a connection, and MUST NOT include it in a
ClientHello sent in response to a HelloRetryRequest.

Having sent CH0, the Beckoner waits for the peer's first handshake
message and MUST be prepared to receive either of the following (see
{{detect}}):

* a ServerHello (or HelloRetryRequest), in which case the peer has
  declined the invitation and the handshake proceeds as an ordinary TLS
  1.3 handshake with the Beckoner in the client role; or

* a ClientHello, in which case the peer has accepted the invitation and
  role reversal proceeds as described in {{reversal}}.

A Beckoner MUST support both outcomes.  A Beckoner that is unwilling to
proceed as a client if its invitation is declined MUST NOT send the
"come_hither" extension in the first place.

## Suitor Behavior {#sec-suitor}

A server that does not recognize the "come_hither" extension ignores it,
as required for unknown extensions by Section 4.2.2 of {{RFC9846}}, and
responds with an ordinary ServerHello.

A Suitor that recognizes the extension and chooses to decline the
invitation likewise responds with an ordinary ServerHello and MUST NOT
otherwise act on the contents of the extension.

A Suitor that recognizes the extension and chooses to accept the
invitation MUST:

1. select exactly one name from the offered_names list;

2. construct a Reversed ClientHello (CH1) as described in {{reversal}},
   with a "server_name" extension {{RFC6066}} identifying the selected
   name (subject to ECH protection as described in {{ech}});

3. include a "come_hither" extension in CH1 in one of its acceptance
   forms -- empty for a plain acceptance, or a SuitorConfirmation for a
   pre-authenticated acceptance ({{preauth}}) -- which signals acceptance
   of the invitation to SLT; and

4. send CH1 in place of a ServerHello.

The "come_hither" extension in CH1 is the definitive signal that role
reversal is taking place.  A Suitor that sends a ClientHello without it is
not accepting the invitation and, from the Beckoner's perspective, has not
produced a valid response at all (see {{detect}}).

A Suitor MUST NOT select a name that does not appear in the offered_names
list.  A Suitor that finds no acceptable name MUST decline by sending an
ordinary ServerHello.

# Role Inversion and the Reversed Handshake {#reversal}

## Overview

When the Suitor accepts the invitation, the two endpoints exchange their
TLS roles.  The transport roles are unchanged: the Beckoner remains the
endpoint that opened the connection.  Only the TLS roles are swapped.
The resulting message flow is shown in {{fig-flow}}.

~~~
    Beckoner                                            Suitor
 (transport initiator)                        (transport responder)

 ClientHello (CH0)
   + come_hither          -------->
                                                 ClientHello (CH1)
                                                    + come_hither (empty)
                                                    + server_name
                                          [+ encrypted_client_hello]
                          <--------
 ServerHello
   + key_share
 {EncryptedExtensions}
 {CertificateRequest*}
 {Certificate}
 {CertificateVerify}
 {Finished}               -------->
                                             {Certificate*}
                                             {CertificateVerify*}
                          <--------          {Finished}
 [Application Data]       <------->          [Application Data]

   +  Indicates noteworthy extensions sent in the previously
      noted message.
   *  Indicates optional or situation-dependent messages or
      extensions that are not always sent.
   {} Indicates messages protected using keys derived from a
      [sender]_handshake_traffic_secret of the reversed handshake.
   [] Indicates messages protected using keys derived from
      [sender]_application_traffic_secret_N.
~~~
{: #fig-flow title="Message Flow for a Role-Reversed Handshake"}

After CH1, the handshake is in every respect an ordinary TLS 1.3
handshake as specified in {{RFC9846}}, with the Suitor as the SLT client
and the Beckoner as the SLT server, and with the single addition of the
transcript treatment described in {{transcript}}.  In particular, the
Beckoner sends the ServerHello, the Suitor and Beckoner derive keys using
the ordinary key schedule of Section 7 of {{RFC9846}}, and the Beckoner
authenticates using a Certificate and CertificateVerify for the selected
name.

## Detecting Inversion {#detect}

After sending CH0, the Beckoner determines whether role reversal has
occurred by examining the "msg_type" field of the first handshake message
it receives:

* a value of server_hello(2) indicates that the invitation was declined
  (or ignored) and the connection continues normally; and

* a value of client_hello(1) indicates that the received message is a
  Reversed ClientHello.  The Beckoner MUST confirm that this ClientHello
  contains a "come_hither" extension in an acceptance form (empty, or a
  SuitorConfirmation); that extension is the acceptance signal.  If it is
  present, the invitation was accepted and role reversal proceeds.  If a
  client_hello arrives without a "come_hither" acceptance extension, the
  Beckoner MUST terminate the connection with an "unexpected_message"
  alert.

A Beckoner that did not send a "come_hither" extension, but that receives
a client_hello where a server_hello is expected, MUST terminate the
connection with an "unexpected_message" alert.

## Transcript Continuity {#transcript}

To bind the Originating ClientHello into the reversed handshake, and thus
to protect the Offered Names and configurations against modification by
an active attacker, the Originating ClientHello (CH0) is incorporated
into the transcript of the reversed handshake using the same synthetic
message construction that {{RFC9846}} uses for HelloRetryRequest.

Specifically, the value of CH0 is replaced in all transcript hash
computations of the reversed handshake with a synthetic handshake message
of type "message_hash" (254) containing Hash(CH0), so that

~~~
Transcript-Hash(CH0, CH1, ...) =
    Hash(message_hash        ||   /* Handshake type */
         00 00 Hash.length   ||   /* Handshake message length */
         Hash(CH0)           ||   /* Hash of CH0 */
         CH1 || ...)
~~~

The hash used is that of the cipher suite negotiated in the reversed
handshake (i.e., the suite selected by the Beckoner in the reversed
ServerHello), as for any other TLS 1.3 transcript.  Both endpoints
possess CH0 and can therefore compute this value independently.

Because CH0 is thereby covered by every Finished message and
CertificateVerify signature in the reversed handshake, an attacker that
modifies, adds, or removes the "come_hither" extension, or that alters
the Offered Names or configurations, will cause the handshake to fail.

## Name Selection and Server Name Indication

The Reversed ClientHello identifies the selected name to the Beckoner
using the "server_name" extension {{RFC6066}}, exactly as an ordinary
client identifies the server it wishes to reach.  The Beckoner uses the
selected name to choose the certificate with which it authenticates.

If the Beckoner does not hold a usable certificate for the selected name
at the time CH1 is processed (for example, because the certificate has
expired since CH0 was sent), the Beckoner MUST terminate the connection
with a "handshake_failure" alert.

## ECH Protection of the Reversed ClientHello {#ech}

When the Beckoner advertises one or more configurations in
willing_configs, the Suitor MAY protect the Reversed ClientHello using
Encrypted Client Hello {{RFC9849}}, treating an advertised ECHConfig as
it would an ECHConfig obtained by any other means.  In this arrangement
the Suitor is the ECH client and the Beckoner is the ECH client-facing
server; the selected Offered Name is carried as the SNI of the
ClientHelloInner.

Because the Beckoner supplied the configurations and holds the
corresponding private keys, the Beckoner is able to decrypt the Reversed
ClientHello and recover the selected name.  This conceals from a network
observer which of the Offered Names the Suitor chose to pursue.

A Suitor SHOULD use ECH whenever willing_configs is non-empty and the
Suitor supports {{RFC9849}}.  When willing_configs is empty, the Reversed
ClientHello is sent without ECH and the selected name is visible on the
wire.

## Authentication

In the reversed handshake, the Beckoner authenticates as the server for
the selected name using the Certificate and CertificateVerify messages,
following Section 4.4 of {{RFC9846}}.  The Suitor verifies this
authentication as an ordinary TLS client.

The Beckoner MAY request certificate-based authentication of the Suitor
by sending a CertificateRequest, in which case the connection is mutually
authenticated with the Suitor in the client role.  All ordinary rules for
client authentication in Section 4.4.2 and Section 4.5 of {{RFC9846}}
apply unchanged.  Alternatively, the Suitor may be authenticated without
a certificate exchange through pre-authenticated role reversal
({{preauth}}), in which case the Beckoner need not send a
CertificateRequest.

# Pre-Authenticated Role Reversal {#preauth}

## Overview

The base mechanism ({{reversal}}) authenticates the SLT server (the
Beckoner) with a certificate and leaves the SLT client (the Suitor)
unauthenticated unless the Beckoner requests a certificate from it.  In
many deployments the Beckoner already knows and has verified the Suitor:
it previously connected to the Suitor in the ordinary direction, verified
the Suitor's certificate, and holds a resumption ticket (Section 4.7.1 of
{{RFC9846}}) that the Suitor issued and that is bound to the Suitor's
authenticated identity.

Pre-authenticated role reversal lets the Beckoner carry that prior
authentication of the Suitor into the reversed handshake, so that the
Suitor's identity is confirmed without a fresh certificate exchange.  The
model uses two connections:

1. Vetting connection: The Beckoner connects to the Suitor without
   beckoning.  The handshake completes in the ordinary direction; the
   Suitor authenticates with a certificate and issues a NewSessionTicket
   to the Beckoner.  The Beckoner now holds a resumption PSK bound to the
   Suitor's authenticated identity.

2. Beckoning connection: The Beckoner connects again, offering both a
   "come_hither" invitation and the resumption PSK obtained from the
   vetting connection.  If the Suitor accepts, it proves possession of the
   resumption secret as part of its acceptance, thereby re-establishing
   its identity, and the reversed handshake proceeds with the Suitor
   already authenticated.

Informally, this is the "I will not SLT on the first date" pattern: an
endpoint declines to reverse roles with a peer it has not already met and
authenticated in the ordinary direction.

## Beckoning with a Pre-Shared Key

To invite pre-authenticated role reversal, the Beckoner includes in CH0
both a "come_hither" offer and a "pre_shared_key" extension (with the
accompanying "psk_key_exchange_modes" extension) offering one or more
resumption PSKs previously issued by the Suitor.  The "pre_shared_key"
extension is constructed, and its binders computed, exactly as in
Section 4.3.11 of {{RFC9846}}; as usual it is the last extension in CH0.

Offering the PSK serves two purposes.  Its binder proves to the Suitor
that the Beckoner is the same peer to which the Suitor issued the ticket.
And, if the Suitor declines the invitation, the connection can still
complete as an ordinary resumption in the un-inverted direction (see
{{decline}}).

## Accepting with a Suitor Confirmation

A Suitor that accepts the invitation and recognizes one of the offered
PSK identities MAY accept in pre-authenticated mode.  To do so, in
addition to the steps of {{sec-suitor}}, it:

1. selects one PskIdentity from the "pre_shared_key" extension of CH0 that
   it recognizes, and verifies the corresponding binder sent by the
   Beckoner;

2. sets the "come_hither" extension in CH1 to a SuitorConfirmation
   carrying the "selected_identity" of the chosen PSK and a
   "suitor_binder"; and

3. places the "come_hither" extension last in CH1.  A CH1 carrying a
   SuitorConfirmation MUST NOT contain a "pre_shared_key" extension.

selected_identity:
: The index, into the "OfferedPsks.identities" list the Beckoner sent in
  the CH0 "pre_shared_key" extension, of the PSK the Suitor selected.

suitor_binder:
: A MAC proving the Suitor's possession of the resumption secret for the
  selected PSK.  It is computed exactly as a PSK binder is computed in
  Section 4.3.11.2 of {{RFC9846}} -- that is, as a Finished MAC keyed by
  the "binder_key" derived from the selected PSK -- but over the
  transcript

~~~
Transcript-Hash(message_hash(CH0), Truncate(CH1))
~~~

: where "message_hash(CH0)" is the synthetic message of {{transcript}}
  carrying Hash(CH0), and Truncate(CH1) is CH1 with the "suitor_binder"
  removed, its length fields set as if a "suitor_binder" of the correct
  length were present.  The hash is the one associated with the selected
  PSK.

Because the resumption secret is known only to the Beckoner and the
Suitor that authenticated in the vetting connection, a valid
"suitor_binder" computed by the peer proves that the peer is that Suitor.
Having offered the PSK itself, the Beckoner verifies the "suitor_binder";
if it does not validate, the Beckoner MUST abort the handshake with a
"decrypt_error" alert.

## Effect on the Reversed Handshake

When a valid SuitorConfirmation is received, the Suitor is authenticated
for the identity established in the vetting connection.  The reversed
handshake then proceeds as in {{reversal}}: the Beckoner authenticates as
the SLT server for the selected Offered Name using a certificate, and the
Beckoner need not send a CertificateRequest to authenticate the Suitor.
The Suitor's (SLT client) Finished transitively covers the
SuitorConfirmation, binding the pre-established identity to the reversed
handshake.

The resumption PSK is used only to authenticate the Suitor as described
here; it is NOT mixed into the reversed handshake's key schedule, which
derives its keys from the fresh (EC)DHE exchange in the usual way
(Section 7 of {{RFC9846}}).  Because the "suitor_binder" covers CH1,
including the Suitor's "key_share", the authenticated identity is bound to
the keys derived from that exchange.

A Beckoner that offered a PSK for pre-authentication but receives a plain
(empty) acceptance MUST NOT consider the Suitor authenticated on the basis
of that PSK.  It MAY continue by requesting a certificate from the Suitor
with a CertificateRequest, or abort the handshake.

## Declining and Fallback {#decline}

A Suitor that receives a beckoning connection carrying an offered PSK MAY
decline the invitation.  If it does, it responds with an ordinary
ServerHello and completes an ordinary resumption handshake in the
un-inverted direction using the offered PSK, authenticating the Suitor to
the Beckoner in the usual way and leaving the Beckoner in the client role.
A Beckoner that offers a PSK alongside a "come_hither" invitation MUST be
prepared for this outcome.

# Interaction with Other Features

## No Recursive Beckoning

Role reversal occurs at most once per connection.  The Reversed
ClientHello carries only the empty (acceptance) form of the "come_hither"
extension; it MUST NOT carry a ComeHitherOffer.  A Suitor therefore
cannot itself extend an invitation to SLT, and the roles cannot invert a
second time.  A Beckoner that receives a Reversed ClientHello containing a
non-empty "come_hither" extension MUST terminate the connection with an
"illegal_parameter" alert.

## Pre-Shared Keys and 0-RTT

An Originating ClientHello that contains a "come_hither" offer MAY also
contain a "pre_shared_key" extension, but only to enable pre-authenticated
role reversal as described in {{preauth}}; the offered PSKs MUST be
resumption PSKs previously issued by the Suitor.

Such a ClientHello MUST NOT contain an "early_data" extension.  This
document does not define 0-RTT for role reversal: early data would occupy
the Suitor's second flight on the connection rather than a first flight,
and the anti-replay properties of Section 8 of {{RFC9846}} do not carry
over across the inversion.  A Suitor that receives a "come_hither" offer
alongside an "early_data" extension MUST decline the invitation and MAY
abort with an "illegal_parameter" alert.

This document does not define session resumption in the reversed
direction.  A Reversed ClientHello MUST NOT contain a "pre_shared_key" or
"early_data" extension.

## HelloRetryRequest

Once role reversal has occurred, the Beckoner (now in the server role)
MAY send a HelloRetryRequest in response to the Reversed ClientHello, and
the Suitor (now in the client role) processes it as an ordinary client
would.  The transcript treatment of {{transcript}} composes with the
HelloRetryRequest treatment of {{RFC9846}}: the synthetic message_hash
for CH0 precedes the Reversed ClientHello in the transcript, and the
ordinary message_hash substitution for the Reversed ClientHello applies
if a HelloRetryRequest is subsequently sent.

## Middlebox Compatibility

The Originating ClientHello is a syntactically ordinary ClientHello and
traverses middleboxes as any ClientHello does.  However, a middlebox that
assumes the first message from the responding endpoint is a ServerHello
may misbehave when it observes a ClientHello instead.  Deployments that
must traverse such middleboxes SHOULD provide willing_configs so that the
Reversed ClientHello is carried within an ECH-protected message that
resembles ordinary client-to-server traffic.

# Security Considerations

## Invitation Stripping and Downgrade

An active attacker could remove the "come_hither" extension from CH0, or
alter the Offered Names or configurations, in an attempt to prevent role
reversal or to steer it toward a name of the attacker's choosing.  The
transcript treatment of {{transcript}} binds CH0 into every Finished
message and CertificateVerify signature of the reversed handshake, so any
such modification causes the handshake to fail once role reversal is
attempted.

An attacker that instead suppresses role reversal entirely (for example,
by injecting a ServerHello) causes the connection to proceed with the
original role assignment.  Applications that require role reversal MUST
treat the absence of reversal as a failure at the application layer; TLS
does not signal a required inversion.

## Name Confusion

The Beckoner asserts, by listing a name in offered_names, that it holds a
certificate for that name and is willing to be a server for it.  A
Beckoner MUST NOT offer names it cannot authenticate, since doing so
invites the Suitor to waste a round trip and may leak the set of names a
Beckoner is associated with.  The Suitor authenticates the Beckoner using
the ordinary certificate verification rules of {{RFC9846}}; listing a
name in offered_names confers no authority by itself.

## Reflection and Amplification

Because the Beckoner opens the connection and yet becomes the party that
sends a certificate, an attacker that can forge the source address of CH0
could induce a Suitor to direct a Reversed ClientHello, and the Beckoner
to direct its (larger) certificate flight, at a victim.  As with ordinary
TLS over unreliable transports, the Suitor SHOULD NOT commit significant
state or send large flights before it has confirmed the Beckoner's
reachability.  Over a connection-oriented transport such as TCP, the
completed handshake before certificate transmission provides this
confirmation.

## Privacy of Offered Names

The offered_names list is sent in the Originating ClientHello and, absent
other protection, is visible to network observers.  This reveals the set
of names for which the Beckoner is willing to act as a server, which may
be more sensitive than the single name revealed by an ordinary SNI.
Beckoners concerned with this exposure SHOULD themselves use Encrypted
Client Hello {{RFC9849}} to protect CH0, independently of the
willing_configs offered for the reversed direction.

The selected name, carried in the Reversed ClientHello, is protected from
observers when ECH is used as described in {{ech}}, and exposed otherwise.

## Unauthenticated Period

As in an ordinary TLS 1.3 handshake, messages sent before the
authenticating party's Finished message has been received are not yet
authenticated.  In a role-reversed handshake the authenticating party is
the Beckoner, so the Suitor MUST NOT rely on the Beckoner's identity, and
MUST NOT send data that assumes it, until it has verified the Beckoner's
Certificate, CertificateVerify, and Finished.

## Pre-Authenticated Role Reversal

The "suitor_binder" of {{preauth}} authenticates the Suitor only as
strongly as the resumption PSK is confined to two parties.  Resumption
PSKs are, by construction, known only to the endpoints of the connection
that established them, so a valid "suitor_binder" identifies the peer as
the Suitor from the vetting connection.  If a PSK is instead shared among
more than two parties -- which resumption PSKs are not, but which some
external PSK deployments are -- then possession no longer identifies a
single peer, and a non-member could reroute the confirmation between honest
parties, as described for the Selfie attack in Section F.8 of {{RFC9846}}.
For this reason, only resumption PSKs, and not external PSKs, are used for
pre-authenticated role reversal.

Because the resumption PSK is used only to authenticate the Suitor and is
not mixed into the reversed handshake's key schedule, the binding between
the authenticated Suitor identity and the session keys rests entirely on
the "suitor_binder" covering CH1, and thus the Suitor's "key_share".
Implementations MUST compute and verify the "suitor_binder" over the exact
transcript specified in {{preauth}}; computing it over a bare Truncate(CH1)
that omits the "message_hash(CH0)" prefix would leave the invitation and
the offered names unbound and is a security error.

An attacker cannot forge a SuitorConfirmation without the resumption
secret, and cannot substitute a plain (empty) acceptance for a
pre-authenticated one without detection: a Beckoner that offered a PSK for
pre-authentication and receives a plain acceptance treats the Suitor as
unauthenticated, as required by {{preauth}}.  The Beckoner obtains no
cryptographic assurance of the Suitor's identity within the beckoning
connection unless a valid SuitorConfirmation is received or the Suitor
authenticates with a certificate.

# IANA Considerations

IANA is requested to add the following entry to the "TLS ExtensionType
Values" registry maintained per {{RFC9846}}:

* Value: TBD (the value 0x1DEA (7658) is suggested)
* Extension Name: come_hither
* TLS 1.3: CH
* Recommended: N
* Reference: This document

The "TLS 1.3" column value "CH" indicates that the extension may appear
only in the ClientHello message.  The extension is marked "Recommended:
N" because its use is appropriate only in deployments that have
specifically arranged for role reversal.

--- back

# Acknowledgments
{:numbered="false"}

The authors thank the TLS working group for its patience with a protocol
that cannot decide which way it faces.
