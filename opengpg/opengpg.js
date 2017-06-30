 /**
  * opengpg.js
  *
  *
  * Requires javascript-opentimestamps
  * Copyright 2017 Valerio Vaccaro - www.valeriovaccaro.it
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  **/

 // Import the requirements
 const openpgp = require('openpgp');

 module.exports = function(RED) {
   // Node for Sign a generic payload
   function GPG_Sign(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
       var privKeyObj = openpgp.key.readArmored(msg.privkey).keys[0];

       privKeyObj.decrypt(msg.passphrase);

       options = {
         data: msg.payload.data, // input as String (or Uint8Array)
         privateKeys: privKeyObj // for signing
       };

       openpgp.sign(options).then(function(signed) {
         msg.payload.signature = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'
         node.status({
           fill: "green",
           shape: "dot",
           text: "Done"
         });

         delete msg['privkey'];
         delete msg['passphrase'];
         node.send(msg);
       });
     });
   }; // End of function
   // Node for Sign a generic payload
   function GPG_Sign_Verify(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
       //cleartext = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

       options = {
         message: openpgp.cleartext.readArmored(msg.payload.signature), // parse armored message
         publicKeys: openpgp.key.readArmored(msg.pubkey).keys // for verification
       };

       openpgp.verify(options).then(function(verified) {
         validity = verified.signatures[0].valid; // true
         if (validity) {
           console.log('signed by key id ' + verified.signatures[0].keyid
             .toHex());
           msg.status = "valid";
           node.status({
             fill: "green",
             shape: "dot",
             text: "Valid"
           });
         } else {
           msg.status = "not valid";
           node.status({
             fill: "red",
             shape: "dot",
             text: "Invalid"
           });
         }
         delete msg['pubkey'];
         node.send(msg);
       });

     });
   }; // End of function

   // Register the node by name. This must be called before overriding any of the
   // Node functions.
   RED.nodes.registerType("GPG_Sign", GPG_Sign);
   RED.nodes.registerType(
     "GPG_Sign_Verify", GPG_Sign_Verify);
 }
