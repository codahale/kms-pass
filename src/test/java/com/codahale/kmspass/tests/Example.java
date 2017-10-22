/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.kmspass.tests;

import com.codahale.kmspass.KMS;
import com.codahale.kmspass.PasswordHasher;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;

public class Example {

  public static void main(String[] args) throws Exception {
    final HttpTransport transport = new NetHttpTransport();
    final JsonFactory jsonFactory = new JacksonFactory();
    GoogleCredential credential = GoogleCredential.getApplicationDefault(transport, jsonFactory);
    if (credential.createScopedRequired()) {
      credential = credential.createScoped(CloudKMSScopes.all());
    }

    final CloudKMS cloudKMS = new CloudKMS.Builder(transport, jsonFactory, credential)
        .setApplicationName("kms-pass example")
        .build();
    final KMS kms = new GoogleKMS(cloudKMS,
        "projects/personal-backup-170114/locations/global/keyRings/test/cryptoKeys/password");

    final PasswordHasher hasher = new PasswordHasher(kms);
    final String hash = hasher.hash("it's a living");
    System.out.println(hash);

    System.out.println(hasher.validate(hash, "it's a living"));
    System.out.println(hasher.validate(hash, "its a living"));
  }
}
