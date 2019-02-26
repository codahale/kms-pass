/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.codahale.kmspass.tests;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.codahale.kmspass.AmazonKMS;
import com.codahale.kmspass.GoogleKMS;
import com.codahale.kmspass.KMS;
import com.codahale.kmspass.PasswordHasher;
import com.google.cloud.kms.v1.KeyManagementServiceClient;

public class Example {

  public static void main(String[] args) throws Exception {
    final AWSKMS awsKMS = AWSKMSClient.builder().build();
    final AmazonKMS amazonKMS = new AmazonKMS(awsKMS, "c4699e13-e3c9-47f8-b772-4f182d5eb041");

    final PasswordHasher awsHasher = new PasswordHasher(amazonKMS);
    final String awsHash = awsHasher.hash("it's a living");
    System.out.println(awsHash);
    System.out.println(awsHasher.validate(awsHash, "it's a living"));
    System.out.println(awsHasher.validate(awsHash, "its a living"));

    final KMS gcpKMS =
        new GoogleKMS(
            KeyManagementServiceClient.create(),
            "projects/personal-backup-170114/locations/global/keyRings/test/cryptoKeys/password");

    final PasswordHasher gcpHasher = new PasswordHasher(gcpKMS);
    final String gcpHash = gcpHasher.hash("it's a living");
    System.out.println(gcpHash);
    System.out.println(gcpHasher.validate(gcpHash, "it's a living"));
    System.out.println(gcpHasher.validate(gcpHash, "its a living"));
  }
}
