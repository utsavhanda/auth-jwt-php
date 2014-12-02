<?php

/**
 * Copyright 2014 Utsav Handa or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0.html
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

namespace Auth\JWT\Parser;

/**
 * @author Utsav Handa <handautsav@gmail.com>
 */
class Signature {

    const SEPARATOR = '.';

    /**
     * Prepares a URL safe base64 encrypted representation
     *
     * @param string $data
     *
     * @return string
     */
    public function encrypt($data) {
        // Preparing URL safe, base64 encoded information
        return rtrim(str_replace('=', '', strtr(base64_encode($data), '+/', '-_')));
    }

    /**
     * Decrypts URL-safe stored representation into a value
     *
     * @param string $data
     *
     * @return string|array|object
     */
    public function decrypt($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    /**
     * Prepares the information for stamp-ed version of representation
     *
     * @param string $data
     * @param string $secretKey
     * @param string $algorithm
     *
     * @return string
     *
     * @throws InvalidArgumentException
     */
    public function stamp($data, $secretKey, $algorithm) {
        if (empty($data) || empty($secretKey) || !Algorithm::IsValid($algorithm)) {
            throw new InvalidArgumentException;
        }

        return hash_hmac($algorithm, $data, $secretKey, true);
    }

    /**
     * Verifies the decoded token information
     *
     * @param string $algorithm
     * @param string $encryptedSignature
     * @param array $verifierList
     * @param string $secretKey    (OPTIONAL)
     *
     * @return bool
     *
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function verify($algorithm, $encryptedSignature, array $verifierList, $secretKey = null) {
        if (empty($algorithm)) {
            throw new Exception('Empty Algorithm');
        } else if (empty($encryptedSignature) || !is_array($verifierList)) {
            throw new InvalidArgumentException;
        }

        return ($this->decrypt($encryptedSignature) == $this->stamp(implode(self::SEPARATOR, $verifierList), $secretKey, $algorithm));
    }

}
