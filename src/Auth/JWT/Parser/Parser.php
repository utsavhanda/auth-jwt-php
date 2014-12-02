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
class Parser {

    /** @var $Algorithm Algorithm */
    private $Algorithm;

    /** @var $Signature Signature */
    private $Signature;

    /**
     *  Initializes a new Parser instance
     */
    public function __construct() {
        $this->Algorithm = new Algorithm();
        $this->Signature = new Signature();
    }

    /**
     * Prepares a JWT with compact serialization strategy
     *
     * @param object|array $payload
     * @param string $secretKey
     * @param string $algorithm
     *
     * @return string
     *
     * @throws InvalidArgumentException
     */
    public function serialize($payload, $secretKey, $algorithm = Algorithm::ALGORITHM_HS256) {
        if (empty($payload) || (!is_array($payload) && !is_object($payload)) || empty($secretKey) || !Algorithm::IsValid($algorithm)) {
            throw new InvalidArgumentException;
        }

        // The prepared JWT would contain "two" period characters, resulting in three non-empty segments:
        // - Header - Payload - Crypto (signature)
        // Preparing header
        $header = [
            // Parameter to identify structure as a JWT
            'typ' => 'JWT',
            // Parameter to identify the cryptographic algorithm used to secure structure
            'alg' => $algorithm
        ];

        // Preparing packet
        $packet = [
            $this->Signature->encrypt(json_encode($header)),
            $this->Signature->encrypt(json_encode($payload))
        ];

        // Appending signature within packet
        $packet[] = $this->Signature->encrypt($this->Signature->Stamp(implode(Signature::SEPARATOR, $packet), $secretKey, $algorithm));

        return implode(Signature::SEPARATOR, $packet);
    }

    /**
     * Unserializes the JWT from stored representation
     *
     * @param string $jwt
     * @param string $secretKey
     * @param bool $verify
     *
     * @return Token
     *
     * @throws Exception
     * @throws UnexpectedValueException
     * @throws InvalidArgumentException
     */
    public function unserialize($jwt, $secretKey = null, $verify = true) {
        if (empty($jwt) || !is_bool($verify)) {
            throw new InvalidArgumentException;
        } else if (substr_count($jwt, Signature::SEPARATOR) != 2) {
            throw new UnexpectedValueException;
        }

        /** @var \stdClass */
        $Token = null;

        // Retrieving segments
        list ($encryptedHeader, $encryptedPayload, $encryptedSignature) = explode(Signature::SEPARATOR, $jwt);

        // Validating header and payload
        if (null === ($header = json_decode($this->Signature->decrypt($encryptedHeader)))) {
            throw new UnexpectedValueException;
        } else if (null === $Token = json_decode($this->Signature->decrypt($encryptedPayload))) {
            throw new UnexpectedValueException;
        }

        // Verifying the JWT Signature
        if ($verify && !$this->Signature->verify($header->alg, $encryptedSignature, [$encryptedHeader, $encryptedPayload], $secretKey)) {
            throw new Exception('Signature verification failed');
        }

        // Verifying the JWT
        if ($verify && (!property_exists($Token, 'iat') || !is_int($Token->iat) || time() < $Token->iat)) {
            throw new Exception('Token verification failed');
        }

        return $Token;
    }

}
