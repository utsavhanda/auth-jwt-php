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
class Algorithm {

    const ALGORITHM_HS256 = 'sha256';
    const ALGORITHM_HS384 = 'sha384';
    const ALGORITHM_HS512 = 'sha512';

    /**
     * @param string $algorithm             
     *
     * @return bool
     */
    public function isValid($algorithm) {
        return in_array($algorithm, [self::ALGORITHM_HS256, self::ALGORITHM_HS384, self::ALGORITHM_HS512]);
    }

}
