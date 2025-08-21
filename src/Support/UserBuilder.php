<?php

namespace Firauth\Support;

/**
 * UserBuilder handles the construction and manipulation of user attributes from JWT claims.
 *
 * This class provides utility methods to process JWT claims into user attributes
 * and clean up control keys from user data arrays.
 *
 * @package firauth\Support
 */
class UserBuilder
{
    /**
     * Build a dynamic user attributes array from JWT claims.
     *
     * This method processes JWT claims to create a clean user attributes array by:
     * - Removing standard JWT reserved claims
     * - Ensuring user ID exists (falls back to 'sub' claim if needed)
     * - Setting display name from first_last_name if available
     *
     * @param array $claims The JWT claims to process
     * @return array The processed user attributes
     */
    public static function fromClaims(array $claims): array
    {
        $exclude = ['exp','iat','nbf','jti','iss','aud'];
        $attrs = array_diff_key($claims, array_flip($exclude));

        if (!isset($attrs['id'])) {
            $attrs['id'] = $claims['sub'] ?? null;
        }

        if (empty($attrs['display_name']) && !empty($claims['first_last_name'])) {
            $attrs['display_name'] = $claims['first_last_name'];
        }

        return $attrs;
    }

    /**
     * Remove control keys from the attributes array.
     *
     * Filters out any keys that start with an underscore, which are typically
     * used for control purposes and should not be included in the final user object.
     *
     * @param array $attrs The attributes array to clean
     * @return array The cleaned attributes array
     */
    public static function stripControlKeys(array $attrs): array
    {
        return array_filter($attrs, function ($_, $key) {
            return !str_starts_with((string)$key, '_');
        }, ARRAY_FILTER_USE_BOTH);
    }
}
