<?php

namespace Firauth\Support;

use Illuminate\Http\JsonResponse;

/**
 * Class ResponseHandler
 *
 * Handles standardized JSON response formatting for the application.
 * Provides methods for generating success and error responses with a consistent structure.
 */
class ResponseHandler
{
    /**
     * Generate an error response with a given status code and messages.
     *
     * @param int $statusCode HTTP status code
     * @param array|string $messages Error message(s)
     * @return JsonResponse
     */
    public static function error(int $statusCode, $messages = []): JsonResponse
    {
        if (is_string($messages)) {
            $messages = [$messages];
        }

        return response()->json([
            'data' => null,
            'status' => false,
            'messages' => $messages
        ], $statusCode);
    }

    /**
     * Generate a success response with given data, status code and messages.
     *
     * @param array|string|null $data Response data
     * @param int $statusCode HTTP status code
     * @param array $messages Additional messages
     * @return JsonResponse
     */
    public static function success($data = [], int $statusCode = 200, array $messages = []): JsonResponse
    {
        if (is_null($data)) {
            $data = [];
        }

        if (is_string($data)) {
            $data = [$data];
        }

        return response()->json([
            'data' => self::handleObject($data),
            'status' => true,
            'messages' => $messages
        ], $statusCode);
    }

    /**
     * Recursively handle nested objects and arrays.
     *
     * @param mixed $data Data to be processed
     * @return mixed Processed data
     */
    private static function handleObject($data)
    {
        if (is_array($data)) {
            foreach ($data as $key => $val) {
                if (is_array($val)) {
                    $data[$key] = self::handleObject($val);
                } elseif (is_object($val)) {
                    $data[$key] = self::convertToArray($val);
                }
            }
            return $data;
        }

        if (is_object($data)) {
            return self::convertToArray($data);
        }

        return $data;
    }

    /**
     * Convert an object to array representation.
     *
     * @param object $object Object to be converted
     * @return array
     */
    private static function convertToArray(object $object): array
    {
        if (is_object($object) && method_exists($object, 'toArray')) {
            return $object->toArray();
        }
        return (array) $object;
    }
}
